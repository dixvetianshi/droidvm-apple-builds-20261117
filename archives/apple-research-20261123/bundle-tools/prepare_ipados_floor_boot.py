#!/usr/bin/env python3
"""Replace only the kernel in an independent copy of the pinned iPadOS boot disk.

This local preparation uses an admitted artifact manifest as input evidence. It
does not execute a target, build a kernel, access a phone, or verify guest boot.
The existing FAT chain is retained; a larger kernel needs a separate allocation
decision. A shorter kernel gets its real directory size, without padding bytes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import struct
import sys
import tomllib

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "output/ipados-stage/release/droidvm-disk.img"
INVENTORY = ROOT / ("verification/boot-repair-20261120/ipados-ui-repair-20261120/"
                    "approved-background-reboot/lsd-probe-pair-runtime/"
                    "floor-source/original-boot-inventory.json")
PUBLIC_ANCHOR = ROOT / "output/ipados-lsd-floor-build-input/owner-anchor.bin"
PUBLIC_ANCHOR_SHA256 = "a0c1d33a47e7af165df02fe40c9f9b0c66080e9cafcc1bd129c65a1084db3c6f"
MANIFEST_SCHEMA = "org.droidvm.ipados.lsd-floor-kernel.build.v1"
SOURCE_PINS = {
    "xnu_commit": "ac9718fb1af618d5ce8678d0dc6e8a58f252216f",
    "unixnu_commit": "6efbb97764f4e39f8c682f6a6261607a2921bc7b",
    "device_commit": "3da41eaa0f06fd21e7bc1ef17aafe0a3e72d70ff",
    "device_patch_sha256": "b15b294f8d26b125e1829c7d70f44565b1a31ac6004e48dd1d311c1916550d10",
}
POLICY = {"boot_argument": "droidvm-ipados-lsd-floor=1", "uid": 501,
          "registered_name": "lsd", "positive_active_inactive_floor_mb": 64,
          "attributes_preserved": True, "executable_path_binding": False,
          "total_guest_RAM_changed": False}
SOURCE_BYTES = 335544320
SOURCE_SHA256 = "8bedfd8dc7ffde37d35d8c49816d404f7c27deedb85d460534c365324027638f"
KERNEL_PATH = "EFI/UniXNU/Payloads/kernel.macho"
KERNEL_BYTES = 95911936
KERNEL_SHA256 = "88a19acd61a450bd6964c43c0ef1d8f129065707444f49058e5627a735b4772f"
CLUSTER_BYTES = 4096
CHAIN_CLUSTERS = 23416
PAGE_BYTES = 16384
CHUNK_BYTES = 1 << 20


def load_fat_parser():
    """Load the existing parser without invoking its CLI or writing bytecode."""
    name = "ipados_floor_existing_fat_parser"
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/prepare_macos_4g_boot.py")
    if spec is None or spec.loader is None:
        raise ValueError("The existing FAT32 parser cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.Fat32


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def workspace_file(path):
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(ROOT.resolve()) or not resolved.is_file():
        raise ValueError("Every input must be a file inside this workspace")
    return resolved


def read_record(path):
    encoded = path.read_bytes()
    value = json.loads(encoded)
    if not isinstance(value, dict):
        raise ValueError(f"The JSON record must be an object: {path}")
    return value, hashlib.sha256(encoded).hexdigest()


def admitted_kernel(manifest_path, kernel_path):
    record, digest = read_record(manifest_path)
    if record.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("Use the admitted iPadOS lsd-floor kernel build v1 manifest")
    files = record.get("files")
    kernel = files.get("kernel.macho") if isinstance(files, dict) else None
    if not isinstance(kernel, dict):
        raise ValueError("The admitted manifest must contain files['kernel.macho']")
    size, expected = kernel.get("bytes"), kernel.get("sha256")
    if (type(size) is not int or size < 32 or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)):
        raise ValueError("The admitted files['kernel.macho'] must have exact bytes and lowercase SHA256")
    if any(record.get(key) != value for key, value in SOURCE_PINS.items()):
        raise ValueError("The admitted manifest must retain this build's fixed source pins")
    policy = record.get("policy")
    if not isinstance(policy, dict) or any(
            type(policy.get(key)) is not type(value) or policy[key] != value
            for key, value in POLICY.items()):
        raise ValueError("The admitted manifest must retain the UID501 lsd 64 MB floor policy")
    anchor_facts = {"original_public_anchor_sha256": PUBLIC_ANCHOR_SHA256,
                    "original_data_seed_sha256": "97351f9059b125f728a75c8630d3b05c8c4ec60d4b6a94d5a33fb0a55e513ce8",
                    "original_data_volume_uuid": "C0A40140-CA85-4848-98AF-0C007018865D"}
    if any(record.get(key) != value for key, value in anchor_facts.items()):
        raise ValueError("The admitted manifest must retain the original public anchor and Data identity")
    if kernel_path.stat().st_size != size or sha256(kernel_path) != expected:
        raise ValueError("The selected kernel differs from admitted files['kernel.macho'] bytes or SHA256")
    return record, digest, size, expected


def pinned_inventory(path):
    record, digest = read_record(path)
    expected = {"source_sha256": SOURCE_SHA256, "fat_cluster_bytes": CLUSTER_BYTES,
                "kernel_member": KERNEL_PATH, "kernel_bytes": KERNEL_BYTES,
                "kernel_capacity": KERNEL_BYTES, "chain_clusters": CHAIN_CLUSTERS,
                "kernel_sha256": KERNEL_SHA256}
    if any(type(record.get(key)) is not type(value) or record[key] != value for key, value in expected.items()):
        raise ValueError("The original boot inventory does not describe this pinned source")
    members = record.get("members")
    if not isinstance(members, dict) or len(members) != 8 or KERNEL_PATH not in members:
        raise ValueError("The original boot inventory must retain its eight FAT members")
    return record, digest


def member_facts(fat):
    rows = {}
    for path, member in fat.members.items():
        chain = list(fat.chain(member.cluster))
        digest = hashlib.sha256()
        for cluster in chain:
            digest.update(struct.pack("<I", cluster))
        rows[path] = {"bytes": member.size, "sha256": fat.member_digest(member),
                      "first_cluster": member.cluster, "entry_offset": member.entry_offset,
                      "chain_clusters": len(chain), "chain_sha256": digest.hexdigest()}
    return rows


def anchor_offsets(fat, member, anchor):
    """Search the logical member with overlap retained between its FAT chunks."""
    positions = []
    tail = b""
    consumed = 0
    for chunk in fat.chunks(member):
        data = tail + chunk
        cursor = 0
        while (found := data.find(anchor, cursor)) >= 0:
            positions.append(consumed - len(tail) + found)
            cursor = found + 1
        consumed += len(chunk)
        tail = data[-(len(anchor) - 1):]
    return positions


def macho_facts(header, size):
    if len(header) != 32:
        raise ValueError("The kernel's Mach-O header is incomplete")
    magic, cpu, subtype, filetype, commands, command_bytes, flags, reserved = struct.unpack("<8I", header)
    if (magic != 0xfeedfacf or cpu != 0x0100000c or filetype != 12
            or 32 + command_bytes > size):
        raise ValueError("The kernel must be a little-endian ARM64 Mach-O 64 fileset")
    return {"magic": hex(magic), "cpu_type": hex(cpu), "cpu_subtype": hex(subtype),
            "file_type": "MH_FILESET", "load_commands": commands,
            "load_command_bytes": command_bytes, "flags": hex(flags), "reserved": reserved,
            "page_bytes": PAGE_BYTES, "complete_pages": size // PAGE_BYTES,
            "trailing_page_bytes": size % PAGE_BYTES}


def boot_argument_facts(fat):
    document = tomllib.loads(fat.read("EFI/UniXNU/unixnu.toml").decode("utf-8"))
    entries = document.get("entry", [])
    selected = [entry for entry in entries if entry.get("id") == "xnu"]
    if len(selected) != 1 or not isinstance(selected[0].get("args"), str):
        raise ValueError("The retained TOML must have exactly one xnu entry with args")
    args = selected[0]["args"]
    tokens = shlex.split(args)
    keys = ("native-source-storage", "droidvm-data-persist", "owner-debug", "droidvm-ipados-lsd-floor")
    return {"toml_args": args,
            "selected_flag_values": {key: [token[len(key) + 1:] for token in tokens
                                           if token.startswith(key + "=")] for key in keys},
            "effective_guest_boot_arguments_verified": False}


def merged_ranges(ranges):
    result = []
    for start, end in sorted(ranges):
        if start < 0 or start >= end or end > SOURCE_BYTES:
            raise ValueError("A planned write is outside the pinned disk")
        if result and start < result[-1][1]:
            raise ValueError("The parser's planned kernel writes overlap")
        if result and start == result[-1][1]:
            result[-1] = (result[-1][0], end)
        else:
            result.append((start, end))
    return result


def verify_image_changes(source, target, allowed):
    """Compare every byte, including FATs, unused space, directory flags and times."""
    source_digest, target_digest = hashlib.sha256(), hashlib.sha256()
    changed_bytes = 0
    changed_page_ranges = []
    range_index = 0
    offset = 0
    with source.open("rb") as original, target.open("rb") as modified:
        while before := original.read(CHUNK_BYTES):
            after = modified.read(len(before))
            if len(after) != len(before):
                raise ValueError("The independent disk's length changed")
            source_digest.update(before)
            target_digest.update(after)
            if before != after:
                for position in range(0, len(before), CLUSTER_BYTES):
                    if before[position:position + CLUSTER_BYTES] == after[position:position + CLUSTER_BYTES]:
                        continue
                    page = (offset + position) // CLUSTER_BYTES
                    if changed_page_ranges and changed_page_ranges[-1][1] == page:
                        changed_page_ranges[-1][1] = page + 1
                    else:
                        changed_page_ranges.append([page, page + 1])
                cursor = 0
                while cursor < len(before):
                    absolute = offset + cursor
                    while range_index < len(allowed) and allowed[range_index][1] <= absolute:
                        range_index += 1
                    inside = range_index < len(allowed) and allowed[range_index][0] <= absolute
                    boundary = (allowed[range_index][1] if inside else allowed[range_index][0]) if range_index < len(allowed) else offset + len(before)
                    end = min(len(before), boundary - offset)
                    old, new = before[cursor:end], after[cursor:end]
                    if old != new:
                        if not inside:
                            relative = next(index for index, (a, b) in enumerate(zip(old, new)) if a != b)
                            raise ValueError(f"A disk byte changed outside kernel content or its directory size: {absolute + relative}")
                        changed_bytes += sum(a != b for a, b in zip(old, new))
                    cursor = end
            offset += len(before)
        if modified.read(1) or offset != SOURCE_BYTES:
            raise ValueError("The independent disk gained bytes or the pinned source length changed")
    if source_digest.hexdigest() != SOURCE_SHA256:
        raise ValueError("The original boot disk changed during preparation")
    return {"output_sha256": target_digest.hexdigest(), "source_after_sha256": source_digest.hexdigest(),
            "changed_byte_count": changed_bytes, "changed_disk_page_bytes": CLUSTER_BYTES,
            "changed_disk_page_count": sum(end - start for start, end in changed_page_ranges),
            "changed_disk_page_ranges": [{"first_page": start, "end_page_exclusive": end}
                                         for start, end in changed_page_ranges]}


def prepare(kernel_input, manifest_input, output_input):
    source, inventory_path = workspace_file(SOURCE), workspace_file(INVENTORY)
    anchor_path = workspace_file(PUBLIC_ANCHOR)
    kernel_path, manifest_path = workspace_file(kernel_input), workspace_file(manifest_input)
    output = output_input.resolve()
    output_root = (ROOT / "output").resolve()
    if output == output_root or not output.is_relative_to(output_root):
        raise ValueError("Use a new independent directory below this workspace's output directory")
    if output.exists() or output.is_symlink():
        raise FileExistsError("Preserve existing output; the output directory must not already exist")
    manifest, manifest_digest, kernel_size, kernel_digest = admitted_kernel(manifest_path, kernel_path)
    inventory, inventory_digest = pinned_inventory(inventory_path)
    anchor = anchor_path.read_bytes()
    if len(anchor) != 395 or hashlib.sha256(anchor).hexdigest() != PUBLIC_ANCHOR_SHA256:
        raise ValueError("The retained original public anchor differs from this source's fixed pin")
    if source.stat().st_size != SOURCE_BYTES or sha256(source) != SOURCE_SHA256:
        raise ValueError("The original boot disk differs from its fixed full-image pin")
    Fat32 = load_fat_parser()
    original_fat = Fat32(source)
    try:
        before = member_facts(original_fat)
        if before.keys() != inventory["members"].keys() or any(
                {key: facts[key] for key in ("bytes", "sha256")} != inventory["members"][path]
                for path, facts in before.items()):
            raise ValueError("Actual original FAT members differ from the retained inventory")
        member = original_fat.members[KERNEL_PATH]
        chain = list(original_fat.chain(member.cluster))
        capacity = len(chain) * original_fat.cluster_bytes
        if (original_fat.cluster_bytes != CLUSTER_BYTES or len(chain) != CHAIN_CLUSTERS
                or member.size != KERNEL_BYTES or capacity != KERNEL_BYTES):
            raise ValueError("The original kernel's real allocation differs from the fixed inventory")
        original_fat.stream.seek(original_fat.offset(member.cluster))
        original_macho = macho_facts(original_fat.stream.read(32), member.size)
        original_anchor_offsets = anchor_offsets(original_fat, member, anchor)
        if len(original_anchor_offsets) != 1:
            raise ValueError("The original source kernel must retain exactly one complete pinned public anchor")
        with kernel_path.open("rb") as stream:
            new_macho = macho_facts(stream.read(32), kernel_size)
        report = {"operation": "replace_only_kernel_in_independent_pinned_ipados_boot_copy", "ok": False,
                  "created_at_utc": datetime.now(timezone.utc).isoformat(), "phase": "capacity preflight",
                  "source": str(source), "source_bytes": SOURCE_BYTES, "source_sha256": SOURCE_SHA256,
                  "source_inventory": str(inventory_path), "source_inventory_sha256": inventory_digest,
                  "kernel": str(kernel_path), "kernel_sha256": kernel_digest, "kernel_bytes": kernel_size,
                  "supplied_kernel": str(kernel_input), "supplied_manifest": str(manifest_input),
                  "supplied_output_dir": str(output_input),
                  "admitted_manifest": str(manifest_path), "admitted_manifest_sha256": manifest_digest,
                  "manifest_input_facts": {"policy": manifest["policy"],
                                           "source_pins": {key: manifest[key] for key in SOURCE_PINS},
                                           "original_public_anchor_sha256": manifest["original_public_anchor_sha256"],
                                           "original_data_seed_sha256": manifest["original_data_seed_sha256"],
                                           "original_data_volume_uuid": manifest["original_data_volume_uuid"]},
                  "manifest_interpretation": "Input provenance; no manifest flag establishes phone or guest verification",
                  "public_anchor": {"source": str(anchor_path), "bytes": len(anchor),
                                    "sha256": PUBLIC_ANCHOR_SHA256,
                                    "original_kernel_file_offset": original_anchor_offsets[0],
                                    "original_kernel_file_page_bytes": PAGE_BYTES,
                                    "original_kernel_file_page_index": original_anchor_offsets[0] // PAGE_BYTES},
                  "kernel_member": KERNEL_PATH, "original_kernel_bytes": member.size,
                  "original_kernel_sha256": KERNEL_SHA256, "existing_chain_clusters": len(chain),
                  "existing_allocation_bytes": capacity, "kernel_fits_existing_allocation": kernel_size <= capacity,
                  "additional_clusters_required": max(0, (kernel_size + CLUSTER_BYTES - 1) // CLUSTER_BYTES - len(chain)),
                  "original_kernel_macho": original_macho, "new_kernel_macho": new_macho,
                  "source_boot_arguments": boot_argument_facts(original_fat), "original_members": before,
                  "phone_operated": False, "adb_invoked": False, "target_executed": False,
                  "kernel_built_by_this_tool": False, "guest_boot_verified": False, "runtime_floor_verified": False}
        output.mkdir(parents=True, exist_ok=False)
        target = output / "droidvm-disk-ipados-lsd-floor.img"
        report_path = output / "preparation.json"
        report["output"] = str(target)
        with report_path.open("x", encoding="utf-8") as report_stream:
            def save():
                report_stream.seek(0)
                json.dump(report, report_stream, ensure_ascii=False, indent=2)
                report_stream.write("\n")
                report_stream.truncate()
                report_stream.flush()
            save()
            try:
                if kernel_size > capacity:
                    raise ValueError(f"New kernel is {kernel_size} bytes; existing allocation is {capacity}. "
                                     f"{report['additional_clusters_required']} additional FAT clusters are required; no image was copied")
                replacement = kernel_path.read_bytes()
                if len(replacement) != kernel_size or hashlib.sha256(replacement).hexdigest() != kernel_digest:
                    raise ValueError("The admitted kernel changed before preparation")
                if replacement.count(anchor) != 1:
                    raise ValueError("The new kernel must retain exactly one complete original public anchor")
                new_anchor_offset = replacement.find(anchor)
                report["public_anchor"].update(new_kernel_file_offset=new_anchor_offset,
                                              new_kernel_file_page_index=new_anchor_offset // PAGE_BYTES,
                                              complete_anchor_present_in_original_and_new=True)
                remaining = kernel_size
                writes = []
                for cluster in chain:
                    length = min(CLUSTER_BYTES, remaining)
                    if not length:
                        break
                    writes.append((original_fat.offset(cluster), length))
                    remaining -= length
                if remaining:
                    raise ValueError("The retained FAT chain cannot cover the actual new kernel")
                size_offset = member.entry_offset + 28
                allowed = [(offset, offset + length) for offset, length in writes]
                if kernel_size != member.size:
                    allowed.append((size_offset, size_offset + 4))
                allowed = merged_ranges(allowed)
                report.update(phase="copy pinned original", kernel_write_method="replace_same_length" if kernel_size == member.size else "existing_chain_content_and_real_directory_size",
                              unused_allocation_bytes=capacity - kernel_size,
                              allowed_disk_byte_ranges=[{"start": start, "end_exclusive": end} for start, end in allowed])
                save()
                copy_digest = hashlib.sha256()
                copied = 0
                with source.open("rb") as incoming, target.open("xb") as outgoing:
                    while chunk := incoming.read(CHUNK_BYTES):
                        copy_digest.update(chunk)
                        if outgoing.write(chunk) != len(chunk):
                            raise OSError("The independent boot disk copy was incompletely written")
                        copied += len(chunk)
                if copied != SOURCE_BYTES or copy_digest.hexdigest() != SOURCE_SHA256 or sha256(target) != SOURCE_SHA256:
                    raise ValueError("The independent copy did not preserve the complete pinned source")
                report.update(phase="replace kernel", complete_copy_bytes=copied, complete_copy_sha256=SOURCE_SHA256)
                save()
                copied_fat = Fat32(target)
                try:
                    if kernel_size == member.size:
                        copied_fat.replace_same_length(KERNEL_PATH, replacement)
                    else:
                        consumed = 0
                        with target.open("r+b") as stream:
                            for offset, length in writes:
                                stream.seek(offset)
                                if stream.write(replacement[consumed:consumed + length]) != length:
                                    raise OSError("A kernel content write was incomplete")
                                consumed += length
                            stream.seek(size_offset)
                            if stream.write(struct.pack("<I", kernel_size)) != 4:
                                raise OSError("The kernel's directory size write was incomplete")
                        if consumed != kernel_size:
                            raise ValueError("The kernel was not completely written")
                finally:
                    copied_fat.close()
                report["phase"] = "verify all members and complete disk"
                save()
                final_fat = Fat32(target)
                try:
                    after = member_facts(final_fat)
                    if before.keys() != after.keys() or final_fat.fat != original_fat.fat:
                        raise ValueError("The copied FAT inventory or allocation table changed")
                    for path, facts in before.items():
                        expected = dict(facts)
                        if path == KERNEL_PATH:
                            expected.update(bytes=kernel_size, sha256=kernel_digest)
                        if after[path] != expected:
                            raise ValueError(f"A retained member's bytes, digest, chain or directory entry changed: {path}")
                    if list(final_fat.chain(final_fat.members[KERNEL_PATH].cluster)) != chain:
                        raise ValueError("The original kernel FAT chain changed")
                finally:
                    final_fat.close()
                diff = verify_image_changes(source, target, allowed)
                if (sha256(kernel_path) != kernel_digest or sha256(manifest_path) != manifest_digest
                        or sha256(inventory_path) != inventory_digest or sha256(anchor_path) != PUBLIC_ANCHOR_SHA256):
                    raise ValueError("A selected kernel or input provenance record changed during preparation")
                report.update(diff, ok=True, phase="complete", output_bytes=target.stat().st_size,
                              final_members=after, unchanged_members=[path for path in before if path != KERNEL_PATH],
                              original_source_unchanged=True, all_selected_inputs_unchanged=True,
                              fat_allocation_unchanged=True, directory_flags_and_times_unchanged=True,
                              all_image_changes_within_kernel_content_and_directory_size=True,
                              kernel_padding_bytes_added=0, completed_at_utc=datetime.now(timezone.utc).isoformat())
                save()
            except BaseException as error:
                report.update(error=f"{type(error).__name__}: {error}", failed_at_utc=datetime.now(timezone.utc).isoformat())
                save()
                raise
        return report, report_path
    finally:
        original_fat.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True, help="the admitted native-compiled ARM64 Mach-O fileset")
    parser.add_argument("--manifest", type=Path, required=True, help="the admitted input provenance manifest")
    parser.add_argument("--output-dir", type=Path, required=True, help="a new independent directory below workspace/output")
    args = parser.parse_args()
    report, path = prepare(args.kernel, args.manifest, args.output_dir)
    print(json.dumps({"ok": report["ok"], "output": report["output"], "output_bytes": report["output_bytes"],
                      "output_sha256": report["output_sha256"], "kernel_bytes": report["kernel_bytes"],
                      "unchanged_fat_members": len(report["unchanged_members"]), "report": str(path),
                      "phone_operated": False, "guest_boot_verified": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
