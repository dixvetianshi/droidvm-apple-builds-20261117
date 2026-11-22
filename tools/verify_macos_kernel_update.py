#!/usr/bin/env python3
"""Verify the pinned PSCI source and its compiled path into the kernel collection."""
import argparse
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess

MACOS_PIN = "524d27bf57ae92375aa39e3a81e11727c08973ff"
PLATFORM_PIN = "0d544705c2e89725caabc0542bb96bc8febd8c70"
XNU_PIN = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"
SYMBOL = "__ZN13ArmDTPlatform11haltRestartEj"
SOURCE_HASHES = {
    "k27/build-platform-rtc.sh": "5c11d57c49ab3c9c0151c54d7ffe180625b41881ef1163e78ee5ce409287ecdc",
    "patches/drivers/ArmDTPlatform-droidvm-psci.patch": "0aa50d9f4188182ade9f42464e3f9eff24ade736f87a9c3db237fe51e90eb47b",
}
PLATFORM_SHA256 = "656d02ee6c5fae84eb41aadfb68747e0d2eb7c497e09060d6873e94b06b59a04"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def require(value, message):
    if not value:
        raise ValueError(message)


def source_record(root):
    require(command("git", "rev-parse", "HEAD", cwd=root) == MACOS_PIN, "macOS source pin differs")
    sources = {}
    for relative, expected in SOURCE_HASHES.items():
        actual = sha256(root / relative)
        require(actual == expected, f"reviewed source digest differs: {relative}")
        sources[relative] = actual
    lock = json.loads((root / "configs/env.lock.json").read_text())
    require(lock["git"]["ArmDTPlatform"]["commit"] == PLATFORM_PIN, "platform pin differs")
    require(lock["git"]["xnu"]["commit"] == XNU_PIN, "XNU pin differs")
    return {"macos_source_commit": MACOS_PIN, "platform_commit": PLATFORM_PIN,
            "xnu_commit": XNU_PIN, "reviewed_source_sha256": sources}


def span(data, offset, size, label):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
            f"out-of-range {label}")


def method_record(symbols, sections, data_size):
    matches = [row for row in symbols if row[0] == SYMBOL]
    require(len(matches) == 1, f"expected one PSCI method symbol, found {len(matches)}")
    _, kind, index, _, address = matches[0]
    require(kind & 0x0E == 0x0E and not kind & 0xE0, "PSCI method is not a non-STAB N_SECT symbol")
    require(1 <= index <= len(sections), "PSCI method has an invalid section index")
    section = sections[index - 1]
    require(section["name"] == "__text" and section["segment"] in ("__TEXT", "__TEXT_EXEC"),
            "PSCI method is outside the compiled text section")
    require(section["initprot"] & 4 and section["maxprot"] & 4,
            "PSCI method segment lacks executable protection")
    require(section["flags"] & 0x80000000 and section["flags"] & 0xFF == 0,
            "PSCI method section is not file-backed pure instructions")
    end = section["va"] + section["size"]
    require(section["va"] <= address < end, "PSCI method address is outside its section")
    require(0 <= section["fileoff"] <= data_size and section["size"] <= data_size - section["fileoff"],
            "PSCI method section exceeds the file")
    following = [value for _, other_kind, other_index, _, value in symbols
                 if other_index == index and other_kind & 0x0E == 0x0E and not other_kind & 0xE0
                 and address < value < end]
    extent = min(following, default=end) - address
    require(extent > 0 and extent % 4 == 0, "PSCI method has an invalid instruction extent")
    return {"symbol": SYMBOL, "address": hex(address), "n_type": hex(kind), "section_index": index,
            "segment": section["segment"], "section": section["name"],
            "section_flags": hex(section["flags"]), "maxprot": section["maxprot"],
            "initprot": section["initprot"], "method_bytes": extent}


def compiled_method(path, expected_filetype):
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        span(data, 0, 32, "Mach-O header")
        magic, cpu, _, filetype, count, command_bytes = struct.unpack_from("<6I", data)
        require((magic, cpu, filetype) == (0xFEEDFACF, 0x100000C, expected_filetype),
                f"unexpected compiled Mach-O identity: {path}")
        span(data, 32, command_bytes, "load commands")
        offset, sections, symtab = 32, [], None
        for _ in range(count):
            require(offset + 8 <= 32 + command_bytes, "truncated load command")
            opcode, size = struct.unpack_from("<II", data, offset)
            require(size >= 8 and offset + size <= 32 + command_bytes, "invalid load command size")
            if opcode == 0x19:
                require(size >= 72, "truncated segment command")
                _, va, vmsize, fileoff, filesize, maxprot, initprot, nsects, _ = struct.unpack_from("<16s4Q4I", data, offset + 8)
                require(72 + nsects * 80 <= size, "truncated segment sections")
                span(data, fileoff, filesize, "segment data")
                for number in range(nsects):
                    values = struct.unpack_from("<16s16sQQ8I", data, offset + 72 + number * 80)
                    name, segment, sva, ssize, soff, _, _, _, flags, _, _, _ = values
                    sections.append({"name": name.split(b"\0")[0].decode(),
                                     "segment": segment.split(b"\0")[0].decode(),
                                     "va": sva, "size": ssize, "fileoff": soff, "flags": flags,
                                     "maxprot": maxprot, "initprot": initprot})
                    if name.split(b"\0")[0] == b"__text":
                        require(va <= sva and ssize <= va + vmsize - sva, "text section exceeds its segment VM range")
                        require(fileoff <= soff and ssize <= fileoff + filesize - soff, "text section exceeds its segment file range")
            elif opcode == 2:
                require(size >= 24 and symtab is None, "invalid or duplicate symbol table command")
                symtab = struct.unpack_from("<4I", data, offset + 8)
            offset += size
        require(offset == 32 + command_bytes and symtab is not None, "missing or inconsistent Mach-O commands")
        symoff, nsyms, stroff, strsize = symtab
        span(data, symoff, nsyms * 16, "symbol table")
        span(data, stroff, strsize, "string table")
        strings, symbols = data[stroff:stroff + strsize], []
        for number in range(nsyms):
            strx, kind, index, description, address = struct.unpack_from("<IBBHQ", data, symoff + number * 16)
            require(strx < len(strings), "invalid symbol string index")
            end = strings.find(b"\0", strx)
            require(end >= strx, "unterminated symbol name")
            name = strings[strx:end].decode(errors="replace")
            symbols.append((name, kind, index, description, address))
        return dict(method_record(symbols, sections, len(data)), filetype=filetype)


def link_diagnostics(root, trace):
    """Publish selected symbols and linker metadata, never instructions or Apple payload bytes."""
    result = {"scope": "selected ArmDTPlatform symbols, archive members and linker metadata", "files": {}}
    paths = ("out/x12377/native-kexts/ArmDTPlatform/ArmDTPlatform.o",
             "out/x12377/un/build/platform-12377-arm64e/ArmDTPlatform/libArmDTPlatform.a",
             "out/k27/obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf",
             "out/k27/kernel-k27.macho")
    for relative in paths:
        path = root / relative
        facts = result["files"][relative] = {"exists": path.exists()}
        if not path.exists():
            continue
        facts.update({"bytes": path.stat().st_size, "mtime_ns": path.stat().st_mtime_ns, "sha256": sha256(path)})
        try:
            rows = command("llvm-nm", "--defined-only", "--no-sort", str(path)).splitlines()
            facts["arm_dt_platform_nm_rows"] = [row for row in rows if row.split() and "ArmDTPlatform" in row.split()[-1]]
            facts["exact_method_nm_rows"] = [row for row in rows if row.split() and row.split()[-1] == SYMBOL]
            if path.suffix == ".a":
                facts["archive_members"] = command("llvm-ar", "t", str(path)).splitlines()
        except (OSError, subprocess.CalledProcessError) as error:
            facts["tool_error"] = str(error)
    if trace is not None:
        result["link_trace_exists"] = trace.exists()
        result["kernel_link_commands"] = ([line for line in trace.read_text().splitlines()
                                            if "mach.development.bcm2837.unstripped.noctf" in line]
                                           if trace.exists() else [])
    return result


def build_record(root, diagnostics=None):
    record = source_record(root)
    platform = root / "out/x12377/un/build/platform-12377-arm64e/ArmDTPlatform/ArmDTPlatform.cpp"
    require(sha256(platform) == PLATFORM_SHA256, "compiled platform source differs from reviewed patch")
    obj = root / "out/x12377/native-kexts/ArmDTPlatform/ArmDTPlatform.o"
    object_method = compiled_method(obj, 1)
    if diagnostics is not None:
        diagnostics["object_method"] = object_method
    kernel = root / "out/k27/kernel-k27.macho"
    kernel_method = compiled_method(kernel, 2)
    address = int(kernel_method["address"], 16)
    if diagnostics is not None:
        diagnostics["kernel_method"] = kernel_method
    collection = root / "out/k27/kc-k27.bin"
    require(0 < collection.stat().st_size <= 512 * 1024 * 1024,
            "KC exceeds the pinned patched DarwinBoot kernel read limit")
    spec = importlib.util.spec_from_file_location("fileset_kc", root / "scripts/fileset_kc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with collection.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        kc = module.Kernelcache(data)
        macho = kc.macho("com.apple.kernel")
        require(macho["kind"] == 2, "collection kernel is not MH_EXECUTE")
        sections = [dict(section, maxprot=segment["maxprot"], initprot=segment["initprot"],
                         flags=struct.unpack_from("<I", data, section["command_offset"] + 64)[0])
                    for segment in macho["segments"] for section in segment["sections"]]
        collection_method = method_record(kc.symbols(macho), sections, len(data))
        require(collection_method["address"] == kernel_method["address"], "PSCI method was not preserved at the linked kernel address")
        if diagnostics is not None:
            diagnostics["collection_method"] = collection_method
        length = collection_method["method_bytes"]
        code = data[kc.file_offset(address, length):kc.file_offset(address, length) + length]
        instructions = [code[at:at + 4] for at in range(0, len(code), 4)]
        require(bytes.fromhex("020000d4") in instructions, "compiled SYSTEM_OFF/RESET path lacks HVC")
        require(bytes.fromhex("030000d4") in instructions, "compiled explicit SMC path is missing")
    record.update({
        "platform_source_sha256": PLATFORM_SHA256,
        "compiled_method": SYMBOL,
        "object_method": object_method,
        "kernel_method": kernel_method,
        "collection_method": collection_method,
        "kernel_and_collection_method_address": hex(address),
        "kernel_collection": {"path": "out/k27/kc-k27.bin", "bytes": collection.stat().st_size,
                              "sha256": sha256(collection)},
        "compiled_method_in_object_kernel_and_collection": True,
        "compiled_HVC_and_SMC_present": True,
        "panic_and_sync_parent_behavior": "preserved by the exact reviewed source digest",
        "verification_scope": "completed kernel/kext/KC build and compiled PSCI method presence",
        "executed_guest_boot": False,
        "executed_guest_shutdown_restart": False,
        "encrypted_payload_members": ["out/k27/kc-k27.bin"],
        "preserve_existing_boot_files": ["kernel.macho.adt", "kernel.macho.trustcache", "scratch-data.img", "unixnu.toml"],
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "build_instructions_commit": os.environ.get("GITHUB_SHA"),
        "reused_inputs_release": "inputs-27.2-" + os.environ.get("INPUTS_KEY", "unknown"),
    })
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--diagnostics", type=Path, help="selected symbol/link metadata, including on verification failure")
    parser.add_argument("--link-trace", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    diagnostics = None
    try:
        if not args.source_only and args.diagnostics:
            diagnostics = link_diagnostics(root, args.link_trace)
        record = source_record(root) if args.source_only else build_record(root, diagnostics)
        if diagnostics is not None:
            diagnostics["verification_status"] = "passed"
    except Exception as error:
        if diagnostics is not None:
            diagnostics.update({"verification_status": "failed", "verification_error": str(error)})
        raise
    finally:
        if diagnostics is not None:
            args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
            args.diagnostics.write_text(json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
