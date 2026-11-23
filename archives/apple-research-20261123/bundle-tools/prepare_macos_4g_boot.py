#!/usr/bin/env python3
"""Prepare a new 4 GiB macOS boot-disk copy, preserving the original Apple payload.

Only declared address/size properties in the FAT32 ADT sidecar can change. The
captured 4 GiB RAM/pool log and fixed source layout establish the first copy;
the fresh runtime FDT must subsequently be checked. No phone access occurs.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "output/macos-stage/boot.img"
OUTPUT = ROOT / "output/device-repair-20261119/macos-4g"
SOURCE_SHA256 = "991125c52d9e1becee16a39c670f8573ed8c0ddb64b06c7c578e7083973c45d1"
FDT_SOURCE = ROOT / "sources/macOS-DroidVM/configs/k27-generated.dtb"
FDT_SOURCE_SHA256 = "89952c66df5293a18a094ecb74b0166493d13e899854614e983bc4b37342f0f8"
FDT_RUNTIME = ROOT / "verification/boot-repair-20261119/macos-runtime-4096.dtb"
# The parent address in run-macos-vm.py's <IQQQ PCI ranges is relative to this
# base, declared by its make-droidvm-adt.py owner and by the original /arm-io ranges.
ARMIO_BASE = 0x1000
ADT_PATH = "EFI/UniXNU/Payloads/kernel.macho.adt"
TOML_PATH = "EFI/UniXNU/unixnu.toml"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass
class FatMember:
    path: str
    cluster: int
    size: int
    entry_offset: int


class Fat32:
    """The fixed FAT32 ESP format emitted by this pinned build's mformat."""
    def __init__(self, path):
        self.path = Path(path)
        self.stream = self.path.open("rb")
        header = self.stream.read(512)
        if header[510:512] != b"\x55\xaa" or header[82:90] != b"FAT32   ":
            raise ValueError("Source boot disk is not the expected direct FAT32 ESP")
        self.sector = struct.unpack_from("<H", header, 11)[0]
        self.cluster_bytes = self.sector * header[13]
        reserved = struct.unpack_from("<H", header, 14)[0]
        fat_count = header[16]
        self.sectors = struct.unpack_from("<I", header, 32)[0]
        fat_sectors = struct.unpack_from("<I", header, 36)[0]
        self.root_cluster = struct.unpack_from("<I", header, 44)[0]
        if self.sector != 512 or not self.cluster_bytes or fat_count != 2 or self.path.stat().st_size != self.sectors * self.sector:
            raise ValueError("Unexpected FAT32 geometry")
        self.data_offset = (reserved + fat_count * fat_sectors) * self.sector
        self.stream.seek(reserved * self.sector)
        self.fat = self.stream.read(fat_sectors * self.sector)
        self.members = {}
        self._walk(self.root_cluster, "", set())

    def close(self):
        self.stream.close()

    def chain(self, first):
        current = first
        seen = set()
        while current < 0x0ffffff8:
            if current < 2 or current in seen or (current + 1) * 4 > len(self.fat):
                raise ValueError("Invalid or repeated FAT cluster")
            seen.add(current)
            yield current
            current = struct.unpack_from("<I", self.fat, current * 4)[0] & 0x0fffffff

    def offset(self, cluster):
        return self.data_offset + (cluster - 2) * self.cluster_bytes

    @staticmethod
    def short_name(raw):
        base = raw[:8].decode("ascii").rstrip()
        extension = raw[8:11].decode("ascii").rstrip()
        return base + ("." + extension if extension else "")

    def _walk(self, first, parent, directories):
        if first in directories:
            raise ValueError("Repeated FAT directory")
        directories.add(first)
        long_parts = {}
        for cluster in self.chain(first):
            offset = self.offset(cluster)
            self.stream.seek(offset)
            data = self.stream.read(self.cluster_bytes)
            for start in range(0, len(data), 32):
                entry = data[start:start + 32]
                if entry[0] == 0:
                    return
                if entry[0] == 0xe5:
                    long_parts.clear()
                    continue
                attributes = entry[11]
                if attributes == 0x0f:
                    if entry[0] & 0x40:
                        long_parts.clear()
                    part = entry[1:11] + entry[14:26] + entry[28:32]
                    long_parts[entry[0] & 0x1f] = part
                    continue
                if attributes & 8:
                    long_parts.clear()
                    continue
                if long_parts:
                    name = b"".join(long_parts[index] for index in sorted(long_parts)).decode("utf-16le").split("\0", 1)[0].rstrip("\uffff")
                else:
                    name = self.short_name(entry[:11])
                long_parts.clear()
                if name in (".", ".."):
                    continue
                if not name or "/" in name or "\\" in name:
                    raise ValueError("Invalid FAT member name")
                path = parent + "/" + name if parent else name
                first_cluster = struct.unpack_from("<H", entry, 26)[0] | (struct.unpack_from("<H", entry, 20)[0] << 16)
                if attributes & 0x10:
                    self._walk(first_cluster, path, directories)
                else:
                    if path in self.members:
                        raise ValueError("Repeated FAT file")
                    self.members[path] = FatMember(path, first_cluster, struct.unpack_from("<I", entry, 28)[0], offset + start)

    def chunks(self, member):
        remaining = member.size
        if not remaining:
            return
        for cluster in self.chain(member.cluster):
            if not remaining:
                break
            self.stream.seek(self.offset(cluster))
            data = self.stream.read(min(self.cluster_bytes, remaining))
            if not data:
                raise ValueError("FAT file ended early")
            remaining -= len(data)
            yield data
        if remaining:
            raise ValueError("FAT chain does not cover its declared file")

    def read(self, path):
        member = self.members[path]
        if member.size > 4 * 1024 * 1024:
            raise ValueError("Only the small ADT/TOML sidecars are read into memory")
        return b"".join(self.chunks(member))

    def member_digest(self, member):
        digest = hashlib.sha256()
        for chunk in self.chunks(member):
            digest.update(chunk)
        return digest.hexdigest()

    def replace_same_length(self, path, replacement):
        member = self.members[path]
        if len(replacement) != member.size:
            raise ValueError("ADT replacement must preserve FAT allocation and file size")
        written = 0
        with self.path.open("r+b") as stream:
            for cluster in self.chain(member.cluster):
                if written == len(replacement):
                    break
                stream.seek(self.offset(cluster))
                chunk = replacement[written:written + self.cluster_bytes]
                stream.write(chunk)
                written += len(chunk)
        if written != len(replacement):
            raise ValueError("ADT replacement was not completely written")


def adt_properties(blob):
    result = {}
    def node(offset, parent):
        if offset + 8 > len(blob):
            raise ValueError("ADT node header is truncated")
        property_count, child_count = struct.unpack_from("<II", blob, offset)
        offset += 8
        local = {}
        for _ in range(property_count):
            if offset + 36 > len(blob):
                raise ValueError("ADT property header is truncated")
            name = blob[offset:offset + 32].split(b"\0", 1)[0].decode("ascii")
            length = struct.unpack_from("<I", blob, offset + 32)[0] & 0x7fffffff
            offset += 36
            if offset + length > len(blob) or name in local:
                raise ValueError("ADT property is truncated or repeated")
            local[name] = (offset, blob[offset:offset + length])
            offset += (length + 3) & ~3
        name = local["name"][1].rstrip(b"\0").decode("ascii")
        path = "/" if not parent else parent.rstrip("/") + "/" + name
        if path in result:
            raise ValueError("ADT node path repeated")
        result[path] = local
        for _ in range(child_count):
            offset = node(offset, path)
        return offset
    end = node(0, "")
    if end != len(blob):
        raise ValueError("ADT coverage does not match its sidecar size")
    return result


def shown(value):
    if len(value) in (4, 8):
        return hex(int.from_bytes(value, "little"))
    if len(value) in (16, 24):
        return [hex(number) for number in struct.unpack("<" + "Q" * (len(value) // 8), value)]
    if value.endswith(b"\0") and all(32 <= item < 127 or item == 0 for item in value):
        return value.rstrip(b"\0").decode("ascii")
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def inspect(source, output):
    output.mkdir(parents=True, exist_ok=True)
    fat = Fat32(source)
    try:
        adt = fat.read(ADT_PATH)
        properties = adt_properties(adt)
        selected = {path: {name: shown(value) for name, (_, value) in props.items()}
                    for path, props in properties.items() if path in ("/chosen", "/pram", "/defaults") or path.startswith("/arm-io/") or path.startswith("/cpus/")}
        for name, content in (("original-kernel.macho.adt", adt), ("original-unixnu.toml", fat.read(TOML_PATH))):
            target = output / name
            if target.exists() and target.read_bytes() != content:
                raise FileExistsError("Preserve the existing inspection output")
            if not target.exists():
                target.write_bytes(content)
        record = {"source": str(source), "source_bytes": source.stat().st_size,
                  "fat_sector_bytes": fat.sector, "fat_cluster_bytes": fat.cluster_bytes,
                  "members": [{"path": entry.path, "bytes": entry.size, "cluster": entry.cluster} for entry in fat.members.values()],
                  "adt_sha256": hashlib.sha256(adt).hexdigest(), "adt_properties": selected,
                  "original_inputs_modified": False, "phone_operated": False}
        (output / "inspection.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return record
    finally:
        fat.close()


def fdt_offsets(blob):
    magic, total, structure, strings, _, version, _, _, string_bytes, structure_bytes = struct.unpack_from(">10I", blob)
    if magic != 0xd00dfeed or total != len(blob) or version < 16:
        raise ValueError("Invalid source FDT")
    string_table = blob[strings:strings + string_bytes]
    offset = structure
    stack = []
    nodes, properties = {}, {}
    while offset < structure + structure_bytes:
        tag = struct.unpack_from(">I", blob, offset)[0]
        offset += 4
        if tag == 1:
            end = blob.index(0, offset, structure + structure_bytes)
            name = blob[offset:end].decode("ascii")
            stack.append(name)
            path = "/" + "/".join(stack[1:])
            nodes[path] = (offset, blob[offset:end])
            properties[path] = {}
            offset = (end + 4) & ~3
        elif tag == 2:
            stack.pop()
        elif tag == 3:
            length, name_offset = struct.unpack_from(">II", blob, offset)
            offset += 8
            name = string_table[name_offset:].split(b"\0", 1)[0].decode("ascii")
            path = "/" + "/".join(stack[1:])
            properties[path][name] = (offset, blob[offset:offset + length])
            offset += (length + 3) & ~3
        elif tag == 4:
            continue
        elif tag == 9:
            if stack:
                raise ValueError("Unclosed FDT nodes")
            return nodes, properties
        else:
            raise ValueError("Unknown source FDT token")
    raise ValueError("FDT structure ended without its terminator")


def pci_ranges(blob):
    _, properties = fdt_offsets(blob)
    candidates = [(path, props) for path, props in properties.items()
                  if b"pci-host-ecam-generic" in props.get("compatible", (0, b""))[1]]
    if len(candidates) != 1:
        raise ValueError("The runtime profile must contain exactly one PCI host")
    path, props = candidates[0]
    if (props.get("#address-cells", (0, b""))[1] != struct.pack(">I", 3)
            or props.get("#size-cells", (0, b""))[1] != struct.pack(">I", 2)
            or properties["/"].get("#address-cells", (0, b""))[1] != struct.pack(">I", 2)):
        raise ValueError("PCI ranges do not use the pinned 3/2/2-cell address layout")
    ranges = props["ranges"][1]
    if not ranges or len(ranges) % 28:
        raise ValueError("PCI ranges do not contain complete seven-cell entries")
    rows = []
    for offset in range(0, len(ranges), 28):
        cells = struct.unpack_from(">7I", ranges, offset)
        rows.append((cells[0], cells[1] << 32 | cells[2],
                     cells[3] << 32 | cells[4], cells[5] << 32 | cells[6]))
    return path, ranges, rows


def adt_pci_ranges(rows):
    converted = bytearray()
    for flags, pci_address, cpu_address, size in rows:
        if cpu_address < ARMIO_BASE or not size:
            raise ValueError("PCI range cannot be represented relative to arm-io")
        # Exact conversion owned by run-macos-vm.py make_adt, MACOS_PCIE=1.
        converted += struct.pack("<IQQQ", flags, pci_address, cpu_address - ARMIO_BASE, size)
    return bytes(converted)


def require_4g_pci_ranges(source_blob, runtime_blob):
    source_path, source_raw, before = pci_ranges(source_blob)
    runtime_path, runtime_raw, after = pci_ranges(runtime_blob)
    expected_source = [(0x02000000, 0x02000000, 0x02000000, 0x02000000),
                       (0x43000000, 0x1c0800000, 0x1c0800000, 0x15f800000)]
    expected_runtime = [(0x02000000, 0x02000000, 0x02000000, 0x02000000),
                        (0x43000000, 0x180800000, 0x180800000, 0x19f800000)]
    if before != expected_source or after != expected_runtime:
        raise ValueError("Source or captured PCI aperture differs from the pinned 5/4 GiB profile")
    if source_path != runtime_path or len(source_raw) != len(runtime_raw):
        raise ValueError("Captured PCI aperture cannot retain the source FDT allocation")
    return source_path, source_raw, runtime_raw, before, after


def derived_fdt_4g(blob, runtime_blob):
    nodes, properties = fdt_offsets(blob)
    modified = bytearray(blob)
    updates = []
    def update_property(path, name, old, new):
        offset, original = properties[path][name]
        if original != old or len(new) != len(old):
            raise ValueError("Fixed FDT property differs from the retained source profile")
        modified[offset:offset + len(new)] = new
        updates.append({"node": path, "property": name, "old": old.hex(), "new": new.hex()})
    def update_node(path, new_name):
        offset, original = nodes[path]
        replacement = new_name.encode("ascii")
        if len(original) != len(replacement):
            raise ValueError("Derived FDT node name must retain its allocation")
        modified[offset:offset + len(original)] = replacement
    update_property("/memory", "reg", struct.pack(">QQQQ", 0x80000000, 0x400000, 0x1bb000000, 0x5000000),
                    struct.pack(">QQQQ", 0x80000000, 0x400000, 0x17b000000, 0x5000000))
    for old_path, new_name, old_base, new_base, size in (
        ("/reserved-memory/simplefb_reserved@1bb000000", "simplefb_reserved@17b000000", 0x1bb000000, 0x17b000000, 0x800000),
        ("/reserved-memory/drm2kgsl_host@1bb800000", "drm2kgsl_host@17b800000", 0x1bb800000, 0x17b800000, 0x4000000),
        ("/reserved-memory/media_host@1bf800000", "media_host@17f800000", 0x1bf800000, 0x17f800000, 0x800000),
        ("/framebuffer@1bb000000", "framebuffer@17b000000", 0x1bb000000, 0x17b000000, 0x800000),
    ):
        update_property(old_path, "reg", struct.pack(">QQ", old_base, size), struct.pack(">QQ", new_base, size))
        update_node(old_path, new_name)
    pci_path, before, after, _, _ = require_4g_pci_ranges(blob, runtime_blob)
    update_property(pci_path, "ranges", before, after)
    fdt_offsets(modified)
    return bytes(modified), updates


def patch_adt_4g(blob, source_fdt, runtime_fdt):
    properties = adt_properties(blob)
    if len([path for path in properties if path.startswith("/cpus/cpu")]) != 8:
        raise ValueError("Existing ADT is not the fixed eight-CPU profile")
    if properties["/chosen"]["dram-base"][1] != struct.pack("<Q", 0x80600000) or properties["/chosen"]["darwinboot-memory-size"][1] != struct.pack("<Q", 0x30000000):
        raise ValueError("Existing ADT RAM base or owned boot window differs")
    if "darwinboot-video-memory" in properties["/chosen"] or "darwinboot-fdt" in properties["/chosen"]:
        raise ValueError("This patch applies only to the fixed macOS profile without a separate boot-video reservation")
    if properties["/arm-io"]["ranges"][1] != struct.pack("<QQQ", 0, ARMIO_BASE, 0x40000000 - ARMIO_BASE):
        raise ValueError("Original ADT arm-io parent mapping differs from the PCI conversion owner")
    _, _, _, old_pci, new_pci = require_4g_pci_ranges(source_fdt, runtime_fdt)
    changes = [
        ("/chosen", "dram-size", struct.pack("<Q", 0x13aa00000), struct.pack("<Q", 0xfaa00000)),
        ("/chosen", "darwinboot-memory-limit", struct.pack("<Q", 0x1bae00000), struct.pack("<Q", 0x17ae00000)),
        ("/pram", "reg", struct.pack("<QQ", 0x1baf80000, 0x80000), struct.pack("<QQ", 0x17af80000, 0x80000)),
        ("/defaults", "kern.maxvnodes", struct.pack("<I", 0x13e80), struct.pack("<I", 0xfe80)),
        ("/arm-io/virtio-gpu", "drm-host-pool", struct.pack("<QQ", 0x1bb800000, 0x4000000), struct.pack("<QQ", 0x17b800000, 0x4000000)),
        ("/arm-io/virtio-media-0", "media-host-pool", struct.pack("<QQ", 0x1bf800000, 0x800000), struct.pack("<QQ", 0x17f800000, 0x800000)),
        ("/arm-io/virtio-media-1", "media-host-pool", struct.pack("<QQ", 0x1bf800000, 0x800000), struct.pack("<QQ", 0x17f800000, 0x800000)),
        ("/arm-io/pcie", "ranges", adt_pci_ranges(old_pci), adt_pci_ranges(new_pci)),
    ]
    modified = bytearray(blob)
    rows = []
    allowed = set()
    for path, name, old, new in changes:
        offset, original = properties[path][name]
        if original != old or len(old) != len(new):
            raise ValueError("Existing ADT property differs from the fixed source profile")
        modified[offset:offset + len(new)] = new
        rows.append({"node": path, "property": name, "old": shown(old), "new": shown(new), "adt_byte_offset": offset})
        allowed.add((path, name))
    changed_properties = []
    after = adt_properties(modified)
    if after.keys() != properties.keys():
        raise ValueError("ADT node coverage changed")
    for path, props in properties.items():
        if props.keys() != after[path].keys():
            raise ValueError("ADT property coverage changed")
        for name, (_, old) in props.items():
            if old != after[path][name][1]:
                changed_properties.append((path, name))
    if set(changed_properties) != allowed:
        raise ValueError("An unlisted ADT property changed")
    return bytes(modified), rows


def require_captured_profile(vm_config, vm_id):
    data = json.loads(vm_config.read_text(encoding="utf-8"))
    rows = data.get("vms", []) if isinstance(data, dict) else data
    selected = [row for row in rows if row.get("id") == vm_id]
    if len(selected) != 1:
        raise ValueError("Captured macOS VM ID is absent or ambiguous")
    vm = selected[0]
    if not (vm.get("memory_mb") == 4096 and vm.get("cpu_count") == 8
            and vm.get("backend") == "crosvm" and vm.get("hypervisor") == "gunyah"
            and vm.get("protected_vm") == "pseudo_unprotected" and vm.get("hugepages") is True):
        raise ValueError("Captured VM must retain the full eight-CPU Gunyah 4 GiB profile")
    options = vm.get("extra_options", [])
    required = {"--mbi-spis", "--virtio-mmio-gpu", "--virtio-mmio-snd", "--virtio-mmio-media"}
    if not required.issubset(options):
        raise ValueError("Captured VM is missing the fixed full-profile devices")
    if options[options.index("--mbi-spis") + 1] != "64":
        raise ValueError("Captured MSI frame differs from the fixed profile")
    if vm.get("cpu_topology_auto") is not False or vm.get("cpu_clusters") != "0-5;6-7" or vm.get("cpu_capacity") != "0=792,1=792,2=792,3=792,4=792,5=792,6=1024,7=1024":
        raise ValueError("Captured eight-CPU topology differs from the retained E/E/E/E/E/E/P/P tree")
    fb = vm.get("screens", {}).get("simplefb", {})
    if not (fb.get("enabled") is True and fb.get("width") == 1920 and fb.get("height") == 1080
            and vm.get("gpu_drm2kgsl_pool_mb") == 64):
        raise ValueError("Captured framebuffer geometry or DRM pool differs from this adaptation")
    return vm


def build(source, output, layout_log, vm_config, vm_id, runtime_fdt):
    output.mkdir(parents=True, exist_ok=True)
    target = output / "boot-macos-27.2-4096MiB.img"
    report_path = output / "boot-adaptation-report.json"
    if target.exists() or report_path.exists():
        raise FileExistsError("Preserve the existing adapted image and report")
    vm = require_captured_profile(vm_config, vm_id)
    text = layout_log.read_text(encoding="utf-8")
    required_log_markers = (
        "drm2kgsl_host pool 0x17b800000..0x17f800000",
        "media_host pool 0x17f800000..0x180000000",
        "GH-SHIM: window gpa=0x80600000 size=0xfaa00000",
        "at gpa=0x17b000000",
    )
    if not all(marker in text for marker in required_log_markers):
        raise ValueError("Captured log does not establish the selected 4 GiB framebuffer/RAM/pool layout")
    source_fdt = FDT_SOURCE.read_bytes()
    if hashlib.sha256(source_fdt).hexdigest() != FDT_SOURCE_SHA256:
        raise ValueError("The pinned five-GiB source FDT changed")
    runtime_blob = runtime_fdt.read_bytes()
    derived_fdt, fdt_changes = derived_fdt_4g(source_fdt, runtime_blob)
    if layout_facts(derived_fdt) != layout_facts(runtime_blob):
        raise ValueError("Captured runtime FDT differs from the complete adapted hardware layout")
    source_fat = Fat32(source)
    try:
        original_adt = source_fat.read(ADT_PATH)
        patched_adt, adt_changes = patch_adt_4g(original_adt, source_fdt, runtime_blob)
        source_members = {path: {"bytes": member.size, "sha256": source_fat.member_digest(member)}
                          for path, member in source_fat.members.items()}
        original_image_digest = hashlib.sha256()
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            while chunk := incoming.read(8 * 1024 * 1024):
                original_image_digest.update(chunk)
                outgoing.write(chunk)
        if original_image_digest.hexdigest() != SOURCE_SHA256:
            raise ValueError("Source boot disk differs from the verified pinned image; preserve the new copy for diagnosis")
    finally:
        source_fat.close()
    copied_fat = Fat32(target)
    try:
        copied_fat.replace_same_length(ADT_PATH, patched_adt)
    finally:
        copied_fat.close()
    final_fat = Fat32(target)
    try:
        final_members = {path: {"bytes": member.size, "sha256": final_fat.member_digest(member)}
                         for path, member in final_fat.members.items()}
        if final_members.keys() != source_members.keys():
            raise ValueError("Adapted FAT member coverage differs from the original")
        unchanged = []
        for path, before in source_members.items():
            if path != ADT_PATH:
                if final_members[path] != before:
                    raise ValueError("A retained kernel, trust, seed, loader or command-line member changed")
                unchanged.append(path)
        if final_fat.read(ADT_PATH) != patched_adt:
            raise ValueError("Adapted ADT bytes did not round-trip through the FAT32 file")
    finally:
        final_fat.close()
    # Confirm every changed image byte lies in the existing ADT's cluster allocation.
    old_fat = Fat32(source)
    member = old_fat.members[ADT_PATH]
    allowed_extents = [(old_fat.offset(cluster), old_fat.offset(cluster) + old_fat.cluster_bytes)
                       for cluster in old_fat.chain(member.cluster)]
    old_fat.close()
    outside_changes = []
    with source.open("rb") as original, target.open("rb") as modified:
        offset = 0
        while before := original.read(8 * 1024 * 1024):
            after = modified.read(len(before))
            if len(before) != len(after):
                raise ValueError("Adapted image size differs")
            if before != after:
                for index, (a, b) in enumerate(zip(before, after)):
                    if a != b and not any(start <= offset + index < end for start, end in allowed_extents):
                        outside_changes.append(offset + index)
            offset += len(before)
        if modified.read(1) or outside_changes:
            raise ValueError("Image bytes changed outside the original ADT allocation")
    (output / "kernel.macho-4096.adt").write_bytes(patched_adt)
    (output / "k27-generated-4096-derived.dtb").write_bytes(derived_fdt)
    report = {"operation": "adapted_existing_macOS_FAT32_boot_to_4096MiB", "ok": True,
              "created_at_utc": datetime.now(timezone.utc).isoformat(), "source": str(source),
              "source_sha256": SOURCE_SHA256, "output": str(target), "output_sha256": sha256(target),
              "output_bytes": target.stat().st_size, "memory_mb": 4096, "cpu_count": 8, "profile": "full",
              "captured_vm_id": vm["id"], "captured_config": str(vm_config), "captured_config_sha256": sha256(vm_config),
              "layout_basis": "captured 4096MiB crosvm RAM/framebuffer/pool log plus the pinned fixed-layout source FDT and ADT",
              "layout_log": str(layout_log), "layout_log_sha256": sha256(layout_log),
              "runtime_fdt": str(runtime_fdt), "runtime_fdt_sha256": sha256(runtime_fdt),
              "source_fdt_sha256": FDT_SOURCE_SHA256, "derived_fdt_sha256": hashlib.sha256(derived_fdt).hexdigest(),
              "derived_fdt_status": "derived profile model; not an observed runtime dump and not placed in the boot disk",
              "adt_changes": adt_changes, "derived_fdt_changes": fdt_changes,
              "pci_conversion": {"source": "sources/macOS-DroidVM/scripts/run-macos-vm.py make_adt MACOS_PCIE=1",
                                 "arm_io_base": hex(ARMIO_BASE), "encoding": "FDT >7I cells to ADT <IQQQ; parent = CPU address - ARMIO_BASE",
                                 "source_high_pci_and_cpu_base": "0x1c0800000", "source_high_size": "0x15f800000",
                                 "captured_high_pci_and_cpu_base": "0x180800000", "captured_high_size": "0x19f800000",
                                 "adt_high_parent_address": "0x1807ff000"},
              "members_before": source_members, "members_after": final_members,
              "unchanged_members": unchanged, "only_original_adt_allocation_modified": True,
              "adt_properties_unchanged_except_listed_eight": len(adt_changes) == 8,
              "original_kernel_commands_preserved": True, "original_identity_seed_and_trust_preserved": True,
              "framebuffer_adt_field": "no fixed framebuffer address property in this ADT; firmware fills boot_args Video from actual GOP",
              "original_boot_source_modified": False, "data_store_opened_or_modified": False, "phone_operated": False,
              "fresh_runtime_fdt_cross_check": "passed against the caller-supplied captured runtime FDT before image creation",
              "guest_boot_or_desktop_verified": False}
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def layout_facts(blob):
    _, nodes = fdt_offsets(blob)
    selected = {}
    for path, properties in nodes.items():
        values = {name: value for name, (_, value) in properties.items()}
        compatible = values.get("compatible", b"")
        role = None
        keys = ("reg", "compatible")
        if values.get("device_type", b"").rstrip(b"\0") == b"memory":
            role, keys = "memory", ("reg",)
        elif path.startswith("/cpus/cpu@"):
            role, keys = path, ("reg", "capacity-dmips-mhz")
        elif path.startswith("/reserved-memory/") and any(label in path for label in ("simplefb_reserved@", "drm2kgsl_host@", "media_host@")):
            role = path.split("@", 1)[0]
        elif compatible.startswith(b"simple-framebuffer"):
            role, keys = "framebuffer", ("reg", "width", "height", "stride", "format")
        elif compatible.startswith(b"virtio,mmio"):
            role, keys = path, ("reg", "interrupts")
        elif b"pci-host-ecam-generic" in compatible:
            role, keys = path, ("reg", "ranges", "interrupt-map")
        elif b"gic" in compatible:
            role, keys = path, ("reg", "mbi-alias", "mbi-ranges")
        if role is not None:
            selected[role] = {key: values[key].hex() for key in keys if key in values}
    return selected


def cross_check_fdt(path, output):
    expected_path = output / "k27-generated-4096-derived.dtb"
    expected = layout_facts(expected_path.read_bytes())
    actual = layout_facts(path.read_bytes())
    if actual != expected:
        differing = sorted(key for key in actual.keys() | expected.keys() if actual.get(key) != expected.get(key))
        raise ValueError("Fresh FDT differs in these hardware-layout facts: " + ", ".join(differing))
    report = {"operation": "checked_caller_supplied_runtime_FDT_against_4096MiB_profile", "ok": True,
              "checked_at_utc": datetime.now(timezone.utc).isoformat(), "input": str(path), "input_sha256": sha256(path),
              "expected_model": str(expected_path), "expected_model_sha256": sha256(expected_path),
              "coverage": "RAM regions, framebuffer geometry, reserved host pools, eight CPU reg/capacity values, PCI/GIC/MSI and virtio-MMIO reg/interrupt facts",
              "facts": actual, "phone_capture_performed_by_this_tool": False, "guest_boot_or_desktop_verified": False}
    target = output / "runtime-fdt-cross-check.json"
    if target.exists():
        raise FileExistsError("Preserve the existing runtime FDT observation")
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--layout-log", type=Path)
    parser.add_argument("--vm-config", type=Path)
    parser.add_argument("--vm-id")
    parser.add_argument("--check-runtime-fdt", type=Path)
    parser.add_argument("--runtime-fdt", type=Path, default=FDT_RUNTIME,
                        help="actual captured 4096MiB FDT used to bind the PCI aperture")
    args = parser.parse_args()
    if args.check_runtime_fdt:
        record = cross_check_fdt(args.check_runtime_fdt.resolve(strict=True), args.output.resolve())
        print(json.dumps({"ok": True, "input": record["input"], "input_sha256": record["input_sha256"],
                          "coverage": record["coverage"], "guest_boot_or_desktop_verified": False}, ensure_ascii=True))
    elif args.inspect:
        record = inspect(args.source.resolve(strict=True), args.output.resolve())
        print(json.dumps({"ok": True, "source": record["source"], "members": record["members"],
                          "adt_sha256": record["adt_sha256"], "output": str(args.output.resolve())}, ensure_ascii=True))
    else:
        if not args.layout_log or not args.vm_config or not args.vm_id:
            parser.error("--layout-log, --vm-config and --vm-id from the actual 4096MiB VM are required")
        record = build(args.source.resolve(strict=True), args.output.resolve(),
                       args.layout_log.resolve(strict=True), args.vm_config.resolve(strict=True), args.vm_id,
                       args.runtime_fdt.resolve(strict=True))
        print(json.dumps({"ok": True, "output": record["output"], "sha256": record["output_sha256"],
                          "bytes": record["output_bytes"], "adt_changed_properties": len(record["adt_changes"]),
                          "unchanged_fat_members": len(record["unchanged_members"]),
                          "fresh_runtime_fdt_cross_check": record["fresh_runtime_fdt_cross_check"]}, ensure_ascii=True))


if __name__ == "__main__":
    main()
