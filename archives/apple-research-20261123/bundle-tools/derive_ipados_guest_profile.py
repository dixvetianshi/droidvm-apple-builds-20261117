"""Derive this guest's monitor addresses from its actual native/fileset images.

Native symbols move by their segment's placement, as fileset-syms.py records.
The caller must subsequently verify the explicit physical base against the
fresh DarwinBoot handoff. This local tool does not access or operate a phone.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import uuid


def header(data, offset=0):
    if offset < 0 or offset + 32 > len(data):
        raise ValueError("Incomplete Mach-O header")
    magic, cpu, sub, kind, count, size, flags, _ = struct.unpack_from("<8I", data, offset)
    end = offset + 32 + size
    if magic != 0xfeedfacf or cpu != 0x100000c or end > len(data):
        raise ValueError("Use complete ARM64 Mach-O bytes")
    result = {"segments": {}, "entries": {}, "uuid": None, "symtab": None, "kind": kind}
    at = offset + 32
    for _ in range(count):
        cmd, length = struct.unpack_from("<II", data, at)
        if length < 8 or at + length > end:
            raise ValueError("Invalid Mach-O load-command extent")
        if cmd == 0x19:
            name = data[at + 8:at + 24].split(b"\0")[0].decode()
            va, vs, fo, fs = struct.unpack_from("<4Q", data, at + 24)
            if name in result["segments"] or fo + fs > len(data):
                raise ValueError("Duplicate or unbacked Mach-O segment")
            result["segments"][name] = {"va": va, "size": vs, "fileoff": fo, "filesize": fs}
        elif cmd == 0x80000035:
            va, fo, no = struct.unpack_from("<QQI", data, at + 8)
            if not 32 <= no < length:
                raise ValueError("Incomplete fileset entry name")
            name = data[at + no:data.index(0, at + no, at + length)].decode()
            if name in result["entries"]:
                raise ValueError("Duplicate fileset entry")
            result["entries"][name] = {"va": va, "fileoff": fo}
        elif cmd == 0x1b:
            if result["uuid"] is not None or length != 24:
                raise ValueError("Duplicate or incomplete image UUID")
            result["uuid"] = {"uuid": str(uuid.UUID(bytes=data[at + 8:at + 24])),
                              "fileoff": at + 8}
        elif cmd == 2:
            result["symtab"] = struct.unpack_from("<4I", data, at + 8)
        at += length
    if at != end:
        raise ValueError("Load commands do not cover their declared extent")
    return result


def symbols(data, image):
    start, count, strings, size = image["symtab"]
    if start + 16 * count > len(data) or strings + size > len(data):
        raise ValueError("Native symbol table is truncated")
    result = {}
    for index in range(count):
        key, typ, sect, _, value = struct.unpack_from("<IBBHQ", data, start + 16 * index)
        if typ & 0xe != 0xe or not sect:
            continue
        if key >= size:
            raise ValueError("Native symbol string is outside its table")
        name = data[strings + key:data.index(0, strings + key, strings + size)].decode()
        segment = [s for s in image["segments"].values() if s["va"] <= value < s["va"] + s["size"]]
        if name in result or len(segment) != 1:
            # Multiple unrelated absolute/link-edit symbols are not monitor facts.
            if name.startswith(("_droidvm_export_", "_memstat_set_memlimits_locked.floor_")):
                raise ValueError("A required native symbol has ambiguous ownership")
            continue
        result[name] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--kexts", required=True, type=Path)
    parser.add_argument("--physical-base", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Preserve the earlier derived identity profile")
    data, native, kext_bytes = (p.read_bytes() for p in (args.kernel, args.native, args.kexts))
    root = header(data)
    if root["kind"] != 12:
        raise ValueError("Select an MH_FILESET kernel")
    entry = root["entries"]["com.apple.kernel"]
    placed, original = header(data, entry["fileoff"]), header(native)
    if not placed["uuid"] or not original["uuid"] or placed["uuid"]["uuid"] != original["uuid"]["uuid"]:
        raise ValueError("The native image does not match the fileset's embedded kernel identity")
    base = root["segments"]["__TEXT"]["va"]
    def pa(va):
        return args.physical_base + va - base
    def file_va(off):
        hits = [s for s in root["segments"].values()
                if s["fileoff"] <= off and off + 16 <= s["fileoff"] + s["filesize"]]
        if len(hits) != 1:
            raise ValueError("An identity UUID has no unique file-to-VA mapping")
        return hits[0]["va"] + off - hits[0]["fileoff"]
    checks = [{"label": "fileset", "physical_address": pa(file_va(root["uuid"]["fileoff"])),
               "uuid": root["uuid"]["uuid"]},
              {"label": "kernel", "physical_address": pa(file_va(placed["uuid"]["fileoff"])),
               "uuid": placed["uuid"]["uuid"]}]
    kexts = json.loads(kext_bytes)["kexts"]
    for bundle in ("com.droidvm.driver.DroidVMGpu", "com.droidvm.driver.DroidVMInput"):
        # The display bundle is called DroidVMGraphics in some producer revisions.
        candidates = [e for n, e in root["entries"].items()
                      if n == bundle or (bundle.endswith("Gpu") and n.endswith("DroidVMGraphics"))]
        if len(candidates) != 1:
            raise ValueError("Select the actual graphics/input fileset entry")
        h = header(data, candidates[0]["fileoff"])
        checks.append({"label": bundle, "physical_address": pa(file_va(h["uuid"]["fileoff"])),
                       "uuid": h["uuid"]["uuid"]})
    needed = ("_droidvm_export_box", "_droidvm_export_data_pa", "_droidvm_export_data_bytes",
              "_memstat_set_memlimits_locked.floor_read", "_memstat_set_memlimits_locked.floor_enabled")
    found, addresses = symbols(native, original), {}
    for name in needed:
        if name not in found:
            continue
        value = found[name]
        segment_name = next(n for n, s in original["segments"].items() if s["va"] <= value < s["va"] + s["size"])
        value += placed["segments"][segment_name]["va"] - original["segments"][segment_name]["va"]
        addresses[name] = pa(value)
    for row in kexts:
        for name, value in row["symbols"].items():
            if name.startswith(("_native_hid_input_", "_native_virtio_", "_native_legacy_", "_native_touch_")):
                addresses[name] = pa(int(value, 16))
    report = {"schema": "org.droidvm.ipados.guest-profile.v1",
              "inputs": {name: {"path": str(p.resolve()), "sha256": hashlib.sha256(body).hexdigest()}
                         for name, p, body in zip(("kernel", "native", "kexts"), (args.kernel, args.native, args.kexts),
                                                 (data, native, kext_bytes))},
              "handoff": {"virtual_base": base, "physical_base": args.physical_base,
                          "fresh_runtime_handoff_verification_required": True},
              "uuid_checks": checks, "physical_symbols": addresses,
              "method": "Actual nlist N_SECT → owning native segment → placed kernel segment; actual fileset UUID offsets",
              "phone_operated": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    print(json.dumps({"profile": str(args.output), "uuid_checks": checks,
                      "monitor_addresses": {n: hex(addresses[n]) for n in needed if n in addresses}}))


if __name__ == "__main__":
    main()
