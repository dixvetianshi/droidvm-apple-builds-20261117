#!/usr/bin/env python3
"""Verify the pinned PSCI source and its compiled path into the kernel collection."""
import argparse
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
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


def defined_address(path):
    rows = command("llvm-nm", "--defined-only", "--no-sort", str(path)).splitlines()
    matches = [row.split() for row in rows if row.split() and row.split()[-1] == SYMBOL]
    require(len(matches) == 1 and matches[0][-2].upper() == "T", f"missing unique compiled method: {path}")
    return int(matches[0][0], 16)


def build_record(root):
    record = source_record(root)
    platform = root / "out/x12377/un/build/platform-12377-arm64e/ArmDTPlatform/ArmDTPlatform.cpp"
    require(sha256(platform) == PLATFORM_SHA256, "compiled platform source differs from reviewed patch")
    obj = root / "out/x12377/native-kexts/ArmDTPlatform/ArmDTPlatform.o"
    defined_address(obj)
    kernel = root / "out/k27/kernel-k27.macho"
    address = defined_address(kernel)
    collection = root / "out/k27/kc-k27.bin"
    require(0 < collection.stat().st_size <= 512 * 1024 * 1024,
            "KC exceeds the pinned patched DarwinBoot kernel read limit")
    spec = importlib.util.spec_from_file_location("fileset_kc", root / "scripts/fileset_kc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with collection.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        kc = module.Kernelcache(data)
        symbols = kc.symbols(kc.macho("com.apple.kernel"))
        defined = [(name, value) for name, kind, _, _, value in symbols if kind & 0x0E == 0x0E and not kind & 0xE0]
        found = [value for name, value in defined if name == SYMBOL]
        require(found == [address], "PSCI method was not preserved at the linked kernel address")
        following = [value for _, value in defined if value > address]
        require(bool(following), "cannot establish compiled method extent")
        length = min(following) - address
        code = data[kc.file_offset(address, length):kc.file_offset(address, length) + length]
        instructions = [code[at:at + 4] for at in range(0, len(code), 4)]
        require(bytes.fromhex("020000d4") in instructions, "compiled SYSTEM_OFF/RESET path lacks HVC")
        require(bytes.fromhex("030000d4") in instructions, "compiled explicit SMC path is missing")
    record.update({
        "platform_source_sha256": PLATFORM_SHA256,
        "compiled_method": SYMBOL,
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
    args = parser.parse_args()
    root = args.root.resolve()
    record = source_record(root) if args.source_only else build_record(root)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
