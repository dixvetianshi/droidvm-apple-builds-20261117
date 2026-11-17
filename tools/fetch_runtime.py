#!/usr/bin/env python3
"""Download and verify the pinned public Android runtime without installing it."""
import argparse
import hashlib
import json
import re
import shutil
import struct
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

PIN = "4253f07b11f6d33e2010303a3c17c16e73ea29a2"
BASE = f"https://raw.githubusercontent.com/Droid-VM/DroidVM-Prebuilts/{PIN}/"
ARCHIVE = "prebuilt-arm64-v8a.tar.xz"
MANIFEST = "prebuilt-arm64-v8a.json"
ARCHIVE_BYTES = 75732820
FLAG_NAMES = (
    "virtio-mmio-block", "virtio-mmio-input", "virtio-mmio-net",
    "virtio-mmio-gpu", "virtio-mmio-snd", "virtio-mmio-media",
    "extended-status", "protected-vm-pseudo-unprotected", "hugepages",
)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def selected(name):
    p = PurePosixPath(name)
    return name == "usr/bin/crosvm" or (
        p.parent == PurePosixPath("usr/lib") and p.suffix == ".so"
    ) or name in {
        "usr/share/droidvm/edk2-gunyah.fd",
        "usr/share/droidvm/edk2-gunyah.vars.fd",
    }


def inspect_embedded_flags(path):
    flags = tuple(name.encode("ascii") for name in FLAG_NAMES)
    observations = {name: False for name in FLAG_NAMES}
    tail = b""
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            data = tail + part
            for flag in flags:
                observations[flag.decode()] |= flag in data
            tail = data[-128:]
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = []
    for name in (MANIFEST, ARCHIVE):
        request = urllib.request.Request(BASE + name, headers={"User-Agent": "DroidVMAppleBuild"})
        path = out / name
        print(f"Downloading {name}", flush=True)
        with urllib.request.urlopen(request, timeout=60) as response, path.open("xb") as stream:
            shutil.copyfileobj(response, stream, 4 * 1024 * 1024)
        sources.append({"url": BASE + name, "file": name, "bytes": path.stat().st_size, "sha256": digest(path)})
    if (out / ARCHIVE).stat().st_size != ARCHIVE_BYTES:
        raise SystemExit("The pinned archive byte count differs from the observed upstream object")
    record = json.loads((out / MANIFEST).read_text(encoding="utf8"))
    hashes = {}
    for row in record["hash"]:
        name = row["file"]
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts or str(p) != name or name in hashes:
            raise SystemExit(f"Invalid or repeated manifest path: {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise SystemExit(f"Invalid manifest digest: {name}")
        hashes[name] = row["sha256"]
    wanted = {name: sha for name, sha in hashes.items() if selected(name)}
    if "usr/bin/crosvm" not in wanted or "usr/share/droidvm/edk2-gunyah.fd" not in wanted:
        raise SystemExit("The pinned manifest lacks the required runtime")
    verified = {}
    staged = out / "verified"
    staged.mkdir()
    with tarfile.open(out / ARCHIVE, mode="r|xz") as archive:
        for member in archive:
            name = str(PurePosixPath(member.name))
            if name not in wanted:
                continue
            if name in verified or not member.isfile():
                raise SystemExit(f"Runtime archive member is repeated or not a regular file: {name}")
            target = staged.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            source = archive.extractfile(member)
            with source, target.open("xb") as stream:
                for part in iter(lambda: source.read(4 * 1024 * 1024), b""):
                    h.update(part)
                    stream.write(part)
            if h.hexdigest() != wanted[name]:
                raise SystemExit(f"Upstream runtime digest mismatch: {name}")
            target.chmod(member.mode & 0o777)
            verified[name] = {"sha256": h.hexdigest(), "bytes": target.stat().st_size}
    missing = sorted(wanted.keys() - verified.keys())
    if missing:
        raise SystemExit(f"The archive lacks selected manifest members: {missing}")
    crosvm = staged / "usr/bin/crosvm"
    with crosvm.open("rb") as stream:
        head = stream.read(20)
    if head[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", head, 18)[0] != 183:
        raise SystemExit("The supplied crosvm is not an ELF64 little-endian AArch64 executable")
    observations = inspect_embedded_flags(crosvm)
    result = {
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_repository": "https://github.com/Droid-VM/DroidVM-Prebuilts",
        "source_commit": PIN,
        "sources": sources,
        "verified_files": verified,
        "crosvm_elf_machine": "AArch64 (183)",
        "crosvm_embedded_flag_names": observations,
        "archive_whole_sha256_is_locally_computed": True,
        "installed_on_phone": False,
        "runtime_help_verified": False,
        "phone_boot_verified": False,
        "limitations": ["The archive has no publisher-provided whole-file SHA-256; selected members were verified against the manifest from the same pinned commit.", "Embedded flag names are static observations; Android loading and guest boot still require device verification.", "Host kernel modules and the DroidVM APK are not included in the staged runtime."],
    }
    (out / "runtime-provenance.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")
    print(json.dumps({"source_commit": PIN, "selected_files_verified": len(verified), "crosvm_embedded_flag_names": observations, "installed_on_phone": False, "phone_boot_verified": False}))


if __name__ == "__main__":
    main()
