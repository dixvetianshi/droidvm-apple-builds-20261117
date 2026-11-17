#!/usr/bin/env python3
"""Stage a completed upstream release; do not fabricate an OS or imply boot verification."""
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            value.update(part)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.build_root.resolve(strict=True)
    work = root / "droidvm/ipados-27.0.1-24A446/droidvm_ipados27"
    release = work / "release"
    record = json.loads((release / "release.json").read_text(encoding="utf-8"))
    for name in ("droidvm-disk.img", "os.img", "systemos.img"):
        path = release / name
        expected = record.get("files", {}).get(name)
        if not expected or not path.is_file() or path.stat().st_size <= 0:
            raise SystemExit(f"A complete upstream release is required: {name}")
        if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
            raise SystemExit(f"The upstream release digest does not match: {name}")
    if args.output.exists():
        raise SystemExit("Refusing to overwrite an existing staging directory")
    args.output.mkdir(parents=True)
    # APFS copy-on-write clones preserve sparse files on the macOS runner.
    subprocess.run(["cp", "-cR", str(release), str(args.output / "release")], check=True)

    data = work / "tree/build/droidvm-data-24A446"
    seed_record = json.loads((data / "seed.json").read_text(encoding="utf-8"))
    seed = data / seed_record["seed"]
    if digest(seed) != seed_record["seed_sha256"]:
        raise SystemExit("The Data seed does not match its generation record")
    generation = args.output / "generation"
    generation.mkdir()
    shutil.copyfile(data / "seed.json", generation / "seed.json")
    subprocess.run(["cp", "-c", str(seed), str(generation / seed.name)], check=True)
    trust = work / "tree/build/owner-trust-extra"
    if trust.is_dir():
        shutil.copytree(trust, generation / "trust")

    store = args.output / "release/data-store.img"
    with store.open("xb") as stream:
        stream.truncate(16 * 1024**3)
        stream.write((b"DroidVMDataStore" + struct.pack("<I", 1)).ljust(4096, b"\0"))
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "sources/UniXNU-droidvm/tools/rig/unixnu-vm.template.json",
        args.output / "upstream-vm-template.json",
    )
    result = {
        "os": "iPadOS 27.0.1 / 24A446",
        "upstream_release": record,
        "data_store_bytes": store.stat().st_size,
        "data_store_label": "DroidVMDataStore, version 1",
        "requires_matching_edk2_and_crosvm": True,
        "vmpkg_created": False,
        "phone_boot_verified": False,
        "next_step": "Combine the completed disks with compatible runtime components, then create and verify a vmpkg.",
    }
    (args.output / "build-result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"os": result["os"], "upstream_file_digests_verified": True,
                      "phone_boot_verified": False, "vmpkg_created": False}))


if __name__ == "__main__":
    main()
