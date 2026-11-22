"""Compile a pinned reserve repair; never install it or operate a phone."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import urllib.request

from build_hostshare_component_ci import (
    DDK_CONFIG_SHA, DDK_IMAGE, OwnedCommandTimeout, apply_checked_patch, cleanup_owned_container, run_logged, sha256,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "patches/reserve/late-return-source.json"
PATCH = ROOT / "patches/reserve/retain-late-return.patch"
MODULE = "gh_hugepage_reserve"
BUILD = r'''set -euo pipefail
export PATH=/opt/ddk/clang/clang-r510928/bin:$PATH
K=/opt/ddk/kdir/android15-6.6
test -f "$K/Makefile"
test -f "$K/Module.symvers"
command -v clang make llvm-strip llvm-readelf llvm-nm llvm-objdump
clang --version > /out/compiler.txt
make -s -C "$K" kernelrelease > /out/kernelrelease.txt
sha256sum "$K/Makefile" "$K/Module.symvers" > /out/kbuild-input-checksums.txt
B=$(mktemp -d /tmp/reserve-component.XXXXXX)
cp -a /src/. "$B/"
make -C "$K" -j2 M="$B" ARCH=arm64 LLVM=1 LLVM_IAS=1 modules
test -f "$B/gh_hugepage_reserve.ko"
cp "$B/gh_hugepage_reserve.ko" /out/gh_hugepage_reserve.unstripped.ko
llvm-strip -d "$B/gh_hugepage_reserve.ko"
cp "$B/gh_hugepage_reserve.ko" /out/gh_hugepage_reserve.ko
llvm-readelf -W -h -S -s -r /out/gh_hugepage_reserve.ko > /out/elf-sections-symbols-relocations.txt
llvm-readelf -n /out/gh_hugepage_reserve.ko > /out/elf-notes.txt
llvm-readelf -p .modinfo /out/gh_hugepage_reserve.ko > /out/modinfo.txt
llvm-nm -u /out/gh_hugepage_reserve.ko > /out/imports.txt
llvm-nm -a /out/gh_hugepage_reserve.ko > /out/all-symbols.txt
llvm-objdump -d -r /out/gh_hugepage_reserve.ko > /out/disassembly-relocations.txt
sha256sum /out/gh_hugepage_reserve.ko /out/gh_hugepage_reserve.unstripped.ko > /out/module-checksums.txt
'''


def file_set(rows):
    result = {}
    for row in rows:
        path = row["path"]
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or ".." in parsed.parts or "\\" in path or parsed.as_posix() != path:
            raise RuntimeError("Unsafe source occurrence: " + path)
        if path in result or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) or row["bytes"] < 0:
            raise RuntimeError("Malformed or duplicate source occurrence: " + path)
        result[path] = row
    return result


def require_tree(directory, expected):
    actual = {p.relative_to(directory).as_posix(): p for p in directory.rglob("*") if p.is_file()}
    if set(actual) != set(expected):
        raise RuntimeError("Source tree has missing or unexpected files")
    for path, row in expected.items():
        data = actual[path].read_bytes()
        if len(data) != row["bytes"] or sha256(data) != row["sha256"]:
            raise RuntimeError("Source identity differs: " + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--source-directory", type=Path,
                        help="Use an existing independently verified upstream tree instead of downloading it")
    parser.add_argument("--output", type=Path, default=Path("output/reserve-component"))
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    record = {"status": "preparing", "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "compiled": False, "module_loaded": False, "phone_modified": False,
              "published_release": False, "ddk_image": DDK_IMAGE}
    try:
        manifest_bytes = MANIFEST.read_bytes()
        manifest = json.loads(manifest_bytes)
        if manifest["source_repository"] != "Droid-VM/gh-hugepage-reserve" or \
                manifest["source_commit"] != "00c8a0322aa6fb25593e00352af2764be5317d7e":
            raise RuntimeError("Unreviewed source repository or commit")
        patch_bytes = PATCH.read_bytes()
        if sha256(patch_bytes) != manifest["patch_sha256"]:
            raise RuntimeError("Repair patch identity differs")
        before_set = file_set(manifest["before"])
        after_set = file_set(manifest["after"])
        inputs = out / "inputs"
        before = inputs / "before"
        before.mkdir(parents=True)
        if args.source_directory:
            source = args.source_directory.resolve()
            require_tree(source, before_set)
            for path in before_set:
                target = before / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source / path).read_bytes())
        else:
            for path, row in before_set.items():
                url = "https://raw.githubusercontent.com/" + manifest["source_repository"] + "/" \
                    + manifest["source_commit"] + "/" + path
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(row["bytes"] + 1)
                if len(data) != row["bytes"] or sha256(data) != row["sha256"]:
                    raise RuntimeError("Fetched upstream bytes differ: " + path)
                target = before / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        require_tree(before, before_set)
        (inputs / "late-return-source.json").write_bytes(manifest_bytes)
        retained_patch = inputs / PATCH.name
        retained_patch.write_bytes(patch_bytes)
        candidate = inputs / "candidate"
        shutil.copytree(before, candidate)
        apply_checked_patch(retained_patch, candidate, out)
        require_tree(candidate, after_set)
        (inputs / "container-build.sh").write_text(BUILD, encoding="utf-8")
        record.update(source_repository=manifest["source_repository"], source_commit=manifest["source_commit"],
                      manifest_sha256=sha256(manifest_bytes), patch_sha256=sha256(patch_bytes),
                      candidate_tree_verified=True)
        if args.prepare_only:
            record["status"] = "prepared_only"
        else:
            if sys.platform != "linux" or not shutil.which("docker"):
                raise RuntimeError("An existing Linux Docker runtime is required; this tool installs nothing")
            run_logged(["make", "-C", str(candidate / "tests"), "test"],
                       out / "source-harness.log", timeout=180)
            record["source_harness_completed"] = True
            # The harness builds local executables. Kernel input identity is
            # still the reviewed source set; create a separate clean mount.
            kernel_source = inputs / "kernel-source"
            kernel_source.mkdir()
            for path in after_set:
                target = kernel_source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((candidate / path).read_bytes())
            require_tree(kernel_source, after_set)
            run_logged(["docker", "pull", DDK_IMAGE], out / "docker-pull.log", timeout=600)
            inspected = subprocess.run(["docker", "image", "inspect", DDK_IMAGE],
                                       capture_output=True, check=True, timeout=30)
            (out / "docker-image-inspect.json").write_bytes(inspected.stdout)
            image = json.loads(inspected.stdout)[0]
            if image["Id"] != DDK_CONFIG_SHA or DDK_IMAGE not in image["RepoDigests"] or \
                    image["Os"] != "linux" or image["Architecture"] != "amd64" or \
                    image["Config"].get("Entrypoint") is not None:
                raise RuntimeError("Docker toolchain identity or platform differs")
            component = out / "component"
            component.mkdir()
            cidfile = out / "owned-build-container.cid"
            command = ["docker", "run", "--rm", "--cidfile", str(cidfile), "--network=none", "--cpus=2", "--memory=2g",
                       "--mount", f"type=bind,source={kernel_source},target=/src,readonly",
                       "--mount", f"type=bind,source={component},target=/out",
                       DDK_IMAGE, "/bin/bash", "-lc", BUILD]
            (out / "docker-build-command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
            try:
                run_logged(command, out / "module-build.log", timeout=600)
                record["compiled"] = True
            finally:
                record["owned_container_cleanup_complete"] = cleanup_owned_container(cidfile, out / "container-cleanup.log")
            if not record["owned_container_cleanup_complete"]:
                raise RuntimeError("Owned container cleanup is unknown or incomplete")
            module = component / (MODULE + ".ko")
            binary = module.read_bytes()
            elf = (component / "elf-sections-symbols-relocations.txt").read_text()
            modinfo = (component / "modinfo.txt").read_text()
            if not re.search(r"Machine:\s+AArch64\b", elf) or not re.search(r"Type:\s+REL\b", elf) or \
                    "name=gh_hugepage_reserve" not in modinfo:
                raise RuntimeError("Compiled module machine, type or name differs")
            record.update(status="built_and_static_verified", module_sha256=sha256(binary), module_bytes=len(binary),
                          runtime_compatibility="Not tested; this tool never loads or installs a module")
    except Exception as error:
        record.update(status="failed", failure=str(error))
        if isinstance(error, OwnedCommandTimeout):
            record["owned_process_group_cleanup_complete"] = error.cleanup_complete
    finally:
        record["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        record["retained_files"] = [] if record.get("owned_process_group_cleanup_complete") is False else [{"path": p.relative_to(out).as_posix(), "sha256": sha256(p.read_bytes()),
                                    "bytes": p.stat().st_size}
                                   for p in sorted(out.rglob("*")) if p.is_file()]
        (out / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: record.get(k) for k in ("status", "failure", "compiled", "module_sha256", "module_bytes")}, indent=2))
    return 0 if record["status"] in ("prepared_only", "built_and_static_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
