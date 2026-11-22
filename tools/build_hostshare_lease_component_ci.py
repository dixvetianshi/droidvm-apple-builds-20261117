"""Test and compile one pinned HostShare lease candidate without installing it."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

from build_hostshare_component_ci import (
    BUILD_SH_SHA, CANDIDATE_SHA as CLEAN_V3_SHA, DDK_CONFIG_SHA, DDK_IMAGE,
    HEADER_SHA, MODULE, OwnedCommandTimeout, PATCH_SHA as CLEAN_V3_PATCH_SHA,
    SOURCE_COMMIT, SOURCE_PATH, SOURCE_REPO, SOURCE_SHA,
    apply_checked_patch, cleanup_owned_container, fetch_source, run_logged, sha256,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "patches/hostshare/lease-source-manifest.json"
MANIFEST_SHA = "3126f84cc32989db28ded2a61bf386f2c9cf437cf331556553e38aa7e263daf9"
CLEAN_PATCH = ROOT / "patches/hostshare/remove-unused-debugfs-probe.patch"
LEASE_PATCH = ROOT / "patches/hostshare/hostshare-lease.patch"
LEASE_PATCH_SHA = "d8ee4c2c95bf137380e2eb052a4be527b4617e68b202949810809867e31a5098"
LEASE_PATCH_BYTES = 70196
UAPI_SHA = "b2f34317da73b49867263bd664c969be1ce74bd33dad693a13ddaeb615c07a48"
BUNDLED_SOURCE = ROOT / "patches/hostshare/lease-source"
FORBIDDEN_PROBE = ("gh_share_probe", "gsp_write", "gsp_fops", "ghsm_dbg", "debugfs_")
STATE_SUCCESS = "lease production-helper/UAPI harness passed; kernel VM/GUP not tested"
IMPL_SUCCESS = "production lease implementation harness: all cases passed (mock files/RM only)"
HARNESS_RUNS = (
    ("lease_harness", "ASan+UBSan", STATE_SUCCESS, 5),
    ("lease_race_harness", "TSan", STATE_SUCCESS, 5),
    ("lease_impl_harness", "ASan+UBSan", IMPL_SUCCESS, 6),
    ("lease_impl_race_harness", "TSan", IMPL_SUCCESS, 6),
)

CONTAINER_BUILD = r'''set -euo pipefail
export PATH=/opt/ddk/clang/clang-r510928/bin:$PATH
K=/opt/ddk/kdir/android15-6.6
MOD=gunyah-host-share-gki-6.6
test -f "$K/Makefile"
test -f "$K/Module.symvers"
command -v clang make llvm-strip llvm-readelf llvm-nm llvm-objdump
clang --version > /out/compiler.txt
make -s -C "$K" kernelrelease > /out/kernelrelease.txt
sha256sum "$K/Makefile" "$K/Module.symvers" > /out/kbuild-input-checksums.txt
B=$(mktemp -d /tmp/hostshare-lease-component.XXXXXX)
cp -a /src/. "$B/"
cp "$B/Makefile" /out/generated-Makefile
make -C "$K" -j2 M="$B" ARCH=arm64 LLVM=1 LLVM_IAS=1 modules
mapfile -t MODULES < <(find "$B" -type f -name '*.ko' -print)
test "${#MODULES[@]}" -eq 1
test "${MODULES[0]}" = "$B/$MOD.ko"
cp "$B/$MOD.ko" "/out/$MOD.unstripped.ko"
llvm-strip -d "$B/$MOD.ko"
cp "$B/$MOD.ko" "/out/$MOD.ko"
llvm-readelf -W -h -S -s -r "/out/$MOD.ko" > /out/elf-sections-symbols-relocations.txt
llvm-readelf -n "/out/$MOD.ko" > /out/elf-notes.txt
llvm-readelf -p .modinfo "/out/$MOD.ko" > /out/modinfo.txt
llvm-nm -u "/out/$MOD.ko" > /out/imports.txt
llvm-nm -a "/out/$MOD.ko" > /out/all-symbols.txt
llvm-objdump -d -r "/out/$MOD.ko" > /out/disassembly-relocations.txt
sha256sum "/out/$MOD.ko" "/out/$MOD.unstripped.ko" > /out/module-checksums.txt
'''


def file_set(rows):
    result = {}
    for row in rows:
        path = row["path"]
        parsed = PurePosixPath(path)
        if not path or parsed.is_absolute() or ".." in parsed.parts or "\\" in path \
                or ":" in path or parsed.as_posix() != path:
            raise RuntimeError("Unsafe source occurrence: " + path)
        if path in result or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) \
                or not isinstance(row["bytes"], int) or row["bytes"] < 0:
            raise RuntimeError("Malformed or duplicate source occurrence: " + path)
        result[path] = row
    return result


def require_tree(directory, expected, *, exact=True):
    actual = {path.relative_to(directory).as_posix(): path
              for path in directory.rglob("*") if path.is_file()}
    if not set(expected).issubset(actual) or (exact and set(actual) != set(expected)):
        raise RuntimeError("Source tree has missing or unexpected files")
    for path, row in expected.items():
        raw = actual[path].read_bytes()
        if len(raw) != row["bytes"] or sha256(raw) != row["sha256"]:
            raise RuntimeError("Source identity differs: " + path)


def require_patch(path, digest, size=None):
    raw = path.read_bytes()
    if sha256(raw) != digest or (size is not None and len(raw) != size):
        raise RuntimeError("Pinned patch identity differs: " + path.name)
    return raw


def validate_manifest(raw):
    if sha256(raw) != MANIFEST_SHA:
        raise RuntimeError("Pinned lease source manifest identity differs")
    manifest = json.loads(raw)
    if manifest["source_repository"] != SOURCE_REPO or manifest["source_commit"] != SOURCE_COMMIT \
            or manifest["upstream_source"]["path"] != SOURCE_PATH \
            or manifest["upstream_source"]["sha256"] != SOURCE_SHA \
            or manifest["clean_v3_patch"]["sha256"] != CLEAN_V3_PATCH_SHA \
            or manifest["clean_v3_patch"]["after_sha256"] != CLEAN_V3_SHA \
            or manifest["lease_patch"]["sha256"] != LEASE_PATCH_SHA \
            or manifest["lease_patch"]["bytes"] != LEASE_PATCH_BYTES \
            or manifest["toolchain"]["image"] != DDK_IMAGE \
            or manifest["toolchain"]["config_digest"] != DDK_CONFIG_SHA:
        raise RuntimeError("Manifest provenance or toolchain differs from pinned inputs")
    before = file_set(manifest["before"])
    after = file_set(manifest["after"])
    if set(before) != {"gunyah_share_mod.c"} or len(after) != 9 \
            or before["gunyah_share_mod.c"]["sha256"] != CLEAN_V3_SHA \
            or after["ghsm_lease_uapi.h"]["sha256"] != UAPI_SHA:
        raise RuntimeError("Lease source set or frozen UAPI differs")
    return manifest, before, after


def run_harnesses(candidate, output, after_set):
    command = ["env", "CC=cc", "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1",
               "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
               "make", "-C", str(candidate / "tests"), "test"]
    (output / "source-harness-command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
    log = output / "source-harness.log"
    # This executes make and all four instrumented programs. Success markers
    # are checked only after the complete command really exits zero.
    run_logged(command, log, timeout=180)
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    if lines.count(STATE_SUCCESS) != 2 or lines.count(IMPL_SUCCESS) != 2:
        raise RuntimeError("Executed harness log lacks all four completion markers")
    for executable, _, _, _ in HARNESS_RUNS:
        if not (candidate / "tests" / executable).is_file():
            raise RuntimeError("Executed harness binary is missing: " + executable)
    require_tree(candidate, after_set, exact=False)
    return {"command_exit_code": 0, "instrumented_harness_runs_completed": 4,
            "scenario_invocations_completed": sum(row[3] for row in HARNESS_RUNS),
            "runs": [{"executable": row[0], "sanitizer": row[1], "completion_marker": row[2],
                      "scenario_invocations_completed": row[3]} for row in HARNESS_RUNS],
            "kernel_vm_gup_rm_runtime_tested": False}


def verify_component(component):
    module = component / (MODULE + ".ko")
    raw = module.read_bytes()
    elf = (component / "elf-sections-symbols-relocations.txt").read_text()
    symbols = (component / "all-symbols.txt").read_text()
    imports = (component / "imports.txt").read_text()
    modinfo = (component / "modinfo.txt").read_text()
    if not re.search(r"Machine:\s+AArch64\b", elf) or not re.search(r"Type:\s+REL\b", elf):
        raise RuntimeError("Compiled lease module machine or ELF type differs")
    if "name=gunyah_host_share_gki_6.6" not in modinfo or "import_ns=DMA_BUF" not in modinfo:
        raise RuntimeError("Compiled lease module identity or DMA_BUF import namespace differs")
    if any(name.encode() in raw or name in symbols or name in imports for name in FORBIDDEN_PROBE):
        raise RuntimeError("Compiled lease module retains removed probe identifiers")
    for name in ("ghsm_lease_ioctl", "ghsm_lease_poll"):
        if not re.search(r"\b" + name + r"(?:\.[A-Za-z0-9_]+)*$", symbols, re.MULTILINE):
            raise RuntimeError("Compiled lease file operations are missing: " + name)
    if not re.search(r"\banon_inode_getfd$", imports, re.MULTILINE):
        raise RuntimeError("Compiled lease fd import is missing")
    vermagic = next(line.split("vermagic=", 1)[1].strip()
                    for line in modinfo.splitlines() if "vermagic=" in line)
    return {"module_sha256": sha256(raw), "module_bytes": len(raw), "vermagic": vermagic,
            "elf_machine": "AArch64", "elf_type": "REL", "module_name": "gunyah_host_share_gki_6.6",
            "binary_probe_identifiers_absent": True, "lease_file_operations_present": True,
            "runtime_compatibility": "Not tested; this builder never loads or installs a module"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true",
                        help="Verify the fixed download, both patches and all nine sources without compilation")
    parser.add_argument("--output", type=Path, default=Path("output/hostshare-lease-component"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {"status": "preparing", "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "compiled": False, "source_harnesses_executed": False, "module_loaded": False,
              "phone_modified": False, "published_release": False, "ddk_image": DDK_IMAGE,
              "builder_sha256": sha256(Path(__file__).read_bytes()),
              "command_runner_sha256": sha256((ROOT / "tools/build_hostshare_component_ci.py").read_bytes()),
              "independent_c_source_review": "pending"}
    try:
        manifest_raw = MANIFEST.read_bytes()
        manifest, before_set, after_set = validate_manifest(manifest_raw)
        require_tree(BUNDLED_SOURCE, after_set)
        clean_patch = require_patch(CLEAN_PATCH, CLEAN_V3_PATCH_SHA)
        lease_patch = require_patch(LEASE_PATCH, LEASE_PATCH_SHA, LEASE_PATCH_BYTES)
        inputs = output / "inputs"
        upstream = inputs / "upstream"
        record["source_inputs"] = [
            fetch_source(SOURCE_PATH, SOURCE_SHA, upstream / SOURCE_PATH),
            fetch_source("gunyah_host_share/GKI6.6/uapi_gunyah_share.h", HEADER_SHA,
                         upstream / "gunyah_host_share/GKI6.6/uapi_gunyah_share.h"),
            fetch_source("build.sh", BUILD_SH_SHA, inputs / "upstream-build.sh"),
        ]
        (inputs / MANIFEST.name).write_bytes(manifest_raw)
        clean_retained = inputs / CLEAN_PATCH.name
        lease_retained = inputs / LEASE_PATCH.name
        clean_retained.write_bytes(clean_patch)
        lease_retained.write_bytes(lease_patch)
        clean_candidate = inputs / "clean-v3"
        shutil.copytree(upstream, clean_candidate)
        clean_replay = output / "patch-replay" / "clean-v3"
        clean_replay.mkdir(parents=True)
        apply_checked_patch(clean_retained, clean_candidate, clean_replay)
        clean_c = (clean_candidate / SOURCE_PATH).read_bytes()
        if sha256(clean_c) != CLEAN_V3_SHA:
            raise RuntimeError("Clean-v3 replay source identity differs")
        if any(name in clean_c.decode() for name in FORBIDDEN_PROBE):
            raise RuntimeError("Clean-v3 replay retains removed probe identifiers")
        candidate = inputs / "lease-candidate"
        candidate.mkdir()
        (candidate / "gunyah_share_mod.c").write_bytes(clean_c)
        require_tree(candidate, before_set)
        lease_replay = output / "patch-replay" / "lease"
        lease_replay.mkdir(parents=True)
        apply_checked_patch(lease_retained, candidate, lease_replay)
        require_tree(candidate, after_set)
        shell = inputs / "container-build.sh"
        shell.write_text(CONTAINER_BUILD, encoding="utf-8", newline="\n")
        record.update(source_repository=SOURCE_REPO, source_commit=SOURCE_COMMIT,
                      source_sha256=SOURCE_SHA, clean_v3_patch_sha256=CLEAN_V3_PATCH_SHA,
                      clean_v3_sha256=CLEAN_V3_SHA, lease_patch_sha256=LEASE_PATCH_SHA,
                      manifest_sha256=sha256(manifest_raw), uapi_sha256=UAPI_SHA,
                      candidate_tree_verified=True, candidate_source_files_verified=len(after_set))
        if args.prepare_only:
            record["status"] = "prepared_only"
        else:
            if sys.platform != "linux" or not shutil.which("docker"):
                raise RuntimeError("An existing Linux Docker runtime is required; this tool installs nothing")
            run_logged(["bash", "-n", str(shell)], output / "container-shell-syntax.log", timeout=30)
            record["container_shell_syntax_checked"] = True
            record["source_harnesses"] = run_harnesses(candidate, output, after_set)
            record["source_harnesses_executed"] = True
            kernel_source = inputs / "kernel-source"
            kernel_source.mkdir()
            for path in after_set:
                target = kernel_source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((candidate / path).read_bytes())
            require_tree(kernel_source, after_set)
            run_logged(["docker", "pull", DDK_IMAGE], output / "docker-pull.log", timeout=600)
            inspected = subprocess.run(["docker", "image", "inspect", DDK_IMAGE],
                                       capture_output=True, check=True, timeout=30)
            (output / "docker-image-inspect.json").write_bytes(inspected.stdout)
            image = json.loads(inspected.stdout)[0]
            if image["Id"] != DDK_CONFIG_SHA or DDK_IMAGE not in image["RepoDigests"] \
                    or image["Os"] != "linux" or image["Architecture"] != "amd64" \
                    or image["Config"].get("Entrypoint") is not None:
                raise RuntimeError("Docker toolchain identity or platform differs")
            component = output / "component"
            component.mkdir()
            cidfile = output / "owned-build-container.cid"
            command = ["docker", "run", "--rm", "--cidfile", str(cidfile), "--network=none", "--cpus=2", "--memory=2g",
                       "--mount", f"type=bind,source={kernel_source},target=/src,readonly",
                       "--mount", f"type=bind,source={component},target=/out",
                       DDK_IMAGE, "/bin/bash", "-lc", CONTAINER_BUILD]
            (output / "docker-build-command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
            try:
                run_logged(command, output / "module-build.log", timeout=600)
                record["compiled"] = True
            finally:
                record["owned_container_cleanup_complete"] = cleanup_owned_container(
                    cidfile, output / "container-cleanup.log")
            if not record["owned_container_cleanup_complete"]:
                raise RuntimeError("Owned container cleanup is unknown or incomplete")
            record.update(verify_component(component))
            record["status"] = "built_and_static_verified"
    except Exception as error:
        record.update(status="failed", failure=str(error))
        if isinstance(error, OwnedCommandTimeout):
            record["owned_process_group_cleanup_complete"] = error.cleanup_complete
    finally:
        record["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        record["retained_files"] = [] if record.get("owned_process_group_cleanup_complete") is False else [
            {"path": path.relative_to(output).as_posix(), "sha256": sha256(path.read_bytes()),
             "bytes": path.stat().st_size} for path in sorted(output.rglob("*")) if path.is_file()]
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: record.get(key) for key in (
        "status", "failure", "candidate_source_files_verified", "source_harnesses_executed",
        "compiled", "module_sha256", "module_bytes")}, indent=2))
    return 0 if record["status"] in ("prepared_only", "built_and_static_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
