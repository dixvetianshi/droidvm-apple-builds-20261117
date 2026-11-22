"""Build one reviewed App component; never publish, load modules or change phone state."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

SOURCE_REPO = "Droid-VM/gunyah_host_mod"
SOURCE_COMMIT = "44e8ae5a088a3a35290a5cacb205640cff187b99"
SOURCE_PATH = "gunyah_host_share/GKI6.6/gunyah_share_mod.c"
SOURCE_SHA = "73df544b50d146f1a53907393a3a40a64eb4484d660074e6494fb54421cf60ce"
CANDIDATE_SHA = "10ee8c3c635e2d5ece48606c03cac218f7633e68226646bfe30125b51443fd99"
PATCH_SHA = "058ca1463c09f484cd401c3906088ecfd15545c9f24781a8cc96a177c234beaf"
HEADER_SHA = "0f1cd1b15c4b2b00a6bfabe8104652b6540bd2a4319cdcaf3975af9180ee11fe"
BUILD_SH_SHA = "ebbb9b63bcd897287c4442d69fd1ed3f205d3e9d575bba17c84de73bf8009921"
DDK_IMAGE = "ghcr.io/ylarod/ddk-min@sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2"
DDK_CONFIG_SHA = "sha256:b3d6c84921b6ff5dc0caea91f06fe71d53b83bf671c55eaaf50ad7eda65b64f2"
MODULE = "gunyah-host-share-gki-6.6"

CONTAINER_BUILD = r'''set -euo pipefail
export PATH=/opt/ddk/clang/clang-r510928/bin:$PATH
K=/opt/ddk/kdir/android15-6.6
MOD=gunyah-host-share-gki-6.6
test -d "$K"
test -f "$K/Makefile"
test -f "$K/Module.symvers"
command -v clang make llvm-strip llvm-readelf llvm-nm llvm-objdump
clang --version > /out/compiler.txt
make -s -C "$K" kernelrelease > /out/kernelrelease.txt
sha256sum "$K/Makefile" "$K/Module.symvers" > /out/kbuild-input-checksums.txt
B=$(mktemp -d /tmp/hostshare-component.XXXXXX)
cp /src/gunyah_share_mod.c "$B/$MOD.c"
cp /src/uapi_gunyah_share.h "$B/uapi_gunyah_share.h"
printf 'obj-m += %s.o\n' "$MOD" > "$B/Makefile"
cp "$B/Makefile" /out/generated-Makefile
make -C "$K" -j2 M="$B" ARCH=arm64 LLVM=1 LLVM_IAS=1 modules
test -f "$B/$MOD.ko"
cp "$B/$MOD.ko" "/out/$MOD.unstripped.ko"
llvm-strip -d "$B/$MOD.ko"
cp "$B/$MOD.ko" "/out/$MOD.ko"
llvm-readelf -W -h -S -s -r "/out/$MOD.ko" > /out/elf-sections-symbols-relocations.txt
llvm-readelf -p .modinfo "/out/$MOD.ko" > /out/modinfo.txt
llvm-nm -u "/out/$MOD.ko" > /out/imports.txt
llvm-nm -a "/out/$MOD.ko" > /out/all-symbols.txt
llvm-objdump -d -r "/out/$MOD.ko" > /out/disassembly-relocations.txt
sha256sum "/out/$MOD.ko" "/out/$MOD.unstripped.ko" > /out/module-checksums.txt
'''


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch_source(relative, expected, destination):
    url = f"https://raw.githubusercontent.com/{SOURCE_REPO}/{SOURCE_COMMIT}/{relative}"
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read()
    if sha256(raw) != expected:
        raise RuntimeError("Immutable source digest mismatch: " + relative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return {"source_url": url, "sha256": expected, "bytes": len(raw)}


def run_logged(arguments, log, *, cwd=None, timeout=300):
    with log.open("wb") as stream:
        result = subprocess.run(arguments, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command exited {result.returncode}; full diagnostic: {log.name}")


def cleanup_owned_container(cidfile, log):
    """Docker client timeout does not stop its daemon-owned container."""
    try:
        if not cidfile.is_file():
            log.write_text("Container ID was not received; cleanup status is unknown.\n", encoding="utf-8")
            return False
        container_id = cidfile.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            log.write_text("Owned container ID is malformed; no removal was attempted.\n", encoding="utf-8")
            return False
        query = ["docker", "container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "id=" + container_id]
        with log.open("wb") as stream:
            before = subprocess.run(query, stdout=subprocess.PIPE, stderr=stream, timeout=30)
            stream.write(before.stdout)
            if before.returncode or before.stdout.strip() not in (b"", container_id.encode()):
                return False
            if before.stdout.strip():
                removed = subprocess.run(["docker", "container", "rm", "--force", container_id],
                                         stdout=stream, stderr=subprocess.STDOUT, timeout=30)
                if removed.returncode:
                    return False
            after = subprocess.run(query, stdout=subprocess.PIPE, stderr=stream, timeout=30)
            stream.write(after.stdout)
            return after.returncode == 0 and not after.stdout.strip()
    except Exception as error:
        with log.open("ab") as stream:
            stream.write(("Cleanup unknown: " + str(error) + "\n").encode())
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", help="Validate source/patch identity without Docker or compilation")
    parser.add_argument("--output", type=Path, default=Path("output/hostshare-component"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {"status": "preparing", "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "source_repository": SOURCE_REPO, "source_commit": SOURCE_COMMIT,
              "source_sha256": SOURCE_SHA, "candidate_sha256": CANDIDATE_SHA,
              "patch_sha256": PATCH_SHA, "ddk_image": DDK_IMAGE,
              "compiled": False, "module_loaded": False, "published": False}
    try:
        patch_path = Path(__file__).resolve().parents[1] / "patches/hostshare/remove-unused-debugfs-probe.patch"
        patch = patch_path.read_bytes()
        if sha256(patch) != PATCH_SHA:
            raise RuntimeError("Reviewed patch digest mismatch")
        inputs = output / "inputs"
        original = inputs / "before" / SOURCE_PATH
        header_path = "gunyah_host_share/GKI6.6/uapi_gunyah_share.h"
        record["source_inputs"] = [
            fetch_source(SOURCE_PATH, SOURCE_SHA, original),
            fetch_source(header_path, HEADER_SHA, inputs / "before" / header_path),
            fetch_source("build.sh", BUILD_SH_SHA, inputs / "upstream-build.sh"),
        ]
        retained_patch = inputs / "remove-unused-debugfs-probe.patch"
        retained_patch.write_bytes(patch)
        candidate_root = inputs / "candidate"
        shutil.copytree(inputs / "before", candidate_root)
        run_logged(["git", "-c", "core.autocrlf=false", "apply", "--check", str(retained_patch)],
                   output / "patch-check.log", cwd=candidate_root)
        run_logged(["git", "-c", "core.autocrlf=false", "apply", str(retained_patch)],
                   output / "patch-apply.log", cwd=candidate_root)
        before = original.read_bytes()
        candidate = (candidate_root / SOURCE_PATH).read_bytes()
        if sha256(candidate) != CANDIDATE_SHA:
            raise RuntimeError("Applied candidate source digest mismatch")
        before_text = before.decode()
        candidate_text = candidate.decode()
        production = before_text[before_text.index("static const struct file_operations ghsm_fops"):
                                 before_text.index("/* ---- debugfs probe for standalone bring-up")]
        if production not in candidate_text:
            raise RuntimeError("Production ioctl table or misc device changed")
        forbidden = ("gh_share_probe", "gsp_write", "gsp_fops", "ghsm_dbg", "debugfs_")
        if any(identifier in candidate_text for identifier in forbidden):
            raise RuntimeError("Source candidate retains probe or debugfs behavior")
        record["production_fops_and_misc_device_verbatim"] = True
        record["source_probe_identifiers_absent"] = True
        (inputs / "container-build.sh").write_text(CONTAINER_BUILD, encoding="utf-8")
        if args.prepare_only:
            record["status"] = "prepared_only"
        else:
            if sys.platform != "linux" or not shutil.which("docker"):
                raise RuntimeError("Build requires existing Linux Docker; no tools are installed by this script")
            run_logged(["docker", "pull", DDK_IMAGE], output / "docker-pull.log", timeout=600)
            inspected = subprocess.run(["docker", "image", "inspect", DDK_IMAGE], capture_output=True, check=True, timeout=30)
            (output / "docker-image-inspect.json").write_bytes(inspected.stdout)
            image = json.loads(inspected.stdout)[0]
            if image["Id"] != DDK_CONFIG_SHA or DDK_IMAGE not in image["RepoDigests"] \
                    or image["Os"] != "linux" or image["Architecture"] != "amd64" \
                    or image["Config"].get("Entrypoint") is not None:
                raise RuntimeError("Pulled Docker image identity/platform/entrypoint differs from reviewed input")
            artifact = output / "component"
            artifact.mkdir()
            source_mount = (candidate_root / "gunyah_host_share/GKI6.6").resolve()
            cidfile = output / "owned-build-container.cid"
            arguments = ["docker", "run", "--rm", "--cidfile", str(cidfile), "--network=none", "--cpus=2", "--memory=2g",
                         "--mount", f"type=bind,source={source_mount},target=/src,readonly",
                         "--mount", f"type=bind,source={artifact},target=/out",
                         DDK_IMAGE, "/bin/bash", "-lc", CONTAINER_BUILD]
            (output / "docker-build-command.json").write_text(json.dumps(arguments, indent=2) + "\n", encoding="utf-8")
            try:
                run_logged(arguments, output / "module-build.log", timeout=600)
                record["compile_command_completed"] = True
                record["compiled"] = True
            finally:
                record["owned_container_cleanup_complete"] = cleanup_owned_container(cidfile, output / "container-cleanup.log")
            if not record["owned_container_cleanup_complete"]:
                raise RuntimeError("Owned build container cleanup is unknown or incomplete; see container-cleanup.log")
            module = artifact / (MODULE + ".ko")
            data = module.read_bytes()
            elf = (artifact / "elf-sections-symbols-relocations.txt").read_text()
            symbols = (artifact / "all-symbols.txt").read_text()
            imports = (artifact / "imports.txt").read_text()
            modinfo = (artifact / "modinfo.txt").read_text()
            if not re.search(r"Machine:\s+AArch64\b", elf) or not re.search(r"Type:\s+REL\b", elf):
                raise RuntimeError("Produced component is not AArch64 relocatable ELF")
            if any(name.encode() in data or name in symbols or name in imports for name in forbidden):
                raise RuntimeError("Produced component retains probe or debugfs identifiers")
            if "name=gunyah_host_share_gki_6.6" not in modinfo or "import_ns=DMA_BUF" not in modinfo:
                raise RuntimeError("Produced module identity or DMA_BUF import namespace differs")
            vermagic = next(line.split("vermagic=", 1)[1].strip() for line in modinfo.splitlines() if "vermagic=" in line)
            record.update({"status": "built_and_static_verified", "compiled": True,
                           "module_sha256": sha256(data), "module_bytes": len(data),
                           "vermagic": vermagic, "elf_machine": "AArch64", "elf_type": "REL",
                           "binary_probe_identifiers_absent": True,
                           "runtime_compatibility": "not tested; no module loading is authorized by this workflow"})
    except Exception as error:
        record.update({"status": "failed", "failure": str(error)})
    finally:
        record["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        record["retained_files"] = [{"path": str(path.relative_to(output)), "sha256": sha256(path.read_bytes()),
                                      "bytes": path.stat().st_size}
                                     for path in sorted(output.rglob("*")) if path.is_file()]
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0 if record["status"] in ("prepared_only", "built_and_static_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
