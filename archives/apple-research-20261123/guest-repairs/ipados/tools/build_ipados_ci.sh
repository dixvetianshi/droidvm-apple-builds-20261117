#!/usr/bin/env bash
# This branch builds only the iPadOS kernel; it reuses the original seed/key.
set -Eeuo pipefail
task_root=$(cd "$(dirname "$0")/.." && pwd)
diagnostics="$task_root/verification/ipados-diagnostics"
mkdir -p "$task_root/output" "$diagnostics"
stage=preflight
finish() {
  local status=$?
  printf 'exit_code=%s\nstage=%s\n' "$status" "$stage" > "$diagnostics/kernel-only-status.txt"
  exit "$status"
}
trap finish EXIT

# Only the explicitly selected existing build secrets are redacted. Inputs,
# source paths and digests remain available; no environment dump is persisted.
run_logged() {
  "$@" 2>&1 | python3 -u -c '
import os, sys
values = {os.environ.get("ARTIFACT_KEY", ""), os.environ.get("UNIXNU_UNIQUE_CHIP_ID", "")}
chip = os.environ.get("UNIXNU_UNIQUE_CHIP_ID", "")
values.update((chip.upper(), chip.lower()))
values = sorted((v for v in values if v), key=len, reverse=True)
for line in sys.stdin:
    for value in values:
        line = line.replace(value, "[REDACTED]")
    print(line, end="", flush=True)
' | tee -a "$diagnostics/kernel-only-build.txt"
}

test "$(uname -s)" = Darwin
test -n "${ARTIFACT_KEY:-}"
[[ "${UNIXNU_UNIQUE_CHIP_ID:-}" =~ ^[0-9a-fA-F]{16}$ ]]
test ! -e "$task_root/sources"
mkdir "$task_root/sources"
openssl_binary="$(brew --prefix openssl@3)/bin/openssl"
test -x "$openssl_binary"
"$openssl_binary" version | tee "$diagnostics/kernel-openssl.txt"

stage=input
gh api repos/dixvetianshi/droidvm-apple-builds-20261117/releases/assets/772370275 \
  -H 'Accept: application/octet-stream' > "$task_root/output/kernel-input.enc"
run_logged python3 "$task_root/tools/admit_ipados_floor_input.py" \
  --encrypted "$task_root/output/kernel-input.enc" --output "$task_root/output/kernel-input" \
  --openssl "$openssl_binary"
input="$task_root/output/kernel-input"

checkout_pin() {
  local url=$1 directory=$2 revision=$3
  test ! -e "$directory"
  git init -q "$directory"
  git -C "$directory" remote add origin "$url"
  git -C "$directory" fetch --depth 1 origin "$revision"
  git -C "$directory" checkout --detach FETCH_HEAD
  test "$(git -C "$directory" rev-parse HEAD)" = "$revision"
}
stage=sources
checkout_pin https://github.com/Droid-VM/UniXNU.git "$task_root/sources/UniXNU" 6efbb97764f4e39f8c682f6a6261607a2921bc7b
checkout_pin https://github.com/Droid-VM/UniXNU-droidvm.git "$task_root/sources/UniXNU-droidvm" 3da41eaa0f06fd21e7bc1ef17aafe0a3e72d70ff
git -C "$task_root/sources/UniXNU" submodule update --init --recursive
git -C "$task_root/sources/UniXNU-droidvm" apply --check "$task_root/patches/ipados-lsd-floor.patch"
git -C "$task_root/sources/UniXNU-droidvm" apply "$task_root/patches/ipados-lsd-floor.patch"

unixnu="$task_root/sources/UniXNU"
device="$task_root/sources/UniXNU-droidvm"
board="$device/ipados27"
os_profile=ipados-27.0.1-24A446
export UNIXNU_OUT="$unixnu/out"
export LLVM_PREFIX LLD_PREFIX
LLVM_PREFIX=$(brew --prefix llvm)
LLD_PREFIX=$(brew --prefix lld)
cp "$input/build-evidence/unixnu.lock" "$board/unixnu.lock"
run_logged "$unixnu/unixnu" defconfig -D "$board" --os "$os_profile" droidvm_ipados27_defconfig
run_logged "$unixnu/unixnu" fetch -D "$board" --os "$os_profile"
run_logged "$unixnu/unixnu" tree -D "$board" --os "$os_profile"

stage=original-kernelcache
# The only IPSW member selected; no OS, SystemOS or Data generation download.
run_logged "$unixnu/unixnu" ipsw -D "$board" --os "$os_profile" fetch KernelCache
export UNIXNU_KERNELCACHE="$UNIXNU_OUT/ipsw/24A446/kernelcache.decompressed"
python3 - "$UNIXNU_KERNELCACHE" <<'PY'
import hashlib, sys
from pathlib import Path
path = Path(sys.argv[1])
expected = '38e6d9fa5f789b8228f4617ef4c6d2a3fd8ab564abdc9b62920f1db53fc1780a'
if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
    raise SystemExit('The original Apple kernelcache differs from the release pin')
print('Original decompressed Apple kernelcache digest verified.')
PY

work="$UNIXNU_OUT/droidvm/$os_profile/droidvm_ipados27"
mkdir -p "$work/tree/build/verified-root-host/keys"
cp "$input/owner-public.pem" "$work/tree/build/verified-root-host/keys/owner-public.pem"
stage=kernel
run_logged python3 "$board/scripts/build-droidvm-all.py" \
  --unixnu "$unixnu" --generation "$input/generation" --only data,kernel --allow-dirty

stage=admit-output
python3 - "$task_root" "$work" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
root, work = (Path(v) for v in sys.argv[1:])
out = root / 'output/ipados-lsd-floor-kernel'
out.mkdir(exist_ok=False)
tree = work / 'tree'
paths = {
    'kernel.macho': work / 'kernel/kernel.macho',
    'kernel.native.macho': tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf',
    'kexts.json': work / 'kernel/kexts.json',
    'kernel.json': work / 'kernel/kernel.json',
}
files = {}
for name, source in paths.items():
    if not source.is_file() or source.is_symlink():
        raise SystemExit('A complete kernel-only result is missing: ' + str(source))
    body = source.read_bytes()
    if len(body) > 128 << 20:
        raise SystemExit('A kernel-only output exceeds its admitted extent')
    shutil.copyfile(source, out / name)
    files[name] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
kernel = (out / 'kernel.macho').read_bytes()
anchor = (root / 'output/kernel-input/owner-anchor.bin').read_bytes()
if kernel[:4] != b'\xcf\xfa\xed\xfe' or anchor not in kernel:
    raise SystemExit('The real compiled fileset does not retain the admitted original public anchor')
if b'droidvm-ipados-lsd-floor' not in kernel:
    raise SystemExit('The real compiled fileset lacks the selected lsd floor switch')
seed = json.loads((work / 'build-all/seed.json').read_text())
if seed['seed_sha256'] != '97351f9059b125f728a75c8630d3b05c8c4ec60d4b6a94d5a33fb0a55e513ce8' or seed['volume_uuid'] != 'C0A40140-CA85-4848-98AF-0C007018865D':
    raise SystemExit('The kernel-only build changed the existing Data generation')
patch = root / 'patches/ipados-lsd-floor.patch'
manifest = {
    'schema': 'org.droidvm.ipados.lsd-floor-kernel.build.v1', 'complete': True,
    'scope': 'iPadOS kernel collection only; existing OS/SystemOS/Data and original boot sidecars retained',
    'xnu_commit': 'ac9718fb1af618d5ce8678d0dc6e8a58f252216f',
    'unixnu_commit': '6efbb97764f4e39f8c682f6a6261607a2921bc7b',
    'device_commit': '3da41eaa0f06fd21e7bc1ef17aafe0a3e72d70ff',
    'device_patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
    'original_public_anchor_sha256': hashlib.sha256(anchor).hexdigest(),
    'original_data_seed_sha256': seed['seed_sha256'], 'original_data_volume_uuid': seed['volume_uuid'],
    'policy': {'boot_argument': 'droidvm-ipados-lsd-floor=1', 'uid': 501, 'registered_name': 'lsd',
               'positive_active_inactive_floor_mb': 64, 'attributes_preserved': True,
               'executable_path_binding': False, 'total_guest_RAM_changed': False},
    'files': files, 'real_kernel_compilation_completed': True,
    'phone_boot_verified': False, 'replication_or_reboot_verified': False,
}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'kernel_only_build_completed': True, 'files': files, 'phone_boot_verified': False}))
PY

stage=encrypt-output
tar -czf - -C "$task_root/output" ipados-lsd-floor-kernel | \
  "$openssl_binary" enc -aes-256-cbc -salt -saltlen 8 -pbkdf2 -iter 200000 -pass env:ARTIFACT_KEY | \
  split -b 1900m -d -a 3 - "$task_root/output/ipados-27.0.1.tar.gz.enc."
shasum -a 256 "$task_root/output/ipados-27.0.1.tar.gz.enc."[0-9][0-9][0-9] > "$diagnostics/kernel-only-parts.txt"
stage=complete
