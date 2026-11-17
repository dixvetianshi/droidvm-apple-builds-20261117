#!/usr/bin/env bash
# This runs on a disposable Ubuntu ARM64 build machine. It never contacts a phone,
# replaces an APK, installs kernel modules, or builds the large crosvm Soong tree.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
EDK2_PIN=ee11a290dc1207270c53eb73f97a9bef92b8e97b
EDK2_SUBMODULE_PIN=b7a715f7c03c45c6b4575bf88596bfd79658b8ce
OUT="$ROOT/output/runtime"
UPSTREAM="$ROOT/output/runtime-upstream"
WORK=$(mktemp -d "${RUNNER_TEMP:-/tmp}/droidvm-apple-runtime.XXXXXX")
export OUT EDK2_PIN EDK2_SUBMODULE_PIN

test "$(uname -m)" = aarch64 || { echo 'An ARM64 Linux build machine is required.' >&2; exit 1; }
test ! -e "$OUT/firmware-builds.json" || { echo "Existing output must be preserved separately: $OUT" >&2; exit 1; }
mkdir -p "$OUT/firmware"

# fetch_runtime.py owns archive admission, the fixed prebuilt source, and all
# static runtime observations. Preserve its output without interpreting it again.
python3 "$ROOT/tools/fetch_runtime.py" --output "$UPSTREAM"
cp -a "$UPSTREAM/verified" "$OUT/verified"
cp "$UPSTREAM/runtime-provenance.json" "$UPSTREAM/prebuilt-arm64-v8a.json" "$OUT/"

python3 - <<'PY'
import json
import os
from pathlib import Path
out = Path(os.environ['OUT'])
report = {
    'edk2_repository': 'https://github.com/Droid-VM/edk2-gunyah',
    'edk2_commit': os.environ['EDK2_PIN'],
    'edk2_submodule_commit': os.environ['EDK2_SUBMODULE_PIN'],
    'firmware_builds': [],
    'phone_runtime_verification': 'not performed',
    'apple_guest_boot_verification': 'not performed',
}
(out / 'firmware-builds.json').write_text(json.dumps(report, indent=2) + '\n')
PY

build_firmware() {
  local variant=$1 gpu_enabled=$2 firmware_name=$3 source_dir="$WORK/edk2-$1"
  git init "$source_dir"
  git -C "$source_dir" remote add origin https://github.com/Droid-VM/edk2-gunyah.git
  git -C "$source_dir" fetch --depth 1 origin "$EDK2_PIN"
  git -C "$source_dir" checkout --detach FETCH_HEAD
  test "$(git -C "$source_dir" rev-parse HEAD)" = "$EDK2_PIN"
  git -C "$source_dir" submodule update --init --recursive --depth 1
  test "$(git -C "$source_dir/edk2" rev-parse HEAD)" = "$EDK2_SUBMODULE_PIN"
  (
    cd "$source_dir"
    EDK2_TARGET=RELEASE bash ./build.sh -n "${JOBS:-4}" \
      -DPCI_CAM_MODE=FALSE -DVIRTIO_GPU_ENABLE="$gpu_enabled"
  )
  test -s "$source_dir/edk2-gunyah.fd"
  test -s "$source_dir/edk2-gunyah.vars.fd"
  cp "$source_dir/edk2-gunyah.fd" "$OUT/firmware/$firmware_name.fd"
  cp "$source_dir/edk2-gunyah.vars.fd" "$OUT/firmware/$firmware_name.vars.fd"
  python3 - "$variant" "$gpu_enabled" "$firmware_name" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys
out = Path(os.environ['OUT'])
path = out / 'firmware-builds.json'
report = json.loads(path.read_text())
firmware = out / f'firmware/{sys.argv[3]}.fd'
vars_file = out / f'firmware/{sys.argv[3]}.vars.fd'
report['firmware_builds'].append({
    'guest': sys.argv[1],
    'target': 'RELEASE_GCC / AARCH64',
    'pci_cam_mode': False,
    'virtio_gpu_enable': sys.argv[2] == 'TRUE',
    'firmware': f'firmware/{sys.argv[3]}.fd',
    'firmware_sha256': hashlib.sha256(firmware.read_bytes()).hexdigest(),
    'vars': f'firmware/{sys.argv[3]}.vars.fd',
    'vars_sha256': hashlib.sha256(vars_file.read_bytes()).hexdigest(),
    'build_output': 'build/Build/GunyahKernel-AARCH64/RELEASE_GCC/FV/GUNYAH_EFI.fd',
    'phone_boot_verification': 'not performed',
})
path.write_text(json.dumps(report, indent=2) + '\n')
PY
}

# Separate checkouts keep upstream patches and firmware configuration independent.
build_firmware macos FALSE edk2-macos
build_firmware ipados TRUE edk2-virtio-gpu

python3 - <<'PY'
import hashlib
import os
from pathlib import Path
out = Path(os.environ['OUT'])
rows = []
for path in sorted(out.rglob('*')):
    if not path.is_file() or path.name == 'SHA256SUMS':
        continue
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    rows.append(f'{digest.hexdigest()}  {path.relative_to(out).as_posix()}\n')
(out / 'SHA256SUMS').write_text(''.join(rows))
print(f'Runtime and both firmware variants prepared in {out}; phone execution remains unverified.')
PY
