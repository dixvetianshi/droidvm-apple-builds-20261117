#!/usr/bin/env bash
# Run only on the approved disposable macOS build runner.
set -euo pipefail

task_root=$(cd "$(dirname "$0")/.." && pwd)
diagnostics="$task_root/verification/ipados-diagnostics"
mkdir -p "$diagnostics"
stage=preflight
disk_summary() {
  printf '\nStage: %s\n' "$1" | tee -a "$diagnostics/disk.txt"
  df -h "$task_root" | tee -a "$diagnostics/disk.txt"
}
finish() {
  local status=$?
  trap - EXIT
  printf 'exit_code=%s\nstage=%s\n' "$status" "$stage" > "$diagnostics/build-status.txt"
  disk_summary "finished ($status)" || true
  exit "$status"
}
trap finish EXIT

# The upstream payload command logs its explicitly secret platform seed. Redact
# exact secret values before sending the console to public Actions diagnostics;
# the upstream's private release/identity records are not uploaded as logs.
run_logged() {
  "$@" 2>&1 | python3 -u -c '
import os, sys
secrets = {os.environ.get("ARTIFACT_KEY", ""), os.environ.get("UNIXNU_UNIQUE_CHIP_ID", "")}
chip = os.environ.get("UNIXNU_UNIQUE_CHIP_ID", "")
secrets.update((chip.lower(), chip.upper()))
secrets = sorted((value for value in secrets if value), key=len, reverse=True)
for line in sys.stdin:
    for value in secrets:
        line = line.replace(value, "[REDACTED]")
    print(line, end="", flush=True)
' | tee -a "$diagnostics/build-console.txt"
}

test "$(uname -s)" = Darwin || { echo 'This pinned iPadOS build requires macOS.' >&2; exit 1; }
test -n "${ARTIFACT_KEY:-}" || { echo 'ARTIFACT_KEY is required.' >&2; exit 1; }
[[ "${UNIXNU_UNIQUE_CHIP_ID:-}" =~ ^[0-9a-fA-F]{16}$ ]] || { echo 'A 16-digit UNIXNU_UNIQUE_CHIP_ID is required.' >&2; exit 1; }

mkdir -p "$task_root/sources" "$task_root/output"
disk_summary preflight
checkout_pin() {
  local url=$1 directory=$2 revision=$3
  test ! -e "$directory" || { echo "Refusing to overwrite $directory" >&2; exit 1; }
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

# The pinned board's tree linker derives its owning checkout from
# <UniXNU>/out/<kit>/<os>/<board>/tree. Keep this internal build output under
# the already selected checkout so its pinned GPU sources resolve correctly.
export UNIXNU_OUT="$task_root/sources/UniXNU/out"
export LLVM_PREFIX
export LLD_PREFIX
LLVM_PREFIX=$(brew --prefix llvm)
LLD_PREFIX=$(brew --prefix lld)
stage=guest-build
disk_summary "$stage"
run_logged python3 "$task_root/sources/UniXNU-droidvm/ipados27/scripts/build-droidvm-all.py" \
  --unixnu "$task_root/sources/UniXNU" \
  --unique-chip-id "$UNIXNU_UNIQUE_CHIP_ID" --data-gib 12

# Only complete upstream release files are admitted to the packaging stage.
stage=staging
disk_summary "$stage"
run_logged python3 "$task_root/tools/stage_ipados_release.py" --build-root "$UNIXNU_OUT" --output "$task_root/output/ipados-stage"

stage=encryption
disk_summary "$stage"
cd "$task_root/output"
encrypted_name=ipados-27.0.1.tar.gz.enc
test ! -e "$encrypted_name" && ! compgen -G "$encrypted_name.*" >/dev/null || { echo 'Encrypted output already exists.' >&2; exit 1; }

# Stream directly into the same numbered chunks consumed by the local decryptor.
# No second full ciphertext is retained beside the split output.
tar -czf - -C ipados-stage . | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass env:ARTIFACT_KEY | \
  split -b 1800m -d -a 3 - "$encrypted_name."
chunks=("$encrypted_name."[0-9][0-9][0-9])
test -s "${chunks[0]}" || { echo 'Encrypted output is missing.' >&2; exit 1; }
shasum -a 256 "${chunks[@]}" > "$encrypted_name.sha256"
stage=complete
