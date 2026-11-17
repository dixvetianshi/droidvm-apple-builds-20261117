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

mkdir -p "$task_root/output"
# This fresh runner's nested source namespace is created exclusively here.
# Retain its directory identity outside it before any build takes ownership.
python3 - "$task_root" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve(strict=True)
sources = root / 'sources'
sources.mkdir()
identity = sources.lstat()
receipt = {'kind': 'DroidVM owned build sources v1', 'task_root': str(root),
           'sources': str(sources), 'device': identity.st_dev, 'inode': identity.st_ino}
with (root / 'verification/ipados-diagnostics/source-owner.txt').open('x') as out:
    out.write(json.dumps(receipt) + '\n')
PY
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

# The disk writer is shared by both root-image consumers, and the Data seed
# stages its IPSW inputs on the same APFS volume. Keep the selected commits
# and record all three explicit representation/copy adjustments.
git -C "$task_root/sources/UniXNU" apply --check "$task_root/patches/unixnu-sparse-udif.patch"
git -C "$task_root/sources/UniXNU-droidvm" apply --check "$task_root/patches/device-sparse-udif.patch"
git -C "$task_root/sources/UniXNU-droidvm" apply --check "$task_root/patches/ipados-apfs-clone-staging.patch"
git -C "$task_root/sources/UniXNU" apply "$task_root/patches/unixnu-sparse-udif.patch"
git -C "$task_root/sources/UniXNU-droidvm" apply "$task_root/patches/device-sparse-udif.patch"
git -C "$task_root/sources/UniXNU-droidvm" apply "$task_root/patches/ipados-apfs-clone-staging.patch"
python3 - "$task_root" <<'PY'
import hashlib, importlib.util, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
root = Path(sys.argv[1])
producer = root / 'sources/UniXNU-droidvm/ipados27/scripts/build-droidvm-all.py'
spec = importlib.util.spec_from_file_location('droidvm_build_records', producer)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
patches = {}
states = {}
for name, directory in (('unixnu', 'UniXNU'), ('device', 'UniXNU-droidvm')):
    file = f'patches/{name}-sparse-udif.patch'
    patches[name] = {'file': file, 'sha256': hashlib.sha256((root / file).read_bytes()).hexdigest()}
    states[name] = module.checkout_state(root / 'sources' / directory)
file = 'patches/ipados-apfs-clone-staging.patch'
patches['device_clone'] = {'file': file, 'sha256': hashlib.sha256((root / file).read_bytes()).hexdigest()}
record = {'kind': 'sparse-udif-output-and-apfs-clone-staging', 'patches': patches, 'checkout_states': states,
          'scope': 'raw disk representation, bounded zero spans and lossless APFS staging clones; original logical image digests and Data seed identity remain mandatory'}
(root / 'output/source-adjustments.json').write_text(json.dumps(record, indent=2) + '\n')
print('Recorded the three source adjustments; the release will retain its actual source-change facts.')
PY

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
  --unique-chip-id "$UNIXNU_UNIQUE_CHIP_ID" --data-gib 12 --allow-dirty

python3 - "$task_root" <<'PY'
import importlib.util, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('droidvm_build_records', root / 'sources/UniXNU-droidvm/ipados27/scripts/build-droidvm-all.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
path = root / 'output/source-adjustments.json'
record = json.loads(path.read_text())
states = {name: module.checkout_state(root / 'sources' / directory)
          for name, directory in (('unixnu', 'UniXNU'), ('device', 'UniXNU-droidvm'))}
if states != record['checkout_states']:
    raise SystemExit('The source checkouts changed beyond the recorded source adjustments during the build.')
record['final_checkout_states'] = states
path.write_text(json.dumps(record, indent=2) + '\n')
print('Final source states match the recorded source adjustments.')
PY

# Only complete upstream release files are admitted to the packaging stage.
stage=staging
disk_summary "$stage"
run_logged python3 "$task_root/tools/stage_ipados_release.py" --build-root "$UNIXNU_OUT" --output "$task_root/output/ipados-stage"
cp "$task_root/output/source-adjustments.json" "$task_root/output/ipados-stage/source-adjustments.json"

# All compilation, source-state verification and staging have completed. The
# remaining encryption uses only this complete stage and system executables.
stage=source-cleanup
disk_summary "$stage"
python3 - "$task_root" "$UNIXNU_OUT" <<'PY'
import hashlib, json, shutil, stat, sys, tempfile
from pathlib import Path
root = Path(sys.argv[1]).resolve(strict=True)
sources = root / 'sources'
stage = root / 'output/ipados-stage'
diagnostic_directory = root / 'verification/ipados-diagnostics'
report = {'kind': 'DroidVM source reclaim v1', 'scope': str(sources),
          'free_bytes_before': shutil.disk_usage(root).free, 'status': 'validating',
          'logical_file_sizes_used_as_freed_bytes': False}

def require(value, message):
    if not value:
        raise RuntimeError(message)

def regular(path, within):
    require(not path.is_symlink() and path.is_file(), 'A retained input is not a regular file: ' + str(path))
    require(within in path.resolve(strict=True).parents, 'A retained input resolves outside its owning directory.')
    return path

def stage_files_are_regular():
    require(not stage.is_symlink() and stage.is_dir() and stage.resolve(strict=True).parent == root / 'output',
            'The complete stage is not the selected local directory.')
    pending = [stage]
    while pending:
        for path in pending.pop().iterdir():
            mode = path.lstat().st_mode
            require(stat.S_ISREG(mode) or stat.S_ISDIR(mode),
                    'The stage contains a link or special file; preserve sources until its dependency is resolved.')
            if stat.S_ISDIR(mode):
                pending.append(path)

try:
    require(not sources.is_symlink() and sources.is_dir() and sources.resolve(strict=True).parent == root,
            'The cleanup target is not the selected plain sources directory.')
    owner = json.loads(regular(root / 'verification/ipados-diagnostics/source-owner.txt', root).read_text())
    identity = sources.lstat()
    require(owner == {'kind': 'DroidVM owned build sources v1', 'task_root': str(root),
                      'sources': str(sources), 'device': identity.st_dev, 'inode': identity.st_ino},
            'Source ownership cannot be matched to the exclusively created directory.')
    stage_files_are_regular()
    release = json.loads(regular(stage / 'release/release.json', stage).read_text())
    result = json.loads(regular(stage / 'build-result.json', stage).read_text())
    require(result.get('upstream_release') == release, 'The staged release differs from its completed staging record.')
    expected = release.get('files')
    require(isinstance(expected, dict) and {'droidvm-disk.img', 'os.img', 'systemos.img'} <= expected.keys(),
            'The stage lacks its complete upstream image inventory.')
    for name, row in expected.items():
        require(isinstance(name, str) and Path(name).name == name and isinstance(row, dict),
                'The upstream release file inventory is malformed.')
        path = regular(stage / 'release' / name, stage)
        require(type(row.get('bytes')) is int and row['bytes'] > 0 and path.stat().st_size == row['bytes'],
                'A staged release file differs from its already verified byte count.')
    store = regular(stage / 'release/data-store.img', stage)
    require(type(result.get('data_store_bytes')) is int and result['data_store_bytes'] > 0 and
            store.stat().st_size == result['data_store_bytes'], 'The staged Data store is incomplete.')
    generation = json.loads(regular(stage / 'generation/seed.json', stage).read_text())
    seed = generation.get('seed')
    require(isinstance(seed, str) and Path(seed).name == seed and
            regular(stage / 'generation' / seed, stage).stat().st_size > 0, 'The retained Data seed is incomplete.')
    require(all(generation.get(key) is not None and generation.get(key) == release.get('seed', {}).get(key)
                for key in ('seed', 'seed_sha256', 'volume_uuid')), 'The retained Data generation differs from the release.')
    adjustment = regular(stage / 'source-adjustments.json', stage).read_bytes()
    require(adjustment == regular(root / 'output/source-adjustments.json', root).read_bytes(),
            'The final source-adjustment record is not preserved byte for byte.')
    regular(stage / 'upstream-vm-template.json', stage)

    build_root = Path(sys.argv[2]).resolve(strict=True)
    require(sources in build_root.parents, 'Build metadata is outside the owned sources tree.')
    work = build_root / 'droidvm/ipados-27.0.1-24A446/droidvm_ipados27'
    tree = work / 'tree'
    evidence = stage / 'release/build-evidence'
    evidence.mkdir(exist_ok=True)
    metadata = {
        'unixnu.lock': sources / 'UniXNU-droidvm/ipados27/unixnu.lock',
        'profile.toml': sources / 'UniXNU/profiles/os/ipados-27.0.1-24A446/profile.toml',
        'verified-root-os.json': tree / 'build/verified-root-24A446/OS/verification.json',
        'verified-root-systemos.json': tree / 'build/verified-root-24A446/SystemOS/verification.json',
    }
    plugin = tree / 'build/adreno-metal-plugin27/trust.json'
    if plugin.exists() or plugin.is_symlink():
        metadata['plugin-trust.json'] = plugin
    hashes = {}
    for name, source in metadata.items():
        content = regular(source, sources).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if name == 'unixnu.lock':
            require(digest == release.get('feeds_lock_sha256'), 'The retained feed lock differs from its release digest.')
        destination = evidence / name
        if destination.exists() or destination.is_symlink():
            require(regular(destination, stage).read_bytes() == content, 'Existing retained build evidence differs; it is preserved.')
        else:
            with destination.open('xb') as out:
                out.write(content)
        hashes[name] = digest
    stage_files_are_regular()
    report.update(status='removing', retained_build_evidence_sha256=hashes,
                  retained_source_record_sha256=hashlib.sha256(adjustment).hexdigest(),
                  stage_files_rehashed=False, complete_stage_verified_before_cleanup=True)
    # This exact resolved, non-link directory still has its creation identity.
    # Nested links are unlinked by rmtree; their external targets are not followed.
    shutil.rmtree(sources)
    report['status'] = 'complete'
except Exception as error:
    report.update(status='failed', error_type=type(error).__name__, error=str(error),
                  ownership_receipt_retained=True)
    raise
finally:
    report['free_bytes_after'] = shutil.disk_usage(root).free
    report['filesystem_free_delta_bytes'] = report['free_bytes_after'] - report['free_bytes_before']
    try:
        with tempfile.NamedTemporaryFile('w', prefix='source-cleanup-', suffix='.txt',
                                         dir=diagnostic_directory, delete=False) as out:
            out.write(json.dumps(report, indent=2) + '\n')
    except OSError:
        print('Cleanup diagnostic could not be written; source ownership receipt remains retained.')
print('Owned source tree reclaimed after complete staging; filesystem free-byte observations recorded.')
PY

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
