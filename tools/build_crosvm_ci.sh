#!/usr/bin/env bash
# Build only the standalone Android VMM and its libraries on a disposable Linux
# x86_64 runner. This does not contact a phone or acquire Apple system files.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
META_PIN=4261ef27261763c4eaa505a0ec03019963b52f92
MANIFEST_PIN=8143624b0ff2c37095d296c0f993c64f936a68a9
CROSVM_PIN=c69de01daf50ee8a24adf07e994adf8bcd5825cf
REPO_PIN=e71a8c6dd85026c8861e675ed7ff468fc611df44
SOURCE_LOCK="$ROOT/profiles/crosvm-display-source-lock.json"
SOURCE_LOCK_SHA256=fe63a6eec0ec48abd7a9551a93e1b60b976ee0171b9a18c1a52f93b9ffccb610
UPSTREAM_MANIFEST_SHA256=ffa1c625ef1bc6fc0a49070436207425d556488cf4a84a4b33a6ee3087846082
VIRTUALIZATION_PIN=c8c132c55d7d5932966e8b2f262e2f86d676cbb1
NATIVE_DISPLAY_PATCH="$ROOT/patches/android-display-owner.patch"
NATIVE_DISPLAY_PATCH_SHA256=508c025223e29868eb3e9b1f4638d7f41b869221cfb6802c79949e5a6452fbcc
NATIVE_DISPLAY_SOURCE_SHA256=47d833cf2832ce6c63e4f6e28e6458dd66a3b8d7b2880ca02f7f6e15159e6e61
NATIVE_DISPLAY_FIXED_SHA256=df3a45d4dede4cac0b0d944a04069fad1d374c8da7b4fd0d721d54405fab5986
SHIM_RUST_TOOLCHAIN=1.100.0
SHIM_SHA256=3db0af7122198f1dde9f7fe1ef9794411b519fe153abcc427755f7280078ecad
OUT="$ROOT/output/crosvm"
test ! -e "$OUT" || { echo "Preserve the existing output before a new run: $OUT" >&2; exit 1; }
mkdir -p "$OUT/diagnostics"
if test -f "${RUNNER_TEMP:-/tmp}/crosvm-runner-space.log"; then
  cp "${RUNNER_TEMP:-/tmp}/crosvm-runner-space.log" "$OUT/diagnostics/runner-space.log"
fi
test "$(uname -s)/$(uname -m)" = Linux/x86_64 || { echo 'The official Soong host prebuilts require Linux x86_64.' >&2; exit 1; }
WORK=$(mktemp -d "${RUNNER_TEMP:-/tmp}/droidvm-crosvm.XXXXXX")
META="$WORK/meta"
MANIFEST_SOURCE="$WORK/manifest-source"
LOCKED_MANIFEST="$WORK/locked-manifest"
REPO_SOURCE="$WORK/git-repo"
export OUT ROOT META META_PIN MANIFEST_PIN CROSVM_PIN REPO_PIN LOCKED_MANIFEST MANIFEST_SOURCE
export SOURCE_LOCK SOURCE_LOCK_SHA256 UPSTREAM_MANIFEST_SHA256 VIRTUALIZATION_PIN
export NATIVE_DISPLAY_PATCH NATIVE_DISPLAY_PATCH_SHA256 NATIVE_DISPLAY_SOURCE_SHA256 NATIVE_DISPLAY_FIXED_SHA256
export SHIM_RUST_TOOLCHAIN SHIM_SHA256
export JOBS=${JOBS:-4}
export REPO_JOBS=${REPO_JOBS:-4}
export GOMEMLIMIT=${GOMEMLIMIT:-8GiB}
export GIT_TERMINAL_PROMPT=0

space_report() {
  printf '\n== %s ==\n' "$1"
  df -B1 "$WORK" "$OUT" | tee -a "$OUT/diagnostics/space.log"
  du -sx --block-size=1 "$WORK" | tee -a "$OUT/diagnostics/space.log"
}

finish_report() {
  local status=$?
  printf '%s\n' "$status" > "$OUT/diagnostics/build-exit-code.txt"
  space_report final || true
  # Final diagnostics must be written before their hashes are computed.
  python3 - <<'PY'
import hashlib
import os
from pathlib import Path
out = Path(os.environ['OUT'])
rows = []
for path in sorted(out.rglob('*')):
    if not path.is_file() or path.name == 'SHA256SUMS':
        continue
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            sha.update(part)
    rows.append(f'{sha.hexdigest()}  {path.relative_to(out).as_posix()}\n')
(out / 'SHA256SUMS').write_text(''.join(rows))
PY
}
trap finish_report EXIT

checkout_commit() {
  local url=$1 pin=$2 directory=$3
  git init "$directory"
  git -C "$directory" remote add origin "$url"
  git -C "$directory" fetch --depth 1 origin "$pin"
  git -C "$directory" checkout --detach FETCH_HEAD
  test "$(git -C "$directory" rev-parse HEAD)" = "$pin"
}

space_report before-source
checkout_commit https://github.com/Droid-VM/droidvm-meta-repo.git "$META_PIN" "$META"
checkout_commit https://github.com/Droid-VM/crosvm-minimal-manifest.git "$MANIFEST_PIN" "$MANIFEST_SOURCE"
checkout_commit https://github.com/GerritCodeReview/git-repo.git "$REPO_PIN" "$REPO_SOURCE"

# Reuse the verified 96-project snapshot from the completed original build.
# declared_revision and selected_ref retain its history; only commit selects
# source for this rebuild. No moving branch or tag is resolved again.
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

lock_bytes = Path(os.environ['SOURCE_LOCK']).read_bytes()
if hashlib.sha256(lock_bytes).hexdigest() != os.environ['SOURCE_LOCK_SHA256']:
    raise SystemExit('The retained 96-project source lock differs from the reviewed snapshot.')
lock = json.loads(lock_bytes)
for field, variable in (
    ('meta_commit', 'META_PIN'),
    ('repo_tool_commit', 'REPO_PIN'),
    ('upstream_manifest_commit', 'MANIFEST_PIN'),
):
    if lock[field] != os.environ[variable]:
        raise SystemExit(f'The retained source lock has a different {field}.')
source = Path(os.environ['MANIFEST_SOURCE']) / 'crosvm-minimal.xml'
if hashlib.sha256(source.read_bytes()).hexdigest() != os.environ['UPSTREAM_MANIFEST_SHA256']:
    raise SystemExit('The pinned upstream manifest bytes differ from the verified original input.')
document = ET.parse(source)
root = document.getroot()
defaults = root.find('default').attrib
remotes = {remote.attrib['name']: remote.attrib['fetch'] for remote in root.findall('remote')}
projects = root.findall('project')
resolved = lock['projects']
records = {record['path']: record for record in resolved}
paths = [project.attrib.get('path', project.attrib['name']) for project in projects]
if len(projects) != 96 or len(resolved) != 96 or len(records) != 96 or len(set(paths)) != 96:
    raise SystemExit('The retained source lock and upstream manifest must each own 96 unique projects.')
if set(paths) != set(records):
    raise SystemExit('The retained source lock paths differ from the pinned upstream manifest.')
for project in projects:
    name = project.attrib['name']
    path = project.attrib.get('path', name)
    remote = project.attrib.get('remote', defaults['remote'])
    url = remotes[remote].rstrip('/') + '/' + name
    revision = project.attrib.get('revision', defaults['revision'])
    record = records[path]
    if (record['name'], record['url'], record['declared_revision']) != (name, url, revision):
        raise SystemExit(f'The retained source provenance differs from the upstream manifest for {path}.')
    if not re.fullmatch('[0-9a-f]{40}', record['commit']):
        raise SystemExit(f'Invalid retained source commit for {path}: {record["commit"]}')
    project.set('revision', record['commit'])
    if not re.fullmatch('[0-9a-f]{40}', record['selected_ref']):
        ref = record['selected_ref']
        project.set('upstream', ref if ref.startswith('refs/') else f'refs/heads/{ref}')
for path, variable in (
    ('external/crosvm', 'CROSVM_PIN'),
    ('packages/modules/Virtualization', 'VIRTUALIZATION_PIN'),
):
    if records[path]['commit'] != os.environ[variable]:
        raise SystemExit(f'The retained source lock has a different commit for {path}.')
directory = Path(os.environ['LOCKED_MANIFEST'])
directory.mkdir()
target = directory / 'crosvm-minimal.xml'
target.write_bytes(ET.tostring(root, encoding='utf-8', xml_declaration=True))
if hashlib.sha256(target.read_bytes()).hexdigest() != lock['locked_manifest_sha256']:
    raise SystemExit('The regenerated locked manifest differs from the original completed build.')
out = Path(os.environ['OUT'])
(out / 'source-lock.json').write_bytes(lock_bytes)
print(f'Reused all {len(resolved)} verified source commits without resolving moving refs.')
PY

git -C "$LOCKED_MANIFEST" init -b main
git -C "$LOCKED_MANIFEST" add crosvm-minimal.xml
git -C "$LOCKED_MANIFEST" -c user.name='DroidVM build' -c user.email='build@localhost' \
  commit -m 'build: lock the standalone crosvm source snapshot'
mkdir -p "$META/crosvm_build"
(
  cd "$META/crosvm_build"
  python3 "$REPO_SOURCE/repo" init -u "file://$LOCKED_MANIFEST" -b main \
    -m crosvm-minimal.xml --depth 1 \
    --repo-url https://github.com/GerritCodeReview/git-repo.git --repo-rev "$REPO_PIN" \
    --no-repo-verify
  # Repo's signature verification otherwise selects the nearest signed tag,
  # which can silently replace the explicitly selected source commit.
  test "$(git -C .repo/repo rev-parse HEAD)" = "$REPO_PIN"
  python3 "$REPO_SOURCE/repo" sync -c --no-tags --no-clone-bundle --optimized-fetch \
    --fail-fast -j "$REPO_JOBS" 2>&1 | tee "$OUT/diagnostics/repo-sync.log"
  python3 "$REPO_SOURCE/repo" manifest -r -o "$OUT/source-manifest.xml"
)
ln -s "$META/crosvm_build/external/crosvm" "$META/crosvm"
ln -s "$META/crosvm_build/hardware/google/gfxstream" "$META/gfxstream"
ln -s "$META/crosvm_build/external/virglrenderer" "$META/virglrenderer"
ln -s "$META/crosvm_build/packages/modules/Virtualization" "$META/Virtualization"
space_report after-source

python3 - <<'PY'
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET
out = Path(os.environ['OUT'])
expected = {item['path']: item['commit'] for item in json.loads((out / 'source-lock.json').read_text())['projects']}
actual = {item.attrib.get('path', item.attrib['name']): item.attrib['revision']
          for item in ET.parse(out / 'source-manifest.xml').getroot().findall('project')}
if actual != expected:
    raise SystemExit('The synchronized source commits differ from the locked manifest.')
print('All synchronized project commits match the source lock.')
PY

# The display owner is a cc_library_static linked into crosvm. Apply the
# reviewed source-only patch before the complete Soong build and retain its
# exact patch and before/after source identities with the resulting VMM.
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess

out = Path(os.environ['OUT'])
repository = Path(os.environ['META']) / 'crosvm_build/packages/modules/Virtualization'
commit = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'], text=True).strip()
if commit != os.environ['VIRTUALIZATION_PIN']:
    raise SystemExit('The synchronized Virtualization checkout differs from the reviewed patch base.')
source_path = 'libs/android_display_backend/crosvm_android_display_client.cpp'
source = repository / source_path
before = hashlib.sha256(source.read_bytes()).hexdigest()
if before != os.environ['NATIVE_DISPLAY_SOURCE_SHA256']:
    raise SystemExit('The native display source differs from the reviewed unpatched bytes.')
patch = Path(os.environ['NATIVE_DISPLAY_PATCH'])
patch_bytes = patch.read_bytes()
patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
if patch_sha256 != os.environ['NATIVE_DISPLAY_PATCH_SHA256']:
    raise SystemExit('The native display patch differs from the reviewed final patch.')
command = ['git', '-c', 'core.autocrlf=false', '-C', str(repository), 'apply', '--whitespace=error']
subprocess.run([*command, '--check', str(patch)], check=True)
subprocess.run([*command, str(patch)], check=True)
after = hashlib.sha256(source.read_bytes()).hexdigest()
if after != os.environ['NATIVE_DISPLAY_FIXED_SHA256']:
    raise SystemExit('The patched native display source differs from the reviewed final bytes.')
retained_patch = out / 'diagnostics/android-display-owner.patch'
retained_patch.write_bytes(patch_bytes)
(out / 'native-display-patch.json').write_text(json.dumps({
    'project_path': 'packages/modules/Virtualization',
    'project_url': 'https://github.com/Droid-VM/Virtualization',
    'upstream_commit': commit,
    'source_path': source_path,
    'source_sha256_before': before,
    'source_sha256_after': after,
    'patch': retained_patch.relative_to(out).as_posix(),
    'patch_sha256': patch_sha256,
    'source_lock_snapshot': 'profiles/crosvm-display-source-lock.json',
    'source_lock_snapshot_sha256': os.environ['SOURCE_LOCK_SHA256'],
    'build_linkage': 'libcrosvm_android_display_client (cc_library_static) linked into crosvm',
    'real_android_surface_vulkan_verification': 'not performed by this build',
    'phone_apple_guest_boot_verification': 'not performed by this build',
}, indent=2) + '\n')
print('Applied the reviewed native display patch and verified exact before/after source bytes.')
PY

# Apply only the reviewed VMM source changes to the pinned crosvm tree.
# This worker builds an app runtime; it never contacts or configures a phone.
python3 - <<'PYCODE'
import hashlib
import json
import os
from pathlib import Path
import subprocess
repo = Path(os.environ['META']) / 'crosvm_build/external/crosvm'
root = Path(os.environ['ROOT'])
out = Path(os.environ['OUT'])
manifest = json.loads((root / 'profiles/crosvm-host-policy-source.json').read_text())
patch = root / 'patches/crosvm-host-read-only.patch'
if subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip() != manifest['base_commit']:
    raise SystemExit('The crosvm patch base is not the reviewed commit.')
if hashlib.sha256(patch.read_bytes()).hexdigest() != manifest['patch_sha256']:
    raise SystemExit('The crosvm host policy patch digest differs.')
for row in manifest['files']:
    if hashlib.sha256((repo / row['file']).read_bytes()).hexdigest() != row['pinned_sha256']:
        raise SystemExit('Unexpected unpatched crosvm source: ' + row['file'])
cmd = ['git', '-c', 'core.autocrlf=false', '-C', str(repo), 'apply', '--whitespace=error']
subprocess.run([*cmd, '--check', str(patch)], check=True)
subprocess.run([*cmd, str(patch)], check=True)
for row in manifest['files']:
    if hashlib.sha256((repo / row['file']).read_bytes()).hexdigest() != row['final_lf_sha256']:
        raise SystemExit('Unexpected patched crosvm source: ' + row['file'])
(out / 'diagnostics/crosvm-host-read-only.patch').write_bytes(patch.read_bytes())
(out / 'host-policy-source.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('Verified and applied the reviewed VMM host read-only policy.')
PYCODE

# The shim is a separate bare-metal crate; Soong uses its own Rust prebuilts.
rustup toolchain install "$SHIM_RUST_TOOLCHAIN" --profile minimal --target aarch64-unknown-none-softfloat
export RUSTUP_TOOLCHAIN="$SHIM_RUST_TOOLCHAIN"
rustc --version | tee "$OUT/diagnostics/shim-rustc-version.txt"
cargo --version | tee "$OUT/diagnostics/shim-cargo-version.txt"
space_report before-build
(
  cd "$META"
  /usr/bin/time -v bash ./2_build_crosvm.sh
) 2>&1 | tee "$OUT/diagnostics/crosvm-build.log"
space_report after-build

# Retain every direct and transitive library collected by the official recipe,
# including platform libraries that will be excluded from the runtime overlay.
# This collection does not build an APK or host kernel modules.
(
  cd "$META/crosvm_build"
  bash ../2-1_collect_crosvm.sh "$OUT/full-build" --deep
) 2>&1 | tee "$OUT/diagnostics/crosvm-collect.log"
git -C "$META/crosvm_build/external/boringssl" diff --binary \
  > "$OUT/diagnostics/boringssl-build.patch"

# Keep the matching non-platform runtime libraries. The platform shadow list is
# the policy of this pinned meta repo's 6_build_apk_prepare.sh: those libraries
# are supplied by Android, and shipping a duplicate can break its own consumers.
# Apply the local linker-stub exclusion as well; full-build still retains the
# original collected file and its checksum as build evidence.
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(os.environ['ROOT']) / 'tools'))
from fetch_runtime import digest, inspect_embedded_flags
from runtime_payload_policy import EXCLUDED_LINK_STUB_NAMES, RUNTIME_PAYLOAD_POLICY_SOURCE

meta = Path(os.environ['META'])
out = Path(os.environ['OUT'])
source = meta / 'crosvm_out'
complete = out / 'full-build'
runtime = out / 'runtime'
binary = complete / 'crosvm'
if not binary.is_file():
    raise SystemExit('The official collection did not produce full-build/crosvm.')
if digest(binary) != digest(source / 'crosvm'):
    raise SystemExit('The deep collection selected a different VMM from the official build.')
shim = out / 'shim'
shim.mkdir()
for name in ('shim.elf', 'shim.bin'):
    shutil.copy2(meta / 'crosvm_build/out/shim' / name, shim / name)
shim_bytes = (shim / 'shim.bin').read_bytes()
if not shim_bytes or shim_bytes != (meta / 'crosvm/hypervisor/src/gunyah/shim.bin').read_bytes():
    raise SystemExit('The retained shim differs from the VMM include_bytes! input.')
shim_sha256 = hashlib.sha256(shim_bytes).hexdigest()
if shim_sha256 != os.environ['SHIM_SHA256']:
    raise SystemExit('The rebuilt shim bytes differ from the original verified Apple/Gunyah shim.')
markers = inspect_embedded_flags(binary)
additional = {'mbi-spis': b'mbi-spis', 'host-memory-policy': b'host-memory-policy', 'embedded-shim': shim_bytes}
observed = {name: False for name in additional}
overlap = max(map(len, additional.values())) - 1
tail = b''
with binary.open('rb') as stream:
    for part in iter(lambda: stream.read(4 * 1024 * 1024), b''):
        data = tail + part
        for name, value in additional.items():
            observed[name] |= value in data
        tail = data[-overlap:] if overlap else b''
markers['mbi-spis'] = observed['mbi-spis']
markers['host-memory-policy'] = observed['host-memory-policy']
(out / 'static-options.json').write_text(json.dumps(markers, indent=2) + '\n')
missing = [name for name, found in markers.items() if not found]
if missing:
    raise SystemExit(f'The newly built VMM lacks required guest option strings: {missing}')
if not observed['embedded-shim']:
    raise SystemExit('The VMM does not contain the retained freshly built shim bytes.')
elf = subprocess.check_output(['readelf', '-h', str(binary)], text=True)
if 'AArch64' not in elf:
    raise SystemExit('The standalone device VMM is not AArch64.')
platform = {name + '.so' for name in (
    'libgui', 'libaaudio', 'libbinder_ndk', 'libc++', 'libbase', 'libcap',
    'libcutils', 'liblog', 'libminijail', 'libnativewindow', 'libprocessgroup')}
platform.update(EXCLUDED_LINK_STUB_NAMES)
files = [(binary, runtime / 'usr/bin/crosvm')]
files += [(path, runtime / 'usr/lib' / path.name)
          for path in sorted(complete.glob('*.so')) if path.name not in platform]
if len(files) != 71:
    raise SystemExit(f'The pinned runtime payload changed: {len(files)} files, expected 71.')
for original, target in files:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original, target)
dynamic = subprocess.check_output(['readelf', '-d', str(binary)], text=True)
report = {
    'meta_commit': os.environ['META_PIN'],
    'crosvm_commit': os.environ['CROSVM_PIN'],
    'build_target': 'crosvm_device_only / aosp_arm64 trunk_staging eng',
    'max_build_jobs': int(os.environ['JOBS']),
    'shim_rust_toolchain_selection': os.environ['SHIM_RUST_TOOLCHAIN'],
    'shim_sha256': shim_sha256,
    'shim_expected_sha256': os.environ['SHIM_SHA256'],
    'shim_rustc_version': (out / 'diagnostics/shim-rustc-version.txt').read_text().strip(),
    'shim_cargo_version': (out / 'diagnostics/shim-cargo-version.txt').read_text().strip(),
    'source_lock': 'source-lock.json',
    'source_lock_snapshot': 'profiles/crosvm-display-source-lock.json',
    'source_lock_snapshot_sha256': os.environ['SOURCE_LOCK_SHA256'],
    'source_lock_reused_without_ref_resolution': True,
    'synchronized_manifest': 'source-manifest.xml',
    'native_display_patch': json.loads((out / 'native-display-patch.json').read_text()),
    'host_policy_source': json.loads((out / 'host-policy-source.json').read_text()),
    'platform_library_policy_source': 'droidvm-meta-repo/6_build_apk_prepare.sh at the meta_commit',
    'local_runtime_policy_source': RUNTIME_PAYLOAD_POLICY_SOURCE,
    'excluded_link_stubs': sorted(path.name for path in complete.glob('*.so')
                                 if path.name in EXCLUDED_LINK_STUB_NAMES),
    'omitted_platform_libraries': sorted(path.name for path in complete.glob('*.so') if path.name in platform),
    'full_build_files': {path.relative_to(out).as_posix(): digest(path)
                         for directory in (complete, shim) for path in sorted(directory.iterdir()) if path.is_file()},
    'runtime_files': {target.relative_to(out).as_posix(): digest(target) for original, target in files},
    'runtime_file_count': len(files),
    'crosvm_embedded_option_names': markers,
    'retained_shim_embedded_in_crosvm': observed['embedded-shim'],
    'collection_scope': 'official direct and transitive DT_NEEDED collection (--deep); bionic libc/libdl/libm are provided by Android',
    'runtime_overlay_policy': 'non-platform implementation libraries only; Android linker stubs excluded; full-build and shim are retained evidence, not a phone installation payload',
    'aosp_build_patch': 'diagnostics/boringssl-build.patch',
    'static_elf_header': elf,
    'static_dynamic_section': dynamic,
    'android_loader_verification': 'not performed',
    'phone_apple_guest_boot_verification': 'not performed',
    'space_measurements': 'diagnostics/space.log',
    'time_measurement_limit': 'GNU time reports its command and child maximum RSS; it is not simultaneous process-family peak memory',
}
(out / 'crosvm-build.json').write_text(json.dumps(report, indent=2) + '\n')
print('Verified required VMM option strings and the embedded shim; Android loading and phone boot still require verification.')
PY
