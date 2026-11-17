#!/usr/bin/env bash
# Build only the standalone Android VMM and its libraries on a disposable Linux
# x86_64 runner. This does not contact a phone or acquire Apple system files.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
META_PIN=4261ef27261763c4eaa505a0ec03019963b52f92
MANIFEST_PIN=8143624b0ff2c37095d296c0f993c64f936a68a9
CROSVM_PIN=c69de01daf50ee8a24adf07e994adf8bcd5825cf
REPO_PIN=e71a8c6dd85026c8861e675ed7ff468fc611df44
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

# Resolve the official manifest once, before downloading source. Fixed fork
# choices follow the reviewed wip/hackintosh -> droidvm branch chain. AOSP
# branch revisions are resolved for this run and their exact commits are retained.
python3 - <<'PY'
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

source = Path(os.environ['MANIFEST_SOURCE']) / 'crosvm-minimal.xml'
document = ET.parse(source)
root = document.getroot()
defaults = root.find('default').attrib
remotes = {remote.attrib['name']: remote.attrib['fetch'] for remote in root.findall('remote')}
pins = {
    'external/crosvm': ('wip/hackintosh', os.environ['CROSVM_PIN']),
    'hardware/google/gfxstream': ('droidvm', 'cbc6df3b11b3eac8fb13d89e0a542f763b3bdfcc'),
    'external/virglrenderer': ('wip/hackintosh', '2529a9f77a1a3f9cd41d50b9174d2e41ea1b75dd'),
    'packages/modules/Virtualization': ('wip/hackintosh', 'c8c132c55d7d5932966e8b2f262e2f86d676cbb1'),
    'external/libvncserver': ('droidvm', '082e869d0e6e2441b810fc9877bce1acd30f9393'),
    'external/zstd': ('droidvm', '0552a06f6a0b50cdeed444534810741a670d6d46'),
    'external/virtio-media': ('wip/hackintosh', '3fe8fb594f5761c4d70d0f05781af23f42b47698'),
    'external/rust/crates/v4l2r': ('wip/hackintosh', '7eb3afa6c4ff7d795394ad09dece6099b4e6a38e'),
    'build/soong': ('android16-qpr2-release', 'c2db5181e9e1b6a383f6e858fb39b3db26aba7e7'),
}
projects = root.findall('project')
if len(projects) != 96:
    raise SystemExit(f'The reviewed minimal manifest changed: {len(projects)} projects, expected 96')
paths = {project.attrib.get('path', project.attrib['name']) for project in projects}
if not pins.keys() <= paths:
    raise SystemExit(f'Pinned projects missing from manifest: {sorted(pins.keys() - paths)}')

def resolve(project):
    name = project.attrib['name']
    path = project.attrib.get('path', name)
    remote = project.attrib.get('remote', defaults['remote'])
    url = remotes[remote].rstrip('/') + '/' + name
    revision = project.attrib.get('revision', defaults['revision'])
    if path in pins:
        selected_ref, commit = pins[path]
    elif re.fullmatch('[0-9a-f]{40}', revision):
        selected_ref, commit = revision, revision
    else:
        refs = [revision, f'refs/heads/{revision}', f'refs/tags/{revision}', f'refs/tags/{revision}^{{}}']
        result = subprocess.run(['git', 'ls-remote', '--exit-code', url, *refs],
                                text=True, capture_output=True, timeout=90, check=True)
        rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
        peeled = [sha for sha, ref in rows if ref.endswith('^{}')]
        choices = set(peeled or [sha for sha, ref in rows])
        if len(choices) != 1:
            raise SystemExit(f'Cannot select one commit for {url} at {revision}: {sorted(choices)}')
        selected_ref, commit = revision, choices.pop()
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise SystemExit(f'Invalid source commit for {path}: {commit}')
    return {'path': path, 'name': name, 'url': url, 'declared_revision': revision,
            'selected_ref': selected_ref, 'commit': commit}

with ThreadPoolExecutor(max_workers=int(os.environ['REPO_JOBS'])) as workers:
    resolved = list(workers.map(resolve, projects))
for project, record in zip(projects, resolved):
    project.set('revision', record['commit'])
    if not re.fullmatch('[0-9a-f]{40}', record['selected_ref']):
        ref = record['selected_ref']
        project.set('upstream', ref if ref.startswith('refs/') else f'refs/heads/{ref}')
directory = Path(os.environ['LOCKED_MANIFEST'])
directory.mkdir()
target = directory / 'crosvm-minimal.xml'
document.write(target, encoding='utf-8', xml_declaration=True)
out = Path(os.environ['OUT'])
(out / 'source-lock.json').write_text(json.dumps({
    'meta_commit': os.environ['META_PIN'],
    'repo_tool_commit': os.environ['REPO_PIN'],
    'upstream_manifest_commit': os.environ['MANIFEST_PIN'],
    'locked_manifest_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
    'scope': '96-project standalone Android crosvm tree; no guest Mesa/additions or Apple files',
    'projects': resolved,
}, indent=2) + '\n')
print(f'Locked all {len(resolved)} source projects before synchronization.')
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

# The shim is a separate bare-metal crate; Soong uses its own Rust prebuilts.
rustup toolchain install stable --profile minimal --target aarch64-unknown-none-softfloat
export RUSTUP_TOOLCHAIN=stable
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
python3 - <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(os.environ['ROOT']) / 'tools'))
from fetch_runtime import digest, inspect_embedded_flags

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
markers = inspect_embedded_flags(binary)
additional = {'mbi-spis': b'mbi-spis', 'embedded-shim': shim_bytes}
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
files = [(binary, runtime / 'usr/bin/crosvm')]
files += [(path, runtime / 'usr/lib' / path.name)
          for path in sorted(complete.glob('*.so')) if path.name not in platform]
for original, target in files:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original, target)
dynamic = subprocess.check_output(['readelf', '-d', str(binary)], text=True)
report = {
    'meta_commit': os.environ['META_PIN'],
    'crosvm_commit': os.environ['CROSVM_PIN'],
    'build_target': 'crosvm_device_only / aosp_arm64 trunk_staging eng',
    'max_build_jobs': int(os.environ['JOBS']),
    'shim_rust_toolchain_selection': 'stable, resolved and recorded on this runner',
    'shim_rustc_version': (out / 'diagnostics/shim-rustc-version.txt').read_text().strip(),
    'shim_cargo_version': (out / 'diagnostics/shim-cargo-version.txt').read_text().strip(),
    'source_lock': 'source-lock.json',
    'synchronized_manifest': 'source-manifest.xml',
    'platform_library_policy_source': 'droidvm-meta-repo/6_build_apk_prepare.sh at the meta_commit',
    'omitted_platform_libraries': sorted(path.name for path in complete.glob('*.so') if path.name in platform),
    'full_build_files': {path.relative_to(out).as_posix(): digest(path)
                         for directory in (complete, shim) for path in sorted(directory.iterdir()) if path.is_file()},
    'runtime_files': {target.relative_to(out).as_posix(): digest(target) for original, target in files},
    'crosvm_embedded_option_names': markers,
    'retained_shim_embedded_in_crosvm': observed['embedded-shim'],
    'collection_scope': 'official direct and transitive DT_NEEDED collection (--deep); bionic libc/libdl/libm are provided by Android',
    'runtime_overlay_policy': 'non-platform libraries only; full-build and shim are retained evidence, not a phone installation payload',
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
