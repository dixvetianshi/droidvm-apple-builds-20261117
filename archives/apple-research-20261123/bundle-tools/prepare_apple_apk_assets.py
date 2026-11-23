#!/usr/bin/env python3
"""Merge the verified Apple runtime into a separate r242 APK's pinned assets.

The original DroidVM checkout and its runtime stay unchanged. Every original
member and every overlay member is checked before the merged assets are staged.
The matching manifest is generated from the bytes actually packaged.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

from runtime_payload_policy import RUNTIME_PAYLOAD_POLICY_SOURCE
from runtime_artifact import (HOST_POLICY_PROVENANCE_FILES, APPLE10_SOURCE_LINEAGE,
                              ORIGINAL_SHIM_SHA256, SOURCE_LOCK_SHA256, load_completed_runtime,
                              object_from, reviewed_host_policy, sha256_file, sha256_value, validate_host_policy_source,
                              validate_native_display_patch, validate_apple10_runtime_asset_owner, apple10_source_manifest)
from verify_vmpkg import validate_archive_path

ROOT = Path(__file__).resolve().parents[1]
APK = ROOT / "sources/DroidVM-Apple"
PREBUILTS = APK / "app/src/main/assets/prebuilts"
BACKUP = ROOT / "verification/backups/apple-apk-prebuilt-20261118"
ASSET_NAMES = ("prebuilt-arm64-v8a.tar.xz", "prebuilt-arm64-v8a.json")
APPLICATION_ID = "cn.classfun.droidvm.apple"

# An App asset overlay, separate from the unchanged 71-member Apple8 native build.
HOSTSHARE_COMPONENT = {
    "name": "host-share-only-clean-v3",
    "member": "usr/lib/modules/android15-6.6/gunyah-host-share-gki-6.6.ko",
    "source": "output/apple-on-demand-capability-proposal-20261122/hostshare-source-review/ci-candidate/ci44993802890-meta/artifact-14742682099-reviewed-members/component/gunyah-host-share-gki-6.6.ko",
    "bytes": 37056,
    "sha256": "709c749da1741108bc3df1593847ee54e696f6d8503297b837445fe9461e2207",
    "source_repository": "https://github.com/Droid-VM/gunyah_host_mod",
    "source_commit": "44e8ae5a088a3a35290a5cacb205640cff187b99",
    "source_removal_patch_sha256": "058ca1463c09f484cd401c3906088ecfd15545c9f24781a8cc96a177c234beaf",
    "ddk_image": "ghcr.io/ylarod/ddk-min@sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2",
    "ci_run_id": 44993802890,
    "ci_head_sha": "f13bf2f1ddf471834c14ba3e6038c7fae2960848",
    "artifact_id": 14742682099,
    "artifact_zip_sha256": "48afb2fc37ecfbda3480d82858aa0ce7fbfc27534f1cf101c7333dc92ae243c1",
    "clean_scope": "Exact newly built KO only; READY providers may have old or unknown origin",
    "phone_abi_verified": False,
}

# This fixed component belongs to Apple10 only. Apple9 retains its clean-v3 KO.
HOSTSHARE_LEASE_COMPONENT = {
    "name": "host-share-lease-v1",
    "member": "usr/lib/modules/android15-6.6/gunyah-host-share-gki-6.6.ko",
    "source": "output/apple-on-demand-capability-proposal-20261122/hostshare-lease-ci45029535267/extracted/hostshare-lease-component/component/gunyah-host-share-gki-6.6.ko",
    "bytes": 55720,
    "sha256": "1a9555640c7aee58e26c21baa18780e40c31edb8ae7cdd9009ca67a84892a53f",
    "source_repository": "https://github.com/Droid-VM/gunyah_host_mod",
    "source_commit": "44e8ae5a088a3a35290a5cacb205640cff187b99",
    "source_removal_patch_sha256": "058ca1463c09f484cd401c3906088ecfd15545c9f24781a8cc96a177c234beaf",
    "lease_patch_sha256": "d8ee4c2c95bf137380e2eb052a4be527b4617e68b202949810809867e31a5098",
    "source_manifest_sha256": "3126f84cc32989db28ded2a61bf386f2c9cf437cf331556553e38aa7e263daf9",
    "lease_uapi_sha256": "b2f34317da73b49867263bd664c969be1ce74bd33dad693a13ddaeb615c07a48",
    "ddk_image": "ghcr.io/ylarod/ddk-min@sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2",
    "ci_run_id": 45029535267,
    "ci_head_sha": "bdc560600c69be57f24ab6f5624721dbc77f68f2",
    "artifact_id": 14756578640,
    "artifact_zip_bytes": 1756750,
    "artifact_zip_sha256": "1f3110d714d8ad2d5576ae0c8fd905a44523be07d9d9ad0c948d25a996fbd068",
    "acceptance_record": "output/apple-on-demand-capability-proposal-20261122/hostshare-lease-ci45029535267/acceptance-receipt.json",
    "acceptance_record_sha256": "647ab09ae629b9b4d8789651ad20bcfc03ffeee2476a309f9ee5c9d2ac6b9857",
    "build_result": "output/apple-on-demand-capability-proposal-20261122/hostshare-lease-ci45029535267/extracted/hostshare-lease-component/result.json",
    "build_result_sha256": "6d9ec918181c2303c14615bae15f04d850802cfbb04eddd5b1c319732e520fbe",
    "phone_abi_verified": False,
    "independent_c_source_review": "pending",
}


MACOS_PSCI_COMPONENT = {'name': 'macos-27.2-psci-kc', 'member': 'usr/share/droidvm/apple/macos-27.2-psci-kc.bin', 'source': 'output/macos-psci-kernel-44981872045/out/k27/kc-k27.bin', 'bytes': 89866240, 'sha256': '1d38f4aa320d2cefe4a6a839c925ef1869b4368d128fd1bc888acbed1682b516', 'ci_run_id': 44981872045, 'ci_head_sha': '313166ae274a469dd4aca855efd25c855de54bb2', 'artifact_id': 14738256207, 'extraction_record': 'output/macos-psci-kernel-44981872045/extraction-record.json', 'extraction_record_sha256': 'f22a0c0829e49cb385933368d43a539dd8fb74ba052ad7ab007c2a4f4e625c16', 'scope': 'Fixed raw kernel resource only; original package pins retained; native build owner verified separately'}


ASSET_RELEASES = {
    "apple2": {"display_patch": False, "host_policy_review": None, "paths": {
        "runtime_dir": "output/crosvm-builds",
        "previous_record": "verification/apple-apk-runtime-assets-20261118.json",
        "previous_backup": "verification/backups/apple-apk-prebuilt-apple1-20261119",
        "work": "output/apk-runtime-merge-apple2",
        "record": "verification/apple-apk-runtime-assets-20261119.json"}},
    "apple5": {"display_patch": True, "host_policy_review": None, "paths": {
        "runtime_dir": "output/crosvm-builds-apple5",
        "previous_record": "verification/apple-apk-runtime-assets-20261119.json",
        "previous_backup": "verification/backups/apple-apk-prebuilt-apple4-20261120",
        "work": "output/apk-runtime-merge-apple5",
        "record": "verification/apple5-apk-runtime-assets-20261120.json"}},
    "apple7": {"display_patch": True, "host_policy_review": "apple7", "paths": {
        "runtime_dir": "output/crosvm-builds-apple7",
        "previous_record": "verification/apple5-apk-runtime-assets-20261120.json",
        "previous_backup": "verification/backups/apple-apk-prebuilt-apple6-20261122",
        "work": "output/apk-runtime-merge-apple7",
        "record": "verification/apple7-apk-runtime-assets-20261122.json"}},
    "apple8": {"display_patch": True, "host_policy_review": "apple8", "paths": {
        "runtime_dir": "output/crosvm-builds-apple8",
        "previous_record": "verification/apple7-apk-runtime-assets-20261122.json",
        "previous_backup": "verification/backups/apple-apk-prebuilt-apple7-20261122",
        "work": "output/apk-runtime-merge-apple8",
        "record": "verification/apple8-apk-runtime-assets-20261122.json"}},
    "apple9": {"display_patch": True, "host_policy_review": "apple8",
               "hostshare_component": HOSTSHARE_COMPONENT, "paths": {
        "runtime_dir": "output/crosvm-builds-apple8",
        "previous_record": "verification/apple8-apk-runtime-assets-20261122.json",
        "previous_backup": "verification/backups/apple-apk-prebuilt-apple8-20261122",
        "work": "output/apk-runtime-merge-apple9",
        "record": "verification/apple9-apk-runtime-assets-20261122.json"}},
}

ASSET_RELEASES["apple10"] = {
    "display_patch": True, "host_policy_review": "apple10",
    "hostshare_component": HOSTSHARE_LEASE_COMPONENT, "macos_boot_component": MACOS_PSCI_COMPONENT,
    "paths": {
        "runtime_dir": "output/crosvm-builds-apple10",
        "previous_record": "verification/apple9-apk-runtime-assets-20261122.json",
        "previous_backup": "verification/backups/apple-apk-prebuilt-apple9-20261122",
        "work": "output/apk-runtime-merge-apple10",
        "record": "verification/apple10-apk-runtime-assets-20261122.json",
    },
}

# App and runtime editions differ when an app-only update reuses native assets.
# The asset and signer consumers use this one release declaration.
APK_RELEASES = {
    "apple4": {"day": "20261119", "version_code": None, "runtime_edition": "apple2", "import_helpers": False},
    "apple5": {"day": "20261120", "version_code": 2725, "runtime_edition": "apple5", "import_helpers": True},
    "apple6": {"day": "20261120", "version_code": 2726, "runtime_edition": "apple5", "import_helpers": True},
    "apple7": {"day": "20261122", "version_code": 2727, "runtime_edition": "apple7", "import_helpers": True},
    "apple8": {"day": "20261122", "version_code": 2728, "runtime_edition": "apple8", "import_helpers": True},
    "apple9": {"day": "20261122", "version_code": 2729, "runtime_edition": "apple9", "import_helpers": True},
}


APK_RELEASES["apple10"] = {"day": "20261122", "version_code": 2730, "runtime_edition": "apple10", "import_helpers": True}

def edition_paths(edition):
    if edition not in ASSET_RELEASES:
        raise ValueError("Unsupported runtime asset edition")
    return {name: ROOT / path for name, path in ASSET_RELEASES[edition]["paths"].items()}


def asset_hashes(value, label):
    if not isinstance(value, dict) or set(value) != set(ASSET_NAMES):
        raise ValueError(f"The {label} must own exactly the runtime archive and JSON hashes")
    return {name: sha256_value(value[name], name) for name in ASSET_NAMES}


def manifest_member_hashes(raw):
    manifest = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("hash"), list):
        raise ValueError("The prebuilt manifest must own its member hash list")
    hashes = {}
    for row in manifest["hash"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid prebuilt manifest member")
        name = validate_archive_path(row.get("file"), "prebuilt manifest member")
        if name in hashes:
            raise ValueError("Duplicate prebuilt manifest member")
        hashes[name] = sha256_value(row.get("sha256"), name)
    if not hashes:
        raise ValueError("The prebuilt manifest is empty")
    return hashes


def validate_merged_record(record):
    if not isinstance(record, dict):
        raise ValueError("The merged asset record must be an object")
    asset_hashes(record.get("merged_assets_sha256"), "merged asset record")
    hashes = record.get("merged_member_sha256")
    if not isinstance(hashes, dict) or not hashes:
        raise ValueError("The merged asset record must own all member hashes")
    for name, expected in hashes.items():
        validate_archive_path(name, "merged asset member")
        sha256_value(expected, name)
    if record.get("merged_regular_members") != len(hashes) \
            or record.get("merged_tar_and_all_members_verified") is not True \
            or record.get("apk_application_id") != APPLICATION_ID:
        raise ValueError("The completed merged asset record is inconsistent")
    edition = record.get("apk_edition")
    release = ASSET_RELEASES.get(edition) if isinstance(edition, str) else None
    if release and release["display_patch"]:
        validate_native_display_patch(record.get("native_display_patch"),
                                      review="apple10" if edition == "apple10" else None)
        if record.get("source_lock_sha256") != SOURCE_LOCK_SHA256 \
                or record.get("shim_sha256") != ORIGINAL_SHIM_SHA256 \
                or edition != "apple10" and record.get("apple_runtime_members") != 71:
            if edition == "apple10":
                raise ValueError("Apple10 must retain the original source lock and matching shim")
            raise ValueError("The native asset record must retain the source lock, shim and 71-member runtime")
    if release and release["host_policy_review"]:
        review = release["host_policy_review"]
        # Existing Apple7 records predate this explicit selection field. Their
        # complete original manifest remains bound to the Apple7 declaration.
        if record.get("host_policy_review", review if review == "apple7" else None) != review:
            raise ValueError("Asset record host policy review differs from its edition")
        validate_host_policy_source(record.get("host_policy_source"), review=review)
        sha256_value(record.get("host_policy_source_sha256"), "native host policy source record")
        if record.get("host_policy_patch_sha256") != reviewed_host_policy(review).patch_sha256:
            raise ValueError("The asset record must retain its reviewed host read-only patch")
    if edition == "apple10":
        if record.get("host_policy_source_sha256") != APPLE10_SOURCE_LINEAGE["host"][1]:
            raise ValueError("Apple10 must retain its exact fourteen-file source manifest digest")
        validate_apple10_runtime_asset_owner(record)
        if record.get("paired_app_aidl_sha256") != apple10_source_manifest("display")["paired_aidl_sha256"]:
            raise ValueError("Apple10 must retain the exact paired App/native AIDL digest")
    component = release.get("hostshare_component") if release else None
    if component and (record.get("hostshare_component") != component
                      or hashes.get(component["member"]) != component["sha256"]):
        raise ValueError("The asset record must select the exact reviewed clean HostShare component")
    mac_component = release.get("macos_boot_component") if release else None
    if mac_component and (record.get("macos_boot_component") != mac_component
                          or hashes.get(mac_component["member"]) != mac_component["sha256"]):
        raise ValueError("The asset record must retain the exact accepted raw macOS PSCI KC")
    return record


def merged_record(path):
    return validate_merged_record(object_from(path))


def verify_runtime_archive(stream, expected):
    """Check the exact regular member set and bytes with bounded streaming reads."""
    verified = {}
    with tarfile.open(fileobj=stream, mode="r|xz") as archive:
        for entry in archive:
            name = validate_archive_path(entry.name, "merged archive member")
            if not entry.isfile() or name in verified or name not in expected:
                raise ValueError("Merged archive member coverage differs")
            with archive.extractfile(entry) as incoming:
                measured = hashlib.file_digest(incoming, "sha256").hexdigest()
            if measured != expected[name]:
                raise ValueError("Merged archive member checksum mismatch: " + name)
            verified[name] = measured
    if verified != expected:
        raise ValueError("Merged archive content or coverage mismatch")
    return len(verified)


def verify_asset_pair(record, directory):
    if any(sha256_file(directory / name) != expected
           for name, expected in record["merged_assets_sha256"].items()):
        raise ValueError("Existing merged asset record differs; preserve and reassess")
    if manifest_member_hashes((directory / ASSET_NAMES[1]).read_bytes()) != record["merged_member_sha256"]:
        raise ValueError("Existing manifest and merged member record differ")
    with (directory / ASSET_NAMES[0]).open("rb") as stream:
        return verify_runtime_archive(stream, record["merged_member_sha256"])


def verify_staged_assets(edition):
    if edition == "apple10":
        verify_apple10_app_aidl(ROOT)
    record = merged_record(edition_paths(edition)["record"])
    if record.get("apk_edition") != edition:
        raise ValueError("Existing asset record belongs to a different edition")
    return verify_asset_pair(record, PREBUILTS)


def verify_apple10_app_aidl(root):
    """Require the matching source API before the new native asset is staged."""
    path = root / "sources/DroidVM-Apple/app/src/main/aidl/android/crosvm/ICrosvmAndroidDisplayService.aidl"
    digest = apple10_source_manifest("display")["paired_aidl_sha256"]
    if sha256_file(path) != digest:
        raise ValueError("Apple10 requires the exact paired App/native owned-display AIDL source")
    return digest


def verify_hostshare_lease_receipts(root, component):
    """Read the accepted Linux build facts; no module or target is executed."""
    for filename, digest in ((component["acceptance_record"], component["acceptance_record_sha256"]),
                             (component["build_result"], component["build_result_sha256"])):
        if sha256_file(root / filename) != digest:
            raise ValueError("Apple10 HostShare accepted build receipt bytes changed")
    acceptance = object_from(root / component["acceptance_record"])
    built = object_from(root / component["build_result"])
    if acceptance.get("api_size_and_digest_matched") is not True \
            or acceptance.get("module_sha256") != component["sha256"] \
            or acceptance.get("module_bytes") != component["bytes"] \
            or acceptance.get("head_sha") != component["ci_head_sha"] \
            or acceptance.get("artifact_id") != component["artifact_id"] \
            or acceptance.get("archive_bytes") != component["artifact_zip_bytes"] \
            or acceptance.get("archive_sha256") != component["artifact_zip_sha256"] \
            or built.get("status") != "built_and_static_verified" or built.get("compiled") is not True \
            or built.get("module_sha256") != component["sha256"] \
            or built.get("module_bytes") != component["bytes"] \
            or built.get("lease_patch_sha256") != component["lease_patch_sha256"] \
            or built.get("manifest_sha256") != component["source_manifest_sha256"] \
            or built.get("uapi_sha256") != component["lease_uapi_sha256"] \
            or built.get("source_harnesses_executed") is not True \
            or built.get("source_harnesses", {}).get("command_exit_code") != 0 \
            or built.get("source_harnesses", {}).get("scenario_invocations_completed") != 22:
        raise ValueError("Apple10 HostShare accepted build provenance differs")


def merge_assets(edition, runtime_dir, previous_record):
    paths = edition_paths(edition)
    release = ASSET_RELEASES[edition]
    if edition == "apple10":
        verify_apple10_app_aidl(ROOT)
    work, record_path, previous_backup = paths["work"], paths["record"], paths["previous_backup"]
    if record_path.exists():
        existing = merged_record(record_path)
        if existing.get("apk_edition") != edition:
            raise ValueError("Existing asset record belongs to a different edition")
        if release["display_patch"] and existing.get("runtime_directory") != str(runtime_dir.resolve()):
            raise ValueError("Existing asset record selected a different runtime directory")
        verify_asset_pair(existing, PREBUILTS)
        print(json.dumps({"ok": True, "operation": "existing_assets_verified", "files": existing["merged_regular_members"]}, ensure_ascii=True))
        return
    if work.exists() or previous_backup.exists():
        raise FileExistsError("Existing merge work or previous edition backup is preserved")
    runtime = load_completed_runtime(runtime_dir, require_display_patch=release["display_patch"],
                                     require_host_policy=release["host_policy_review"] is not None,
                                     host_policy_review=release["host_policy_review"])
    if release["host_policy_review"] and runtime.host_policy_review != release["host_policy_review"]:
        raise ValueError("Completed runtime selected a different host policy review")
    component = release.get("hostshare_component")
    component_source = ROOT / component["source"] if component else None
    if component and (component_source.is_symlink() or not component_source.is_file()
                      or component_source.stat().st_size != component["bytes"]
                      or sha256_file(component_source) != component["sha256"]):
        raise ValueError("Expected the exact regular reviewed clean HostShare input")
    if edition == "apple10":
        verify_hostshare_lease_receipts(ROOT, component)
    mac_component = release.get("macos_boot_component")
    mac_source = ROOT / mac_component["source"] if mac_component else None
    if mac_component:
        if (mac_source.is_symlink() or not mac_source.is_file()
                or mac_source.stat().st_size != mac_component["bytes"]
                or sha256_file(mac_source) != mac_component["sha256"]):
            raise ValueError("Expected the exact regular accepted raw macOS PSCI KC input")
        extraction_path = ROOT / mac_component["extraction_record"]
        if sha256_file(extraction_path) != mac_component["extraction_record_sha256"]:
            raise ValueError("The accepted macOS PSCI KC extraction record changed")
        extraction = object_from(extraction_path)
        if (extraction.get("status") != "complete" or extraction.get("kind") != "macos-kernel"
                or extraction.get("archive_integrity_verified") is not True
                or len(extraction.get("files", [])) != 1
                or extraction["files"][0].get("sha256") != mac_component["sha256"]):
            raise ValueError("The accepted macOS PSCI KC extraction provenance differs")
    previous = merged_record(previous_record)
    originals = asset_hashes(previous.get("base_prebuilt_assets_sha256"), "original asset record")
    for name in ASSET_NAMES:
        source = PREBUILTS / name
        if sha256_file(BACKUP / name) != originals[name]:
            raise ValueError("Original asset backup mismatch")
        if sha256_file(source) != previous["merged_assets_sha256"][name]:
            raise ValueError("Previous APK asset bytes changed; preserve and reassess")
    original_hashes = manifest_member_hashes((BACKUP / ASSET_NAMES[1]).read_bytes())
    previous_backup.mkdir(parents=True)
    for name in ASSET_NAMES:
        shutil.copy2(PREBUILTS / name, previous_backup / name)
        if sha256_file(previous_backup / name) != previous["merged_assets_sha256"][name]:
            raise ValueError("Previous APK asset backup mismatch")
    work.mkdir()
    base = work / "members"
    base.mkdir()
    modes = {}
    with tarfile.open(BACKUP / ASSET_NAMES[0], "r|xz") as archive:
        for entry in archive:
            if entry.isdir():
                continue
            name = validate_archive_path(entry.name.removeprefix("./"), "original archive member")
            if not entry.isfile() or name not in original_hashes or name in modes:
                raise ValueError("Original archive member coverage differs")
            destination = base / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(entry) as incoming, destination.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            if sha256_file(destination) != original_hashes[name]:
                raise ValueError("Original publisher member checksum mismatch: " + name)
            modes[name] = entry.mode
    if set(modes) != set(original_hashes):
        raise ValueError("Original asset extraction incomplete")
    overlay, excluded = runtime.members, runtime.excluded
    changed = []
    added = []
    for archive_name, expected in overlay.items():
        destination_name = archive_name.removeprefix("runtime/")
        source = runtime.directory / archive_name
        if source.is_symlink() or not source.is_file():
            raise ValueError("Expected a regular runtime member: " + archive_name)
        destination = base / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha256_file(destination) != expected:
            raise ValueError("Completed Apple runtime bytes changed: " + archive_name)
        modes[destination_name] = 0o755 if destination_name == "usr/bin/crosvm" else 0o644
        if destination_name not in original_hashes:
            added.append(destination_name)
        elif expected != original_hashes[destination_name]:
            changed.append(destination_name)
    if component:
        destination = base / component["member"]
        if component["member"] not in modes:
            raise ValueError("The HostShare overlay must replace only its existing App asset")
        shutil.copyfile(component_source, destination)
        if destination.stat().st_size != component["bytes"] or sha256_file(destination) != component["sha256"]:
            raise ValueError("Clean HostShare input changed during staging")
        modes[component["member"]] = 0o644
        changed.append(component["member"])
    if mac_component:
        destination = base / mac_component["member"]
        if mac_component["member"] in modes:
            raise ValueError("The macOS PSCI KC resource collides with a native/base asset")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(mac_source, destination)
        if destination.stat().st_size != mac_component["bytes"] or sha256_file(destination) != mac_component["sha256"]:
            raise ValueError("Accepted raw macOS PSCI KC changed during staging")
        modes[mac_component["member"]] = 0o644
        added.append(mac_component["member"])
    hashes = {name: sha256_file(base / name) for name in sorted(modes)}
    archive_path = work / ASSET_NAMES[0]
    with tarfile.open(archive_path, "w:xz", format=tarfile.USTAR_FORMAT, preset=6) as archive:
        for name in sorted(modes):
            source = base / name
            entry = tarfile.TarInfo(name)
            entry.size = source.stat().st_size
            entry.mode = modes[name]
            entry.mtime = 1794960000
            with source.open("rb") as incoming:
                archive.addfile(entry, incoming)
    manifest_path = work / ASSET_NAMES[1]
    manifest_path.write_text(json.dumps({"hash": [{"file": name, "source": "prebuilt", "sha256": digest} for name, digest in hashes.items()]}, indent=2) + "\n", encoding="utf-8")
    with archive_path.open("rb") as stream:
        verify_runtime_archive(stream, hashes)
    if manifest_member_hashes(manifest_path.read_bytes()) != hashes:
        raise ValueError("Generated manifest content mismatch")
    staged_assets = {name: sha256_file(work / name) for name in ASSET_NAMES}
    for name in ASSET_NAMES:
        shutil.copyfile(work / name, PREBUILTS / name)
        if sha256_file(PREBUILTS / name) != staged_assets[name]:
            raise ValueError("Staged APK asset copy mismatch")
    result = {"operation": "verified_apple_runtime_merged_into_isolated_apk_assets",
              "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "apk_application_id": APPLICATION_ID,
              "apk_edition": edition,
              "base_droidvm_commit": "33488301c902124d9ddb09fa04b8126443d83230",
              "base_prebuilt_commit": "c4998e150a08f0e60d141591fd63ea0010eb4f75",
              "base_prebuilt_assets_sha256": originals, "backup": str(BACKUP),
              "previous_edition_record": str(previous_record),
              "previous_recorded_asset_edition": previous.get("apk_edition"),
              "previous_merged_assets_backup": str(previous_backup),
              "previous_merged_assets_sha256": previous["merged_assets_sha256"],
              "runtime_directory": str(runtime.directory),
              "runtime_build_record": str(runtime.directory / "crosvm-build.json"),
              "runtime_extraction_record": str(runtime.directory / "extraction-record.json"),
              "runtime_build_record_sha256": runtime.file_sha256["crosvm-build.json"],
              "runtime_extraction_record_sha256": sha256_file(runtime.directory / "extraction-record.json"),
              "runtime_artifact_source": runtime.extraction["source"],
              "native_display_patch": runtime.native_display_patch,
              "host_policy_source": runtime.host_policy_source,
              "host_policy_review": runtime.host_policy_review,
              "host_policy_source_sha256": runtime.file_sha256.get(HOST_POLICY_PROVENANCE_FILES[0]),
              "host_policy_patch_sha256": runtime.file_sha256.get(HOST_POLICY_PROVENANCE_FILES[1]),
              "source_lock_sha256": runtime.file_sha256.get("source-lock.json"),
              "shim_sha256": runtime.file_sha256.get("shim/shim.bin"),
              "local_runtime_policy_source": RUNTIME_PAYLOAD_POLICY_SOURCE,
              "excluded_link_stubs": excluded,
              "recorded_runtime_file_map_preserved": True,
              "original_regular_members": len(original_hashes), "apple_runtime_members": len(overlay),
              "merged_regular_members": len(hashes), "changed_original_paths": sorted(changed),
              "added_paths": sorted(added), "merged_member_sha256": hashes,
              "merged_assets_sha256": staged_assets,
              "original_droidvm_checkout_modified": False, "phone_modified": False,
              "merged_tar_and_all_members_verified": True}
    if component:
        result["hostshare_component"] = component
    if edition == "apple10":
        result.update(runtime_members_sha256=dict(runtime.members), runtime_member_count=len(runtime.members),
                      compiled_crosvm_sha256=runtime.members["runtime/usr/bin/crosvm"],
                      runtime_source_lineage=runtime.source_lineage,
                      paired_app_aidl_sha256=apple10_source_manifest("display")["paired_aidl_sha256"])
    if mac_component:
        result["macos_boot_component"] = mac_component
    validate_merged_record(result)
    with record_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"ok": True, "original_members": len(original_hashes), "merged_members": len(hashes), "new_apk_assets": str(PREBUILTS), "record": str(record_path)}, ensure_ascii=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edition", choices=tuple(ASSET_RELEASES), default="apple2")
    parser.add_argument("--verify-only", action="store_true",
                        help="read-only production check of the selected staged asset pair and owner")
    parser.add_argument("--runtime-dir", type=Path, help="absolute path to one completed extracted runtime")
    parser.add_argument("--previous-record", type=Path,
                        help="absolute path to the owner of the currently staged APK asset pair")
    args = parser.parse_args()
    if args.verify_only:
        count = verify_staged_assets(args.edition)
        print(json.dumps({"ok": True, "operation": "staged_assets_verified", "edition": args.edition,
                          "regular_members": count, "phone_modified": False}))
        return
    paths = edition_paths(args.edition)
    runtime_dir = args.runtime_dir or paths["runtime_dir"]
    previous_record = args.previous_record or paths["previous_record"]
    if not runtime_dir.is_absolute() or not previous_record.is_absolute():
        parser.error("--runtime-dir and --previous-record must be absolute paths")
    merge_assets(args.edition, runtime_dir.resolve(), previous_record.resolve())


if __name__ == "__main__":
    main()
