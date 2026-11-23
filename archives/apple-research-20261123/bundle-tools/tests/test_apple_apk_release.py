"""Small real archive boundaries for selecting and packaging an Apple edition.

These fixtures never build/sign an APK, operate a phone, or read release payloads.
The merge workflow runs only against fresh tiny files in an owned temporary tree.
"""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import prepare_apple_apk_assets as assets
import runtime_artifact as artifact
import sign_apple_apk as signing


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf8")


def tar_bytes(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:xz", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return result.getvalue()


def manifest_bytes(hashes):
    return json_bytes({"hash": [{"file": name, "source": "prebuilt", "sha256": expected}
                                 for name, expected in hashes.items()]})


def native_patch_record():
    return {
        "project_path": "packages/modules/Virtualization",
        "project_url": "https://github.com/Droid-VM/Virtualization",
        "upstream_commit": artifact.VIRTUALIZATION_COMMIT,
        "source_path": "libs/android_display_backend/crosvm_android_display_client.cpp",
        "source_sha256_before": artifact.NATIVE_DISPLAY_SOURCE_BEFORE,
        "source_sha256_after": artifact.NATIVE_DISPLAY_SOURCE_AFTER,
        "patch": "diagnostics/android-display-owner.patch",
        "patch_sha256": artifact.NATIVE_DISPLAY_PATCH_SHA256,
        "source_lock_snapshot": "profiles/crosvm-display-source-lock.json",
        "source_lock_snapshot_sha256": artifact.SOURCE_LOCK_SHA256,
        "build_linkage": "libcrosvm_android_display_client (cc_library_static) linked into crosvm",
        "real_android_surface_vulkan_verification": "not performed by this build",
        "phone_apple_guest_boot_verification": "not performed by this build",
    }


def host_policy_record(review="apple7"):
    return json.loads((Path(__file__).parent / f"fixtures/host-policy-{review}.json").read_text(encoding="utf8"))


def complete_source():
    return {
        "source_kind": "github_actions_artifact", "status": "complete",
        "repository": "example/public-builds", "workflow_run_url": "https://github.com/example/public-builds/actions/runs/123",
        "artifact_id": 456, "name": "reviewed-runtime", "original_api_url": "https://api.github.com/example/artifacts/456/zip",
        "size_verified": True, "sha256_verified": True, "expected_size": 1234, "observed_size": 1234,
        "expected_sha256": "a" * 64, "observed_sha256": "a" * 64,
    }


def recorded_assets(edition, archive, manifest, hashes):
    result = {
        "apk_application_id": assets.APPLICATION_ID, "apk_edition": edition,
        "merged_assets_sha256": {assets.ASSET_NAMES[0]: digest(archive), assets.ASSET_NAMES[1]: digest(manifest)},
        "merged_member_sha256": hashes, "merged_regular_members": len(hashes),
        "merged_tar_and_all_members_verified": True, "apple_runtime_members": 71,
    }
    release = assets.ASSET_RELEASES.get(edition)
    if release and release["display_patch"]:
        result.update({"native_display_patch": native_patch_record(), "source_lock_sha256": artifact.SOURCE_LOCK_SHA256,
                       "shim_sha256": artifact.ORIGINAL_SHIM_SHA256})
    if release and release["host_policy_review"]:
        review = release["host_policy_review"]
        source = host_policy_record(review)
        result.update({"host_policy_source": source, "host_policy_source_sha256": digest(json_bytes(source)),
                       "host_policy_patch_sha256": artifact.reviewed_host_policy(review).patch_sha256})
        if review != "apple7":
            result["host_policy_review"] = review
    return result


def extracted_runtime(directory, *, native=False):
    directory.mkdir()
    members = {"runtime/usr/bin/crosvm": digest(b"vmm")}
    members.update({f"runtime/usr/lib/library{index}.so": digest(f"library{index}".encode()) for index in range(70)})
    full = {"full-build/library0.so": members["runtime/usr/lib/library0.so"]}
    build = {"runtime_files": members, "full_build_files": full}
    fixed = {}
    if native:
        patch_value = native_patch_record()
        build.update({"native_display_patch": patch_value, "source_lock_snapshot_sha256": artifact.SOURCE_LOCK_SHA256,
                      "source_lock_reused_without_ref_resolution": True, "shim_sha256": artifact.ORIGINAL_SHIM_SHA256,
                      "shim_expected_sha256": artifact.ORIGINAL_SHIM_SHA256, "retained_shim_embedded_in_crosvm": True})
        (directory / "native-display-patch.json").write_bytes(json_bytes(patch_value))
        fixed = {"diagnostics/android-display-owner.patch": artifact.NATIVE_DISPLAY_PATCH_SHA256,
                 "source-lock.json": artifact.SOURCE_LOCK_SHA256, "shim/shim.bin": artifact.ORIGINAL_SHIM_SHA256}
        full["shim/shim.bin"] = artifact.ORIGINAL_SHIM_SHA256
    (directory / "crosvm-build.json").write_bytes(json_bytes(build))
    hashes = {**members, **full, **fixed, "crosvm-build.json": digest((directory / "crosvm-build.json").read_bytes())}
    if native:
        hashes["native-display-patch.json"] = digest((directory / "native-display-patch.json").read_bytes())
    extraction = {"status": "complete", "original_SHA256SUMS_verified": True, "source": complete_source(),
                  "files": [{"path": name, "status": "complete", "sha256": expected, "bytes": 1}
                            for name, expected in hashes.items()]}
    (directory / "extraction-record.json").write_bytes(json_bytes(extraction))
    return build, extraction, hashes


class CompletedRuntimeTest(unittest.TestCase):
    def test_completed_actions_source_and_71_member_map_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "selected-runtime"
            build, extraction, hashes = extracted_runtime(directory)
            result = artifact.load_completed_runtime(directory)
            self.assertEqual(result.directory, directory.resolve())
            self.assertEqual(result.extraction["source"], extraction["source"])
            self.assertEqual(result.build, build)
            self.assertEqual(result.members, build["runtime_files"])
            self.assertEqual(result.file_sha256, hashes)
            self.assertEqual(len(result.members), 71)

    def test_incomplete_source_or_member_or_duplicate_member_is_rejected(self):
        for failure in ("source", "source_size", "member", "duplicate"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "runtime"
                _, extraction, _ = extracted_runtime(directory)
                if failure == "source":
                    extraction["source"]["sha256_verified"] = False
                elif failure == "source_size":
                    extraction["source"]["expected_size"] = 1
                    extraction["source"]["observed_size"] = True
                elif failure == "member":
                    extraction["files"][0]["status"] = "partial"
                else:
                    extraction["files"].append(extraction["files"][0].copy())
                (directory / "extraction-record.json").write_bytes(json_bytes(extraction))
                with self.assertRaises(ValueError):
                    artifact.load_completed_runtime(directory)

    def test_extracted_map_and_actual_build_record_must_match(self):
        for failure in ("runtime_hash", "build_bytes"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "runtime"
                _, extraction, _ = extracted_runtime(directory)
                if failure == "runtime_hash":
                    extraction["files"][0]["sha256"] = "b" * 64
                    (directory / "extraction-record.json").write_bytes(json_bytes(extraction))
                else:
                    with (directory / "crosvm-build.json").open("ab") as stream:
                        stream.write(b" ")
                with self.assertRaises(ValueError):
                    artifact.load_completed_runtime(directory)

    def test_apple5_requires_bound_final_patch_and_original_shim(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "runtime"
            build, _, hashes = extracted_runtime(directory, native=True)
            # Fixed artifact bytes are represented by recorded hashes here;
            # this tests metadata binding, not a real-provider byte verification.
            with patch.object(artifact, "sha256_file", side_effect=lambda path: hashes[path.relative_to(directory).as_posix()]):
                result = artifact.load_completed_runtime(directory, require_display_patch=True)
                self.assertEqual(result.native_display_patch, native_patch_record())
                build["shim_expected_sha256"] = "f" * 64
                (directory / "crosvm-build.json").write_bytes(json_bytes(build))
                with self.assertRaisesRegex(ValueError, "original matching"):
                    artifact.load_completed_runtime(directory, require_display_patch=True)

    def test_legacy_unpatched_input_and_relative_input_cannot_select_apple5(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            artifact.load_completed_runtime(Path("relative/runtime"))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "runtime"
            extracted_runtime(directory)
            with self.assertRaises(ValueError):
                artifact.load_completed_runtime(directory, require_display_patch=True)

    def test_host_policy_checks_all_eight_before_after_hashes_and_unique_coverage(self):
        source = host_policy_record()
        self.assertIs(artifact.validate_host_policy_source(source), source)
        for index, row in enumerate(source["files"]):
            for field in ("pinned_sha256", "final_lf_sha256"):
                with self.subTest(file=row["file"], field=field):
                    changed = json.loads(json.dumps(source))
                    changed["files"][index][field] = "f" * 64
                    with self.assertRaisesRegex(ValueError, "before/after"):
                        artifact.validate_host_policy_source(changed)
        for failure in ("missing", "duplicate", "base", "patch"):
            with self.subTest(failure=failure):
                changed = json.loads(json.dumps(source))
                if failure == "missing":
                    changed["files"].pop()
                elif failure == "duplicate":
                    changed["files"][-1] = changed["files"][0]
                elif failure == "base":
                    changed["base_commit"] = "e" * 40
                else:
                    changed["patch_sha256"] = "e" * 64
                with self.assertRaises(ValueError):
                    artifact.validate_host_policy_source(changed)

    def test_host_policy_review_selection_preserves_legacy_and_binds_all_nine_new_files(self):
        source = host_policy_record("apple8")
        self.assertIs(artifact.validate_host_policy_source(source, review="apple8"), source)
        self.assertEqual(len(source["files"]), 9)
        for wrong_review in ("apple7", "unknown", None):
            with self.subTest(review=wrong_review), self.assertRaises(ValueError):
                artifact.validate_host_policy_source(source, review=wrong_review)
        with self.assertRaises(ValueError):
            artifact.validate_host_policy_source(source)
        with self.assertRaises(ValueError):
            artifact.validate_host_policy_source(host_policy_record(), review="apple8")
        for index, row in enumerate(source["files"]):
            for field in ("pinned_sha256", "final_lf_sha256"):
                changed = json.loads(json.dumps(source))
                changed["files"][index][field] = "f" * 64
                with self.subTest(file=row["file"], field=field), self.assertRaisesRegex(ValueError, "before/after"):
                    artifact.validate_host_policy_source(changed, review="apple8")
        for failure in ("missing", "duplicate", "old_patch", "unreviewed_patch"):
            changed = json.loads(json.dumps(source))
            if failure == "missing": changed["files"].pop()
            elif failure == "duplicate": changed["files"][-1] = changed["files"][0]
            elif failure == "old_patch": changed["patch_sha256"] = artifact.HOST_POLICY_PATCH_SHA256
            else: changed["patch_sha256"] = "e" * 64
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                artifact.validate_host_policy_source(changed, review="apple8")


class AssetArchiveTest(unittest.TestCase):
    def test_manifest_rejects_duplicate_and_noncanonical_paths(self):
        for rows in (
            [{"file": "usr/bin/crosvm", "sha256": "a" * 64}] * 2,
            [{"file": "usr//bin/crosvm", "sha256": "a" * 64}],
        ):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                assets.manifest_member_hashes(json_bytes({"hash": rows}))

    def test_archive_checks_actual_members_and_rejects_missing_duplicate_and_changed_bytes(self):
        expected = {"usr/bin/crosvm": digest(b"vmm"), "usr/lib/libone.so": digest(b"one")}
        good = [("usr/bin/crosvm", b"vmm"), ("usr/lib/libone.so", b"one")]
        self.assertEqual(assets.verify_runtime_archive(io.BytesIO(tar_bytes(good)), expected), 2)
        for members in (good[:1], good + [good[0]], [good[0], (good[1][0], b"changed")]):
            with self.subTest(members=members), self.assertRaises(ValueError):
                assets.verify_runtime_archive(io.BytesIO(tar_bytes(members)), expected)

    def merge_fixture(self, directory, *, host_policy=False):
        (directory / "output").mkdir()
        (directory / "verification").mkdir()
        backup, prebuilts = directory / "original-backup", directory / "current-prebuilts"
        backup.mkdir()
        prebuilts.mkdir()
        original_members = {"usr/bin/crosvm": b"original-vmm", "usr/share/original.txt": b"base evidence"}
        original_hashes = {name: digest(data) for name, data in original_members.items()}
        original_tar = tar_bytes(list(original_members.items()))
        original_json = manifest_bytes(original_hashes)
        for name, data in zip(assets.ASSET_NAMES, (original_tar, original_json)):
            (backup / name).write_bytes(data)
            (prebuilts / name).write_bytes(data)
        previous = recorded_assets("apple2", original_tar, original_json, original_hashes)
        previous["base_prebuilt_assets_sha256"] = previous["merged_assets_sha256"].copy()
        previous_path = directory / "verification/previous.json"
        previous_path.write_bytes(json_bytes(previous))
        runtime_dir = directory / "runtime"
        runtime_dir.mkdir()
        members = {"runtime/usr/bin/crosvm": b"new-vmm"}
        members.update({f"runtime/usr/lib/library{index}.so": f"new-library-{index}".encode() for index in range(70)})
        for name, data in members.items():
            target = runtime_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        member_hashes = {name: digest(data) for name, data in members.items()}
        build_bytes = json_bytes({"runtime_files": member_hashes})
        extraction = {"source": complete_source()}
        (runtime_dir / "crosvm-build.json").write_bytes(build_bytes)
        (runtime_dir / "extraction-record.json").write_bytes(json_bytes(extraction))
        file_hashes = {**member_hashes, "crosvm-build.json": digest(build_bytes),
                       "source-lock.json": artifact.SOURCE_LOCK_SHA256, "shim/shim.bin": artifact.ORIGINAL_SHIM_SHA256}
        runtime = artifact.CompletedRuntime(runtime_dir, {}, extraction, file_hashes, member_hashes, {}, native_patch_record())
        if host_policy:
            review = "apple7" if host_policy is True else host_policy
            source = host_policy_record(review)
            file_hashes.update({artifact.HOST_POLICY_PROVENANCE_FILES[0]: digest(json_bytes(source)),
                               artifact.HOST_POLICY_PROVENANCE_FILES[1]: artifact.reviewed_host_policy(review).patch_sha256})
            runtime = artifact.CompletedRuntime(runtime_dir, {}, extraction, file_hashes, member_hashes, {},
                                                native_patch_record(), source, review)
        return backup, prebuilts, previous_path, runtime, previous

    def test_small_complete_merge_backs_up_actual_current_pair_and_rechecks_on_rerun(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            backup, prebuilts, previous_path, runtime, previous = self.merge_fixture(directory)
            with patch.object(assets, "ROOT", directory), patch.object(assets, "BACKUP", backup), \
                    patch.object(assets, "PREBUILTS", prebuilts), patch.object(assets, "load_completed_runtime", return_value=runtime), \
                    contextlib.redirect_stdout(io.StringIO()):
                assets.merge_assets("apple5", runtime.directory, previous_path)
                paths = assets.edition_paths("apple5")
                result = assets.merged_record(paths["record"])
                self.assertEqual(result["previous_merged_assets_sha256"], previous["merged_assets_sha256"])
                self.assertEqual(result["merged_member_sha256"]["usr/bin/crosvm"], runtime.members["runtime/usr/bin/crosvm"])
                self.assertEqual(result["merged_regular_members"], 72)
                for name in assets.ASSET_NAMES:
                    self.assertEqual((paths["previous_backup"] / name).read_bytes(), (backup / name).read_bytes())
                report_bytes = paths["record"].read_bytes()
                assets.merge_assets("apple5", runtime.directory, previous_path)
                self.assertEqual(paths["record"].read_bytes(), report_bytes)

    def test_stale_current_owner_fails_before_creating_backup_or_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            backup, prebuilts, previous_path, runtime, _ = self.merge_fixture(directory)
            (prebuilts / assets.ASSET_NAMES[1]).write_bytes(b"changed current manifest")
            with patch.object(assets, "ROOT", directory), patch.object(assets, "BACKUP", backup), \
                    patch.object(assets, "PREBUILTS", prebuilts), patch.object(assets, "load_completed_runtime", return_value=runtime):
                with self.assertRaisesRegex(ValueError, "Previous APK asset bytes changed"):
                    assets.merge_assets("apple5", runtime.directory, previous_path)
                paths = assets.edition_paths("apple5")
                self.assertFalse(paths["previous_backup"].exists())
                self.assertFalse(paths["work"].exists())

    def test_apple7_merge_uses_a_required_host_gate_and_separate_owner_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            backup, prebuilts, previous_path, runtime, previous = self.merge_fixture(directory, host_policy=True)
            with patch.object(assets, "ROOT", directory), patch.object(assets, "BACKUP", backup), \
                    patch.object(assets, "PREBUILTS", prebuilts), \
                    patch.object(assets, "load_completed_runtime", return_value=runtime) as owner, \
                    contextlib.redirect_stdout(io.StringIO()):
                assets.merge_assets("apple7", runtime.directory, previous_path)
                owner.assert_called_once_with(runtime.directory, require_display_patch=True, require_host_policy=True,
                                               host_policy_review="apple7")
                apple7, apple5 = assets.edition_paths("apple7"), assets.edition_paths("apple5")
                for key in ("runtime_dir", "previous_backup", "work", "record"):
                    self.assertNotEqual(apple7[key], apple5[key])
                record = assets.merged_record(apple7["record"])
                self.assertEqual(record["host_policy_source"], runtime.host_policy_source)
                self.assertEqual(record["host_policy_patch_sha256"], artifact.HOST_POLICY_PATCH_SHA256)
                self.assertEqual(record["previous_merged_assets_sha256"], previous["merged_assets_sha256"])
                self.assertFalse(apple5["record"].exists())
                for name in assets.ASSET_NAMES:
                    self.assertEqual((apple7["previous_backup"] / name).read_bytes(), (backup / name).read_bytes())
                # Even a byte-matching completed asset pair cannot use a record
                # from which the required native provenance was removed.
                record["host_policy_source"] = None
                apple7["record"].write_bytes(json_bytes(record))
                with self.assertRaisesRegex(ValueError, "host policy"):
                    assets.merge_assets("apple7", runtime.directory, previous_path)

    def test_bad_overlay_bytes_preserve_previous_pair_and_owned_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            backup, prebuilts, previous_path, runtime, _ = self.merge_fixture(directory)
            (runtime.directory / "runtime/usr/bin/crosvm").write_bytes(b"tampered overlay")
            with patch.object(assets, "ROOT", directory), patch.object(assets, "BACKUP", backup), \
                    patch.object(assets, "PREBUILTS", prebuilts), patch.object(assets, "load_completed_runtime", return_value=runtime):
                with self.assertRaisesRegex(ValueError, "runtime bytes changed"):
                    assets.merge_assets("apple5", runtime.directory, previous_path)
                paths = assets.edition_paths("apple5")
                self.assertTrue(paths["previous_backup"].exists())
                self.assertTrue(paths["work"].exists())
                self.assertFalse(paths["record"].exists())
                for name in assets.ASSET_NAMES:
                    self.assertEqual((prebuilts / name).read_bytes(), (backup / name).read_bytes())

    def test_apple8_merge_backs_up_sha_matched_apple7_pair_and_preserves_its_record(self):
        for bad_current in (False, True):
            with self.subTest(bad_current=bad_current), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary).resolve()
                backup, prebuilts, _, runtime, original = self.merge_fixture(directory, host_policy="apple8")
                old_members = {"usr/bin/crosvm": b"apple7-vmm", "usr/share/original.txt": b"base evidence"}
                old_members.update({f"usr/lib/library{index}.so": f"apple7-library-{index}".encode() for index in range(70)})
                old_hashes = {name: digest(data) for name, data in old_members.items()}
                old_pair = (tar_bytes(list(old_members.items())), manifest_bytes(old_hashes))
                previous = recorded_assets("apple7", *old_pair, old_hashes)
                previous["base_prebuilt_assets_sha256"] = original["base_prebuilt_assets_sha256"]
                previous_path = directory / "verification/apple7-apk-runtime-assets-20261122.json"
                previous_path.write_bytes(json_bytes(previous))
                saved_record = previous_path.read_bytes()
                for name, data in zip(assets.ASSET_NAMES, old_pair): (prebuilts / name).write_bytes(data)
                if bad_current: (prebuilts / assets.ASSET_NAMES[0]).write_bytes(b"changed current pair")
                with patch.object(assets, "ROOT", directory), patch.object(assets, "BACKUP", backup), \
                        patch.object(assets, "PREBUILTS", prebuilts), \
                        patch.object(assets, "load_completed_runtime", return_value=runtime) as owner, \
                        contextlib.redirect_stdout(io.StringIO()):
                    paths = assets.edition_paths("apple8")
                    self.assertEqual(paths["previous_record"], previous_path)
                    self.assertNotEqual(paths["record"], previous_path)
                    if bad_current:
                        with self.assertRaisesRegex(ValueError, "Previous APK asset bytes changed"):
                            assets.merge_assets("apple8", runtime.directory, previous_path)
                        self.assertFalse(paths["previous_backup"].exists())
                        self.assertFalse(paths["work"].exists())
                        self.assertFalse(paths["record"].exists())
                    else:
                        assets.merge_assets("apple8", runtime.directory, previous_path)
                        assets.merge_assets("apple8", runtime.directory, previous_path)
                        owner.assert_called_once_with(runtime.directory, require_display_patch=True,
                                                       require_host_policy=True, host_policy_review="apple8")
                        merged = assets.merged_record(paths["record"])
                        self.assertEqual(merged["host_policy_review"], "apple8")
                        self.assertEqual(merged["host_policy_source"], host_policy_record("apple8"))
                        self.assertEqual(merged["previous_merged_assets_sha256"], previous["merged_assets_sha256"])
                        for name, data in zip(assets.ASSET_NAMES, old_pair):
                            self.assertEqual((paths["previous_backup"] / name).read_bytes(), data)
                    self.assertEqual(previous_path.read_bytes(), saved_record)
                    self.assertEqual(assets.merged_record(previous_path), previous)


class SignedContentTest(unittest.TestCase):
    def apk_fixture(self, directory, *, changed_tar=False, duplicate_network=False, helpers=True,
                    runtime_edition="apple5"):
        content = {"usr/bin/crosvm": b"new-vmm"}
        content.update({f"usr/lib/library{index}.so": f"library-{index}".encode() for index in range(70)})
        hashes = {name: digest(data) for name, data in content.items()}
        manifest = manifest_bytes(hashes)
        if changed_tar:
            content["usr/bin/crosvm"] = b"corrupted-vmm"
        archive = tar_bytes(list(content.items()))
        runtime = recorded_assets(runtime_edition, archive, manifest, hashes)
        network = b'{"schema":2,"name":"br-apple-nat"}\n'
        source = directory / "sources/DroidVM-Apple/app/src/main/resources/apple-guest-network.json"
        source.parent.mkdir(parents=True)
        source.write_bytes(network)
        apk = directory / "tiny.apk"
        with zipfile.ZipFile(apk, "w") as output, warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            output.writestr("assets/prebuilts/" + assets.ASSET_NAMES[0], archive)
            output.writestr("assets/prebuilts/" + assets.ASSET_NAMES[1], manifest)
            output.writestr("apple-guest-network.json", network)
            if duplicate_network:
                output.writestr("apple-guest-network.json", network)
            dex = b"dex\n035\0" + (b"\0".join(("L" + name + ";").encode() for name in signing.MAC_IMPORT_CLASSES) if helpers else b"none")
            output.writestr("classes10.dex", dex)
        return apk, runtime, source

    def test_new_payload_json_all_tar_members_resource_and_helper_strings_are_verified(self):
        for edition in ("apple5", "apple6"):
            with self.subTest(edition=edition), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                apk, runtime, _ = self.apk_fixture(directory)
                with patch.object(signing, "ROOT", directory):
                    result = signing.verify_apk_content(apk, runtime, edition)
                self.assertEqual(result["runtime_archive_sha256"], runtime["merged_assets_sha256"][assets.ASSET_NAMES[0]])
                self.assertEqual(result["runtime_regular_members_verified"], 71)
                self.assertTrue(result["apple_guest_network_resource_unique_and_source_match"])
                self.assertTrue(all(result["compiled_import_helper_class_strings"].values()))

    def test_apple6_reuses_only_the_completed_apple5_runtime_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            apk, runtime, _ = self.apk_fixture(directory)
            for wrong_owner in ("apple2", "apple6", None):
                runtime["apk_edition"] = wrong_owner
                with self.subTest(owner=wrong_owner), patch.object(signing, "ROOT", directory), \
                        self.assertRaisesRegex(ValueError, "completed Apple5 runtime"):
                    signing.verify_apk_content(apk, runtime, "apple6")

    def test_apple7_verifies_new_payload_and_cannot_reuse_an_old_or_unproven_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            apk, runtime, _ = self.apk_fixture(directory, runtime_edition="apple7")
            with patch.object(signing, "ROOT", directory):
                result = signing.verify_apk_content(apk, runtime, "apple7")
                self.assertEqual(result["runtime_regular_members_verified"], 71)
                self.assertTrue(result["apple_guest_network_resource_unique_and_source_match"])
                for owner in ("apple2", "apple5", "apple6", None):
                    changed = {**runtime, "apk_edition": owner}
                    with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, "host read-only runtime"):
                        signing.verify_apk_content(apk, changed, "apple7")
                for field in ("native_display_patch", "host_policy_source", "host_policy_source_sha256",
                              "host_policy_patch_sha256", "source_lock_sha256", "shim_sha256"):
                    changed = {**runtime, field: None}
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        signing.verify_apk_content(apk, changed, "apple7")

    def test_matching_archive_digest_does_not_hide_wrong_member_bytes(self):
        for edition in ("apple5", "apple6"):
            with self.subTest(edition=edition), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                apk, runtime, _ = self.apk_fixture(directory, changed_tar=True)
                with patch.object(signing, "ROOT", directory), self.assertRaisesRegex(ValueError, "member checksum"):
                    signing.verify_apk_content(apk, runtime, edition)

    def test_duplicate_nat_resource_missing_helpers_or_changed_source_is_rejected(self):
        for edition in ("apple5", "apple6"):
            for failure in ("duplicate", "helpers", "source"):
                with self.subTest(edition=edition, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    apk, runtime, source = self.apk_fixture(directory, duplicate_network=failure == "duplicate", helpers=failure != "helpers")
                    if failure == "source":
                        source.write_bytes(b"a different source resource")
                    with patch.object(signing, "ROOT", directory), self.assertRaises(ValueError):
                        signing.verify_apk_content(apk, runtime, edition)

    def test_apple6_build_selection_uses_new_output_paths_and_version_code(self):
        metadata = {"applicationId": assets.APPLICATION_ID, "elements": [{"versionCode": 2726,
                    "versionName": "0.0.6.r242.g3348830.apple6", "outputFile": "app-release-unsigned.apk"}]}
        version = signing.validate_build_metadata(metadata, "apple6", 2726, "app-release-unsigned.apk")
        self.assertEqual(version, "0.0.6.r242.g3348830.apple6")
        signing.verify_badging(f"package: name='{assets.APPLICATION_ID}' versionCode='2726' versionName='{version}'\n", version, 2726)
        for wrong_code in (2725, 2727):
            with self.subTest(code=wrong_code), patch.object(sys, "argv", [
                    "sign_apple_apk.py", "--edition", "apple6", "--version-code", str(wrong_code)]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                signing.main()
            self.assertEqual(result.exception.code, 2)
        apple5 = signing.delivery_paths("apple5")
        apple6 = signing.delivery_paths("apple6")
        self.assertEqual(apple6["runtime_record"], apple5["runtime_record"])
        for key in ("aligned", "apk", "record", "signature", "badging", "checksum"):
            self.assertNotEqual(apple6[key], apple5[key])
        self.assertEqual(apple6["apk"].name, "DroidVM-0.0.6-r242-Apple6-NX736J.apk")
        self.assertEqual(apple6["record"].name, "apple6-apk-delivery-20261120.json")

    def test_version_and_certificate_values_are_bound_to_named_declarations(self):
        metadata = {"applicationId": assets.APPLICATION_ID, "elements": [{"versionCode": 2725,
                    "versionName": "0.0.6.r242.g3348830.apple5", "outputFile": "app-release-unsigned.apk"}]}
        version = signing.validate_build_metadata(metadata, "apple5", 2725, "app-release-unsigned.apk")
        with self.assertRaises(ValueError):
            signing.validate_build_metadata(metadata, "apple5", 2724, "app-release-unsigned.apk")
        signing.verify_certificate("Number of signers: 1\r\nSigner #1 certificate SHA-256 digest: " + signing.CERTIFICATE + "\r\n")
        with self.assertRaises(ValueError):
            signing.verify_certificate("Unrelated SHA: " + signing.CERTIFICATE + "\nSigner #1 certificate SHA-256 digest: " + "b" * 64)
        signing.verify_badging(f"package: name='{assets.APPLICATION_ID}' versionCode='2725' versionName='{version}'\n", version, 2725)
        with self.assertRaises(ValueError):
            signing.verify_badging(f"package: name='wrong' versionCode='2725' versionName='{version}'\napplication: name='{assets.APPLICATION_ID}'\n", version, 2725)

    def test_apple7_build_selection_preserves_apple5_and_apple6_outputs(self):
        metadata = {"applicationId": assets.APPLICATION_ID, "elements": [{"versionCode": 2727,
                    "versionName": "0.0.6.r242.g3348830.apple7", "outputFile": "app-release-unsigned.apk"}]}
        version = signing.validate_build_metadata(metadata, "apple7", 2727, "app-release-unsigned.apk")
        signing.verify_badging(f"package: name='{assets.APPLICATION_ID}' versionCode='2727' versionName='{version}'\n", version, 2727)
        for wrong_code in (2725, 2726, 2728):
            with self.subTest(code=wrong_code), patch.object(sys, "argv", [
                    "sign_apple_apk.py", "--edition", "apple7", "--version-code", str(wrong_code)]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                signing.main()
            self.assertEqual(result.exception.code, 2)
        apple7 = signing.delivery_paths("apple7")
        for old in ("apple5", "apple6"):
            paths = signing.delivery_paths(old)
            for key in ("aligned", "apk", "record", "signature", "badging", "checksum", "runtime_record"):
                self.assertNotEqual(apple7[key], paths[key])
        self.assertEqual(apple7["apk"].name, "DroidVM-0.0.6-r242-Apple7-NX736J.apk")
        self.assertEqual(apple7["record"].name, "apple7-apk-delivery-20261122.json")

    def test_existing_apple7_delivery_is_preserved_before_any_signing_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            apk, runtime, _ = self.apk_fixture(directory, runtime_edition="apple7")
            with patch.object(signing, "ROOT", directory):
                paths = signing.delivery_paths("apple7")
                paths["runtime_record"].parent.mkdir(parents=True)
                paths["runtime_record"].write_bytes(json_bytes(runtime))
                unsigned = directory / "sources/DroidVM-Apple/app/build/outputs/apk/release/app-release-unsigned.apk"
                unsigned.parent.mkdir(parents=True)
                unsigned.write_bytes(apk.read_bytes())
                unsigned.with_name("output-metadata.json").write_bytes(json_bytes({
                    "applicationId": assets.APPLICATION_ID, "elements": [{"versionCode": 2727,
                        "versionName": "0.0.6.r242.g3348830.apple7", "outputFile": unsigned.name}]}))
                paths["apk"].parent.mkdir(parents=True)
                paths["apk"].write_bytes(b"preserve prior reviewed delivery")
                with patch.object(sys, "argv", ["sign_apple_apk.py", "--edition", "apple7", "--version-code", "2727"]), \
                        patch.object(signing.subprocess, "run") as command, \
                        self.assertRaisesRegex(FileExistsError, "Preserve existing signed outputs"):
                    signing.main()
                command.assert_not_called()
                self.assertEqual(paths["apk"].read_bytes(), b"preserve prior reviewed delivery")

    def test_apple8_selects_new_owner_and_paths_and_rejects_legacy_provenance(self):
        metadata = {"applicationId": assets.APPLICATION_ID, "elements": [{"versionCode": 2728,
                    "versionName": "0.0.6.r242.g3348830.apple8", "outputFile": "app-release-unsigned.apk"}]}
        self.assertEqual(signing.validate_build_metadata(metadata, "apple8", 2728, "app-release-unsigned.apk"),
                         "0.0.6.r242.g3348830.apple8")
        for code in (2727, 2729):
            with self.subTest(code=code), self.assertRaises(ValueError):
                signing.validate_build_metadata(metadata, "apple8", code, "app-release-unsigned.apk")
        paths = signing.delivery_paths("apple8")
        for key in ("aligned", "apk", "record", "signature", "badging", "checksum", "runtime_record"):
            self.assertNotEqual(paths[key], signing.delivery_paths("apple7")[key])
        self.assertEqual(paths["record"].name, "apple8-apk-delivery-20261122.json")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            apk, runtime, _ = self.apk_fixture(directory, runtime_edition="apple8")
            with patch.object(signing, "ROOT", directory):
                self.assertEqual(signing.verify_apk_content(apk, runtime, "apple8")["runtime_regular_members_verified"], 71)
                for failure in ("old_owner", "old_manifest", "review_missing", "wrong_review"):
                    changed = json.loads(json.dumps(runtime))
                    if failure == "old_owner": changed["apk_edition"] = "apple7"
                    elif failure == "old_manifest":
                        changed["host_policy_source"] = host_policy_record()
                        changed["host_policy_patch_sha256"] = artifact.HOST_POLICY_PATCH_SHA256
                    elif failure == "review_missing": changed.pop("host_policy_review")
                    else: changed["host_policy_review"] = "apple7"
                    with self.subTest(failure=failure), self.assertRaises(ValueError):
                        signing.verify_apk_content(apk, changed, "apple8")

    def test_sdk37_recorded_v3_certificate_is_read_from_its_actual_scheme_block(self):
        output = (Path(__file__).parent / "fixtures/apksigner-37-v3-only.txt").read_text(encoding="utf8")
        signing.verify_certificate(output)
        with self.assertRaises(ValueError):
            signing.verify_certificate(output.replace(signing.CERTIFICATE, "b" * 64))

    def test_signer_count_and_public_key_digest_cannot_stand_in_for_one_certificate(self):
        for output in (
            "Number of signers: 1\nV3.0 Signer: public key SHA-256 digest: " + signing.CERTIFICATE,
            "Number of signers: 2\nV3.0 Signer: certificate SHA-256 digest: " + signing.CERTIFICATE,
            "V3.0 Signer: certificate SHA-256 digest: " + signing.CERTIFICATE,
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                signing.verify_certificate(output)


if __name__ == "__main__":
    unittest.main()
