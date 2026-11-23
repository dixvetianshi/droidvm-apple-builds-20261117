"""Small App asset boundaries; no APK build, signing, phone or native execution."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import prepare_apple_apk_assets as assets
import sign_apple_apk as signing
from tools.tests.test_apple_apk_release import digest, manifest_bytes, recorded_assets, tar_bytes


class HostShareAssetTest(unittest.TestCase):
    def test_apple9_has_its_own_asset_owner_and_retains_apple8_native_review(self):
        release = assets.ASSET_RELEASES["apple9"]
        self.assertEqual(release["host_policy_review"], "apple8")
        self.assertEqual(release["paths"]["runtime_dir"], assets.ASSET_RELEASES["apple8"]["paths"]["runtime_dir"])
        self.assertEqual(assets.APK_RELEASES["apple9"]["runtime_edition"], "apple9")
        self.assertEqual(assets.APK_RELEASES["apple9"]["version_code"], 2729)
        for name in ("apk", "record", "runtime_record"):
            self.assertNotEqual(signing.delivery_paths("apple9")[name], signing.delivery_paths("apple8")[name])
        metadata = {"applicationId": assets.APPLICATION_ID, "elements": [{"versionCode": 2729,
                    "versionName": "0.0.6.r242.g3348830.apple9", "outputFile": "app-release-unsigned.apk"}]}
        self.assertEqual(signing.validate_build_metadata(metadata, "apple9", 2729, "app-release-unsigned.apk"),
                         "0.0.6.r242.g3348830.apple9")

    def test_completed_record_rejects_wrong_component_member_and_provenance(self):
        component = assets.HOSTSHARE_COMPONENT
        hashes = {component["member"]: component["sha256"]}
        record = recorded_assets("apple9", b"container", b"manifest", hashes)
        record["hostshare_component"] = copy.deepcopy(component)
        self.assertIs(assets.validate_merged_record(record), record)
        for failure in ("missing", "old_digest", "wrong_bytes", "wrong_source", "wrong_ci", "old_native_review"):
            changed = copy.deepcopy(record)
            if failure == "missing": changed.pop("hostshare_component")
            elif failure == "old_digest": changed["merged_member_sha256"][component["member"]] = "a" * 64
            elif failure == "wrong_bytes": changed["hostshare_component"]["bytes"] += 1
            elif failure == "wrong_source": changed["hostshare_component"]["source"] = "unreviewed.ko"
            elif failure == "wrong_ci": changed["hostshare_component"]["ci_run_id"] += 1
            else: changed["host_policy_review"] = "apple7"
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                assets.validate_merged_record(changed)

    def test_wrong_source_bytes_fail_before_any_asset_backup_or_staging(self):
        for failure in ("size", "digest"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                component = assets.HOSTSHARE_COMPONENT
                source = root / component["source"]
                source.parent.mkdir(parents=True)
                source.write_bytes(b"bad" if failure == "size" else b"\0" * component["bytes"])
                with patch.object(assets, "ROOT", root), patch.object(assets, "PREBUILTS", root / "prebuilts"), \
                        patch.object(assets, "BACKUP", root / "base-backup"), \
                        patch.object(assets, "load_completed_runtime", return_value=SimpleNamespace(host_policy_review="apple8")), \
                        self.assertRaisesRegex(ValueError, "exact regular reviewed clean HostShare"):
                    assets.merge_assets("apple9", root / "native-runtime", root / "previous.json")
                self.assertFalse((root / "output/apk-runtime-merge-apple9").exists())
                self.assertFalse((root / "verification/backups/apple-apk-prebuilt-apple8-20261122").exists())
                self.assertFalse((root / "prebuilts").exists())

    def test_matching_container_hash_cannot_hide_an_old_hostshare_member(self):
        member = assets.HOSTSHARE_COMPONENT["member"]
        hashes = {member: digest(b"clean-fixture-ko")}
        manifest = manifest_bytes(hashes)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = tar_bytes([(member, b"old-fixture-ko")])
            record = recorded_assets("apple8", archive, manifest, hashes)
            for name, data in zip(assets.ASSET_NAMES, (archive, manifest)):
                (directory / name).write_bytes(data)
            with self.assertRaisesRegex(ValueError, "member checksum"):
                assets.verify_asset_pair(record, directory)


if __name__ == "__main__":
    unittest.main()
