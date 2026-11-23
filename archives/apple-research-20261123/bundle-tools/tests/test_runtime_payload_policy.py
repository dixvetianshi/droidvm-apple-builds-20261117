"""Recorded legacy runtime remains evidence while only implementations deploy."""

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from runtime_payload_policy import EXCLUDED_LINK_STUB_NAMES, select_runtime_members
import pack_runtime_support
import runtime_artifact


class RuntimePayloadPolicyTest(unittest.TestCase):
    def legacy_map(self):
        members = {"runtime/usr/bin/crosvm": "a" * 64}
        members.update({f"runtime/usr/lib/library{index}.so": "b" * 64 for index in range(70)})
        members["runtime/usr/lib/libdl_android.so"] = "c" * 64
        return members

    def test_legacy_completed_map_stays_intact_while_stub_cannot_deploy(self):
        original = self.legacy_map()
        retained = copy.deepcopy(original)
        selected, excluded = select_runtime_members(original)
        self.assertEqual(original, retained)
        self.assertEqual(len(original), 72)
        self.assertEqual(len(selected), 71)
        self.assertEqual(sum(name.startswith("runtime/usr/lib/") for name in selected), 70)
        self.assertEqual(excluded, {"runtime/usr/lib/libdl_android.so": "c" * 64})
        self.assertEqual(selected["runtime/usr/bin/crosvm"], original["runtime/usr/bin/crosvm"])

    def test_future_collection_uses_the_same_exclusion_and_needs_no_stub(self):
        legacy = self.legacy_map()
        collected = {name: digest for name, digest in legacy.items()
                     if Path(name).name not in EXCLUDED_LINK_STUB_NAMES}
        selected, excluded = select_runtime_members(collected)
        self.assertEqual(selected, collected)
        self.assertEqual(excluded, {})
        self.assertEqual(len(selected), 71)

    def test_bad_metadata_cannot_be_hidden_by_stub_filter(self):
        members = self.legacy_map()
        members["runtime/usr/lib/libdl_android.so"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "invalid digest"):
            select_runtime_members(members)

    def test_off_allowlist_or_missing_executable_cannot_deploy(self):
        for malformed in (
            {"runtime/usr/lib/../libdl_android.so": "a" * 64},
            {"runtime/usr/lib/libdl_android.so": "a" * 64},
            {"runtime/usr/bin/other": "a" * 64},
        ):
            with self.subTest(members=malformed), self.assertRaises(ValueError):
                select_runtime_members(malformed)

    def test_support_selection_accepts_verified_old_and_future_build_records(self):
        legacy = self.legacy_map()
        for recorded_map in (legacy, select_runtime_members(legacy)[0]):
            with self.subTest(recorded_member_count=len(recorded_map)):
                original = copy.deepcopy(recorded_map)
                build = {"runtime_files": recorded_map, "crosvm_embedded_option_names":
                         {name: True for name in (*pack_runtime_support.FLAG_NAMES, "mbi-spis")}}
                members, excluded = select_runtime_members(recorded_map)
                runtime = SimpleNamespace(directory=pack_runtime_support.ROOT / "output/crosvm-builds",
                    build=build, members=members, excluded=excluded, native_display_patch=None,
                    file_sha256={name: "d" * 64 for name in
                                 ("crosvm-build.json", "source-lock.json", "source-manifest.xml",
                                  "static-options.json", "SHA256SUMS")})
                firmware = {"firmware_builds": [
                        {"guest": guest, "pci_cam_mode": False, "virtio_gpu_enable": guest == "ipados",
                         "firmware": f"firmware/{guest}.fd", "firmware_sha256": "e" * 64,
                         "vars": f"firmware/{guest}.vars.fd", "vars_sha256": "f" * 64}
                        for guest in ("macos", "ipados")]}
                with patch.object(pack_runtime_support, "load_completed_runtime", return_value=runtime), \
                        patch.object(pack_runtime_support, "object_from", return_value=firmware):
                    rows, returned_build, _, excluded = pack_runtime_support.selected_files()
                runtime_names = {row[0] for row in rows if row[3] == "runtime"}
                self.assertEqual(len(runtime_names), 71)
                self.assertNotIn("runtime/usr/lib/libdl_android.so", runtime_names)
                self.assertIs(returned_build, build)
                self.assertEqual(returned_build["runtime_files"], original)
                self.assertEqual(bool(excluded), len(recorded_map) == 72)

    def test_support_still_requires_the_original_extraction_verification(self):
        with patch.object(runtime_artifact, "object_from",
                          return_value={"status": "complete", "original_SHA256SUMS_verified": False}):
            with self.assertRaisesRegex(ValueError, "completed crosvm verification"):
                pack_runtime_support.selected_files()


if __name__ == "__main__":
    unittest.main()
