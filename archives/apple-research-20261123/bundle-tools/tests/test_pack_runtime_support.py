"""Support selection keeps the chosen runtime and its local patch provenance bound."""

import contextlib
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import pack_runtime_support as support


class SupportRuntimeSelectionTest(unittest.TestCase):
    def runtime(self, *, patched=True):
        directory = support.ROOT / "output/crosvm-builds-apple5"
        members = {"runtime/usr/bin/crosvm": "a" * 64}
        members.update({f"runtime/usr/lib/library{index}.so": "b" * 64 for index in range(70)})
        build = {"runtime_files": members, "crosvm_embedded_option_names":
                 {name: True for name in (*support.FLAG_NAMES, "mbi-spis")}}
        file_hashes = {name: "c" * 64 for name in
                       ("crosvm-build.json", "source-lock.json", "source-manifest.xml",
                        "static-options.json", "SHA256SUMS", *support.NATIVE_DISPLAY_PROVENANCE_FILES)}
        source = {"source_kind": "github_actions_artifact", "repository": "owner/new-runtime",
                  "run_id": 55, "name": "new-runtime.zip", "artifact_id": 555,
                  "run_url": "https://example.test/actions/runs/55",
                  "original_artifact_url": "https://example.test/actions/artifacts/555",
                  "expected_size": 100, "expected_sha256": "d" * 64,
                  "api_asset_digest": "sha256:" + "d" * 64,
                  "local_path": "unneeded-local-download-path"}
        return SimpleNamespace(directory=directory, build=build, members=members,
                               excluded={"runtime/usr/lib/libdl_android.so": "e" * 64},
                               file_sha256=file_hashes, extraction={"source": source},
                               native_display_patch={"final_sha256": "f" * 64} if patched else None)

    def firmware(self):
        return {"firmware_builds": [
            {"guest": guest, "pci_cam_mode": False, "virtio_gpu_enable": guest == "ipados",
             "firmware": f"firmware/{guest}.fd", "firmware_sha256": "1" * 64,
             "vars": f"firmware/{guest}.vars.fd", "vars_sha256": "2" * 64}
            for guest in ("macos", "ipados")]}

    def test_custom_runtime_keeps_patch_and_extraction_provenance_in_fixed_allowlist(self):
        runtime = self.runtime()
        runtime.file_sha256["private-config.json"] = "9" * 64
        runtime.file_sha256["os-image.img"] = "9" * 64
        with patch.object(support, "object_from", return_value=self.firmware()):
            rows, returned_build, _, excluded = support.selected_files(runtime)
        self.assertIs(returned_build, runtime.build)
        self.assertEqual(excluded, runtime.excluded)
        self.assertEqual(sum(row[3] == "runtime" for row in rows), 71)
        self.assertTrue(all(row[1].is_relative_to(runtime.directory)
                            for row in rows if row[3] != "firmware" and row[3] != "original_firmware_record"))
        names = {row[0] for row in rows}
        self.assertIn("provenance/crosvm/extraction-record.json", names)
        for name in support.NATIVE_DISPLAY_PROVENANCE_FILES:
            row = next(row for row in rows if row[0] == "provenance/crosvm/" + name)
            self.assertEqual(row[2], runtime.file_sha256[name])
            self.assertEqual(row[3], "native_display_patch_provenance")
        self.assertNotIn("runtime/usr/lib/libdl_android.so", names)
        self.assertFalse(any("private-config" in name or "os-image" in name for name in names))

    def test_original_unpatched_runtime_does_not_require_future_patch_files(self):
        runtime = self.runtime(patched=False)
        for name in support.NATIVE_DISPLAY_PROVENANCE_FILES:
            runtime.file_sha256.pop(name)
        with patch.object(support, "object_from", return_value=self.firmware()):
            rows, _, _, _ = support.selected_files(runtime)
        self.assertFalse(any(row[3] == "native_display_patch_provenance" for row in rows))

    def test_selected_artifact_source_keeps_its_identity_without_reading_old_release(self):
        runtime = self.runtime()
        firmware_download = {"status": "complete", "release": {"tag_name": "firmware-one"},
                             "assets": []}
        with patch.object(support, "object_from", return_value=firmware_download) as read_record:
            sources = support.public_release_sources(runtime)
        read_record.assert_called_once_with(support.ROOT / "output/firmware-downloads/download-record.json")
        self.assertIs(sources["crosvm"]["source"], runtime.extraction["source"])
        self.assertEqual(sources["crosvm"]["source"]["artifact_id"], 555)
        self.assertEqual(sources["crosvm"]["source"]["name"], "new-runtime.zip")
        self.assertEqual(sources["crosvm"]["source_record"], str(runtime.directory / "extraction-record.json"))
        self.assertEqual(sources["crosvm"]["source"]["local_path"], "unneeded-local-download-path")

    def test_unverified_firmware_download_still_fails(self):
        with patch.object(support, "object_from", return_value={"status": "incomplete"}):
            with self.assertRaisesRegex(ValueError, "Completed firmware"):
                support.public_release_sources(self.runtime())

    def test_missing_native_provenance_digest_cannot_select_a_patch(self):
        runtime = self.runtime()
        runtime.file_sha256.pop(support.NATIVE_DISPLAY_PROVENANCE_FILES[0])
        with patch.object(support, "object_from", return_value=self.firmware()):
            with self.assertRaises(KeyError):
                support.selected_files(runtime)

    def test_apple5_default_outputs_are_separate_and_dated(self):
        args = support.parse_args(["--edition", "apple5"])
        self.assertEqual(args.output.name, "DroidVM-Apple5-runtime-support-20261120.zip")
        self.assertEqual(args.metadata_dir.name, "edition-apple5-20261120")
        self.assertEqual(args.runtime_dir, support.ROOT / "output/crosvm-builds-apple5")
        self.assertEqual(support.archive_info("MANIFEST.json", 1, 0o644, edition=args.edition).date_time,
                         (2026, 11, 20, 0, 0, 0))

    def test_legacy_default_output_paths_remain_the_original_paths(self):
        args = support.parse_args([])
        self.assertEqual(args.output, support.ROOT / "output/packages/DroidVM-Apple-runtime-support-20261119.zip")
        self.assertEqual(args.metadata_dir, support.ROOT / "output/runtime-support")
        self.assertEqual(args.runtime_dir, support.ROOT / "output/crosvm-builds")

    def test_explicit_runtime_and_readme_inputs_require_absolute_paths(self):
        for argument in ("--runtime-dir", "--readme"):
            with self.subTest(argument=argument), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    support.parse_args([argument, "relative-input"])
        runtime_dir = support.ROOT / "output/crosvm-builds-apple5"
        readme = support.ROOT / "output/runtime-support/README.zh-CN.md"
        args = support.parse_args(["--edition", "apple5", "--runtime-dir", str(runtime_dir),
                                  "--readme", str(readme)])
        self.assertEqual(args.runtime_dir, runtime_dir.resolve())
        self.assertEqual(args.readme, readme.resolve())


if __name__ == "__main__":
    unittest.main()
