"""Synthetic metadata regressions; no real Windows image, package or phone is used."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from prepare_windows_package import actual_stage, bind_config, bind_import, load_profile, qcow2_header, sha
from verify_vmpkg import PackageError, validate_manifest

# Documented RFC namespace IDs used only in synthetic metadata, never as phone IDs.
EXAMPLE_ID = str(uuid.NAMESPACE_DNS)
PARENT = "/storage/emulated/0/DroidVMWindows/Win11ARM64"
VM_DIR = PARENT + "/SyntheticContractFixture"
NAMES = {"image": "Windows11.qcow2", "firmware": "edk2-windows.fd", "vars": "edk2-windows.vars.fd"}
ARCHIVE = {key: ("boots/" if key == "firmware" else "disks/") + name for key, name in NAMES.items()}


def fixture_header(*, backing=False, external_data=False, virtual_size=64 * 1024**3):
    raw = bytearray(104)
    raw[:4] = b"QFI\xfb"
    struct.pack_into(">I", raw, 4, 3)
    struct.pack_into(">QI", raw, 8, 104 if backing else 0, 5 if backing else 0)
    struct.pack_into(">I", raw, 20, 16)
    struct.pack_into(">Q", raw, 24, virtual_size)
    struct.pack_into(">Q", raw, 72, (1 << 2) if external_data else 0)
    struct.pack_into(">I", raw, 100, 104)
    return bytes(raw)


def fixture_binding_inputs():
    disks = []
    for key, index, attached in [("image", 0, True), ("vars", -1, False)]:
        disks.append({"name": NAMES[key], "index": index, "attached": attached,
                      "readonly": False, "bus": "virtio", "format": "qcow2" if attached else "raw",
                      "archive_path": ARCHIVE[key], "path": PARENT + "/" + NAMES[key], "size": 104})
    boots = [{"name": NAMES["firmware"], "kind": "uefi", "archive_path": ARCHIVE["firmware"],
              "path": PARENT + "/boot/" + NAMES["firmware"], "size": 104}]
    raw = {"manifest_version": 2, "format": "vmpkg", "created_at": 0,
           "app_version": "0.0.6.r242.g3348830", "app_version_code": 2720,
           "app_build_type": "release", "compression": "gzip", "vm": {"name": "SyntheticContractFixture"},
           "disks": disks, "boots": boots, "networks": []}
    manifest = validate_manifest(json.dumps(raw).encode("utf-8"))
    receipt = {"event": "vm_import_status", "phase": "done", "done": 3, "total": 3,
               "vm_id": EXAMPLE_ID, "vm_name": "SyntheticContractFixture",
               "disks": copy.deepcopy(disks), "boots": copy.deepcopy(boots)}
    for disk in receipt["disks"]:
        disk["path"] = VM_DIR + "/" + disk["name"]
    receipt["boots"][0]["path"] = VM_DIR + "/boot/" + NAMES["firmware"]
    current = {"id": EXAMPLE_ID, "name": receipt["vm_name"], "cpu_count": 4, "memory_mb": 6144,
               "disks": [{"path": receipt["disks"][0]["path"], "readonly": False, "bus": "virtio"}],
               "boot": {"protocol": "uefi", "uefi": {"firmware": receipt["boots"][0]["path"], "vars": "", "vars_enabled": False}},
               "networks": [{"network_id": str(uuid.NAMESPACE_URL), "future_field": "preserve"}],
               "unknown_selected_field": {"value": None, "choices": ["kept", 2]}}
    report = {"phone_import_target_dir": PARENT, "archive_paths": ARCHIVE}
    return manifest, report, receipt, {"success": True, "data": current}


class WindowsPackageContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="droidvm-windows-contract-")
        self.directory = Path(self.temporary.name).resolve()
        self.assertTrue(self.directory.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temporary.cleanup)

    def test_missing_real_stage_fails_without_creating_output(self):
        destination = self.directory / "never-created"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/prepare_windows_package.py"),
                                 "prepare", "--stage", str(self.directory / "missing-real-stage"),
                                 "--output", str(destination)], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Completed real Windows source stage is missing", json.loads(result.stderr)["error"])
        self.assertFalse(destination.exists())

    def test_explicit_synthetic_build_record_is_rejected(self):
        profile, _, _ = load_profile(ROOT / "profiles/windows11-arm64.json")
        record = {"format": "droidvm-windows-build-record-v1", "status": "complete",
                  "evidence_mode": "actual_windows_build", "fixture_only": True}
        (self.directory / "build-record.json").write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(PackageError, "Synthetic fixtures"):
            actual_stage(self.directory, profile)

    def test_qcow2_external_storage_is_rejected(self):
        path = self.directory / "synthetic-header.qcow2"
        for kwargs, message in [({"backing": True}, "external backing"),
                                ({"external_data": True}, "external data"),
                                ({"virtual_size": 1}, "virtual size differs")]:
            with self.subTest(kwargs=kwargs):
                path.write_bytes(fixture_header(**kwargs))
                with self.assertRaisesRegex(PackageError, message):
                    qcow2_header(path, 64 * 1024**3)

    def test_binding_preserves_current_config_except_private_vars(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        before = copy.deepcopy(response)
        bound, _, _ = bind_config(manifest, report, {"type": "event", "data": receipt}, response)
        expected = copy.deepcopy(response["data"])
        expected["boot"]["uefi"].update(vars=VM_DIR + "/" + NAMES["vars"], vars_enabled=True)
        self.assertEqual(bound, expected)
        self.assertEqual(response, before)

    def test_native_default_or_selected_parent_can_differ_from_preparation_plan(self):
        for actual_parent in ["/storage/emulated/0/DroidVM", "/storage/emulated/0/MyVMs/SelectedFolder"]:
            with self.subTest(actual_parent=actual_parent):
                manifest, report, receipt, response = fixture_binding_inputs()
                before_report = copy.deepcopy(report)
                actual_directory = actual_parent + "/SyntheticContractFixture"
                for disk in receipt["disks"]:
                    disk["path"] = actual_directory + "/" + disk["name"]
                receipt["boots"][0]["path"] = actual_directory + "/boot/" + NAMES["firmware"]
                response["data"]["disks"][0]["path"] = receipt["disks"][0]["path"]
                response["data"]["boot"]["uefi"]["firmware"] = receipt["boots"][0]["path"]
                expected = copy.deepcopy(response["data"])
                expected["boot"]["uefi"].update(vars=receipt["disks"][1]["path"], vars_enabled=True)
                bound, _, _ = bind_config(manifest, report, receipt, response)
                self.assertEqual(bound, expected)
                self.assertEqual(report, before_report)

    def test_public_binding_records_actual_directory_separately_from_plan(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        actual_directory = "/storage/emulated/0/DroidVM/SyntheticContractFixture"
        for disk in receipt["disks"]:
            disk["path"] = actual_directory + "/" + disk["name"]
        receipt["boots"][0]["path"] = actual_directory + "/boot/" + NAMES["firmware"]
        response["data"]["disks"][0]["path"] = receipt["disks"][0]["path"]
        response["data"]["boot"]["uefi"]["firmware"] = receipt["boots"][0]["path"]
        prepared = self.directory / "synthetic-prepared-metadata"
        prepared.mkdir()
        (prepared / "manifest.json").write_bytes(manifest.raw)
        report.update(format="droidvm-windows-preparation-v1", operation="prepared_windows_package_inputs",
                      requires_post_import_vars_binding=True, manifest_sha256=sha(manifest.raw))
        (prepared / "preparation-report.json").write_text(json.dumps(report), encoding="utf-8")
        receipt_file, response_file = self.directory / "synthetic-import-event.json", self.directory / "synthetic-get-response.json"
        receipt_file.write_text(json.dumps({"type": "event", "data": receipt}), encoding="utf-8")
        response_file.write_text(json.dumps(response), encoding="utf-8")
        output = self.directory / "synthetic-bound-metadata"
        bind_import(prepared, receipt_file, response_file, output)
        saved = json.loads((output / "binding-report.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["actual_vm_directory"], actual_directory)
        self.assertEqual(saved["preparation_import_parent_plan"], PARENT)
        self.assertFalse(saved["preparation_parent_used_as_actual_boundary"])

    def test_partial_and_boolean_completion_counts_are_rejected(self):
        for changes in [{"phase": "pack"}, {"done": 2}, {"done": True, "total": True}]:
            with self.subTest(changes=changes):
                manifest, report, receipt, response = fixture_binding_inputs()
                receipt.update(changes)
                with self.assertRaises(PackageError):
                    bind_config(manifest, report, receipt, response)

    def test_cross_vm_and_failed_get_response_are_rejected(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        response["data"]["id"] = str(uuid.NAMESPACE_OID)
        with self.assertRaisesRegex(PackageError, "different VM"):
            bind_config(manifest, report, receipt, response)
        manifest, report, receipt, response = fixture_binding_inputs()
        response["success"] = False
        with self.assertRaisesRegex(PackageError, "successful current"):
            bind_config(manifest, report, receipt, response)

    def test_renamed_current_vm_retains_its_name(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        response["data"]["name"] = "RenamedSyntheticVM"
        expected = copy.deepcopy(response["data"])
        expected["boot"]["uefi"].update(vars=VM_DIR + "/" + NAMES["vars"], vars_enabled=True)
        bound, _, _ = bind_config(manifest, report, receipt, response)
        self.assertEqual(bound, expected)

    def test_current_disk_options_are_preserved(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        response["data"]["disks"][0].update(bus="scsi", readonly=True)
        expected = copy.deepcopy(response["data"])
        expected["boot"]["uefi"].update(vars=VM_DIR + "/" + NAMES["vars"], vars_enabled=True)
        bound, _, _ = bind_config(manifest, report, receipt, response)
        self.assertEqual(bound, expected)

    def test_duplicate_wrong_attribute_and_escaped_vars_are_rejected(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        for case in ["duplicate", "attached", "escape", "different-directory", "reused-path"]:
            with self.subTest(case=case):
                changed = copy.deepcopy(receipt)
                if case == "duplicate":
                    changed["disks"][1] = copy.deepcopy(changed["disks"][0])
                elif case == "attached":
                    changed["disks"][1]["attached"] = True
                elif case == "escape":
                    changed["disks"][1]["path"] = PARENT + "/../Debian/" + NAMES["vars"]
                elif case == "reused-path":
                    changed["disks"][1]["path"] = changed["disks"][0]["path"]
                    changed["disks"][1]["name"] = changed["disks"][0]["name"]
                else:
                    changed["disks"][1]["path"] = PARENT + "/AnotherVM/" + NAMES["vars"]
                with self.assertRaises(PackageError):
                    bind_config(manifest, report, changed, response)

    def test_private_vars_already_attached_as_disk_are_rejected(self):
        manifest, report, receipt, response = fixture_binding_inputs()
        response["data"]["disks"].append({"path": receipt["disks"][1]["path"], "readonly": False, "bus": "virtio"})
        with self.assertRaisesRegex(PackageError, "attached as a guest disk"):
            bind_config(manifest, report, receipt, response)


if __name__ == "__main__":
    unittest.main()
