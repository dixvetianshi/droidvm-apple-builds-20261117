"""Apple NAT preparation and native import binding boundaries, without OS images or a device."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))
from prepare_apple_packages import (
    apple_network_recipe, bind_import, prepare, preserved_import_networks,
    recommend_network_import,
)
from verify_vmpkg import PackageError


class AppleNetworkImport(unittest.TestCase):
    WIFI_ID = str(uuid.NAMESPACE_DNS)
    NAT_ID = str(uuid.NAMESPACE_URL)

    def wifi(self):
        return {"schema": 2, "id": self.WIFI_ID, "name": "Original WiFi",
                "bridge_name": "br1971c95f", "bridge_type": "linux", "uplink_mode": "l2",
                "l2": {"uplink": "WiFi", "pseudo_bridge": True}, "auto_up": True}

    def nat(self, network_id=None):
        network = apple_network_recipe()
        network.pop("pkg_network_ref")
        network["id"] = network_id or self.NAT_ID
        return network

    def registry(self, directory, networks):
        path = directory / "registry.json"
        path.write_text(json.dumps({"networks": networks}), encoding="utf-8")
        return path

    def test_recipe_is_shared_with_the_apk_and_each_factory_result_is_independent(self):
        resource = ROOT / "sources/DroidVM-Apple/app/src/main/resources/apple-guest-network.json"
        self.assertEqual(apple_network_recipe(), json.loads(resource.read_text(encoding="utf-8")))
        changed = apple_network_recipe()
        changed["l3"]["vlans"][0]["dns_servers"].append("192.168.237.2")
        self.assertEqual(apple_network_recipe()["l3"]["vlans"][0]["dns_servers"], [])

    def test_wifi_only_inventory_recommends_independent_nat_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = self.registry(Path(temporary), [self.wifi()])
            before = registry.read_bytes()
            selected, recipe, plan, binding = recommend_network_import(registry, self.WIFI_ID)
            self.assertEqual(selected, self.wifi())
            self.assertEqual(recipe["name"], "br-apple-nat")
            self.assertEqual(recipe["bridge_type"], "gvisor")
            self.assertEqual(recipe["uplink_mode"], "l3")
            self.assertEqual(plan, [{"ref": "apple-uplink", "action": "create", "config": recipe}])
            self.assertEqual(binding, {"pkg_network_ref": "apple-uplink"})
            self.assertNotIn("id", recipe)
            self.assertEqual(registry.read_bytes(), before)

    def test_existing_gvisor_l3_is_reused_and_an_explicit_same_kind_choice_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            second_id = str(uuid.NAMESPACE_OID)
            registry = self.registry(directory, [self.wifi(), self.nat(), self.nat(second_id)])
            selected, _, plan, binding = recommend_network_import(registry, self.WIFI_ID)
            self.assertEqual(selected["id"], self.WIFI_ID)
            self.assertEqual(plan, [{"ref": "apple-uplink", "action": "join", "network_id": self.NAT_ID}])
            self.assertEqual(binding, {"network_id": self.NAT_ID})
            _, _, plan, binding = recommend_network_import(registry, second_id)
            self.assertEqual(plan[0]["network_id"], second_id)
            self.assertEqual(binding["network_id"], second_id)

    def prepare_metadata(self, directory):
        template = directory / "template.json"
        template.write_text(json.dumps({"config": {"screens": {"gpu-0": {}, "simplefb": {}},
                                                     "serial_ports": []}}), encoding="utf-8")
        registry = self.registry(directory, [self.wifi()])
        args = SimpleNamespace(guest="ipados", profile="full", app_uid=12123,
            app_build_type="release", output=directory / "prepared", network_registry=registry,
            network_id=self.WIFI_ID, vm_template=template,
            phone_media_dir="/storage/emulated/0/Chosen folder", file_record=directory / "files.json",
            compression="none")
        files = {}
        # The production stage/runtime owners are isolated here. These tiny members test only
        # metadata, manifest validation and source-map handling; they are not bootable images.
        for name in ("droidvm-disk.img", "os.img", "systemos.img", "data-store.img"):
            path = directory / name
            content = ("synthetic " + name).encode("utf-8")
            path.write_bytes(content)
            files[name] = {"path": str(path), "bytes": len(content),
                           "sha256": hashlib.sha256(content).hexdigest()}
        firmware = directory / "edk2-virtio-gpu.fd"
        firmware.write_bytes(b"synthetic firmware")
        firmware_record = {"path": str(firmware), "bytes": firmware.stat().st_size,
                           "sha256": hashlib.sha256(firmware.read_bytes()).hexdigest()}
        with mock.patch("prepare_apple_packages.stage_files", return_value=(files, {})), \
             mock.patch("prepare_apple_packages.verify_runtime", return_value=(firmware_record, {})):
            prepare(args)
        return args.output

    def test_prepare_places_the_shared_nat_in_manifest_and_leaves_actual_binding_to_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prepared = self.prepare_metadata(directory)
            manifest = json.loads((prepared / "manifest.json").read_text(encoding="utf-8"))
            config = json.loads((prepared / "device-config.json").read_text(encoding="utf-8"))
            report = json.loads((prepared / "preparation-report.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["networks"], [apple_network_recipe()])
            self.assertEqual(manifest["vm"]["networks"][0]["pkg_network_ref"], "apple-uplink")
            self.assertNotIn("network_id", config["networks"][0])
            self.assertEqual(config["networks"][0]["pkg_network_ref"], "apple-uplink")
            self.assertEqual(report["selected_network"], self.wifi())
            self.assertTrue(report["requires_current_vm_networks_for_binding"])
            self.assertEqual(report["network_import_authority"], "import_preview")

    def test_binding_keeps_all_actual_nic_fields_and_refuses_another_vm(self):
        vm_id = str(uuid.NAMESPACE_X500)
        networks = [{"network_id": self.NAT_ID, "mac_address": None,
                     "ipv4": {"offset": 41}, "future_field": {"unknown": None}}, {}]
        response = {"success": True, "data": {"id": vm_id, "networks": networks}}
        prepared = {"networks": [{"pkg_network_ref": "apple-uplink"}]}
        bound = preserved_import_networks(vm_id, response)
        self.assertEqual(bound, networks)
        bound[0]["future_field"]["unknown"] = "changed"
        self.assertIsNone(networks[0]["future_field"]["unknown"])
        self.assertEqual(prepared["networks"], [{"pkg_network_ref": "apple-uplink"}])
        with self.assertRaisesRegex(PackageError, "different VM"):
            preserved_import_networks(self.WIFI_ID, response)

    def test_missing_or_unresolved_current_networks_cannot_produce_a_bound_config(self):
        with self.assertRaisesRegex(PackageError, "--vm-get-result"):
            preserved_import_networks(self.NAT_ID)
        response = {"success": True, "data": {"id": self.NAT_ID,
                    "networks": [{"pkg_network_ref": "apple-uplink"}]}}
        with self.assertRaisesRegex(PackageError, "unresolved"):
            preserved_import_networks(self.NAT_ID, response)

    def test_native_bind_uses_current_imported_nics_and_missing_vm_get_writes_no_bound_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prepared = self.prepare_metadata(directory)
            manifest = json.loads((prepared / "manifest.json").read_text(encoding="utf-8"))
            vm_id = str(uuid.NAMESPACE_X500)
            receipt = {"event": "vm_import_status", "phase": "done", "vm_id": vm_id,
                       "vm_name": "Imported Apple VM", "done": 5, "total": 5}
            for section in ("disks", "boots"):
                receipt[section] = [{**entry, "path": "/storage/emulated/0/Chosen folder/import/" +
                                    ("boot/" if section == "boots" else "") + entry["name"]}
                                   for entry in manifest[section]]
            receipt_path = directory / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            bind_args = SimpleNamespace(prepared=prepared, import_result=receipt_path,
                                        output=directory / "bound", vm_get_result=None)
            report_path = prepared / "preparation-report.json"
            original_report = json.loads(report_path.read_text(encoding="utf-8"))
            config_path = prepared / "device-config.json"
            original_config = json.loads(config_path.read_text(encoding="utf-8"))
            for metadata_version in ("new", "old"):
                with self.subTest(metadata_version=metadata_version):
                    report = dict(original_report)
                    config = dict(original_config)
                    if metadata_version == "old":
                        for key in ("requires_current_vm_networks_for_binding", "network_import_authority"):
                            report.pop(key)
                        config["networks"] = [{"network_id": self.WIFI_ID,
                                               "mac_address": "02:00:00:aa:bb:01"}]
                    report_path.write_text(json.dumps(report), encoding="utf-8")
                    config_path.write_text(json.dumps(config), encoding="utf-8")
                    with self.assertRaisesRegex(PackageError, "--vm-get-result"):
                        bind_import(bind_args)
                    self.assertFalse(bind_args.output.exists())
            chosen = [{"network_id": self.NAT_ID, "mac_address": "02:de:ad:be:ef:01",
                       "future_field": "kept from import"}]
            vm_get = directory / "vm-get.json"
            vm_get.write_text(json.dumps({"success": True, "data": {"id": vm_id, "networks": chosen}}),
                              encoding="utf-8")
            bind_args.vm_get_result = vm_get
            bind_import(bind_args)
            config = json.loads((bind_args.output / "device-config.json").read_text(encoding="utf-8"))
            self.assertEqual(config["networks"], chosen)
            self.assertEqual(config["id"], vm_id)
            self.assertFalse(config["auto_up"])
            self.assertNotIn("pkg_network_ref", config["networks"][0])


if __name__ == "__main__":
    unittest.main()
