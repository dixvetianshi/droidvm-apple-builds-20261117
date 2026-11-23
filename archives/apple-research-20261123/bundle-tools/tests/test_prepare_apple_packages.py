"""Apple block argument regressions; no OS images, packages or device are accessed."""
from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))
from prepare_apple_packages import device_config, extra_options


class AppleBlockArguments(unittest.TestCase):
    def make_recipe(self, guest):
        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary) / "vm-template.json"
            template.write_text(json.dumps({"config": {"screens": {"gpu-0": {"retained": "kept"},
                "simplefb": {"retained": "kept"}}, "serial_ports": []}}), encoding="utf-8")
            args = SimpleNamespace(vm_template=template, guest=guest, profile="full", app_uid=12123,
                network_id="synthetic-network", phone_media_dir="/storage/emulated/0/Chosen folder")
            names = ("boot.img", "data-store.img") if guest == "macos" else ("droidvm-disk.img", "os.img", "systemos.img", "data-store.img")
            return device_config(args, {name: {} for name in names}, {"path": "edk2-macos.fd" if guest == "macos" else "edk2-virtio-gpu.fd"})

    def test_ipad_recipe_uses_four_gib_with_two_capacity_tiers(self):
        config = self.make_recipe("ipados")
        self.assertEqual(config["memory_mb"], 4096)
        self.assertEqual(config["cpu_count"], 4)
        self.assertEqual(config["cpu_affinity"], "0=2:1=3:2=6:3=7")
        self.assertEqual(config["cpu_capacity"], "0=792,1=792,2=1024,3=1024")
        self.assertEqual(config["cpu_clusters"], "0-1;2-3")
        self.assertFalse(config["cpu_topology_auto"])
        self.assertEqual(config["screens"]["gpu-0"]["retained"], "kept")
        self.assertEqual(config["screens"]["simplefb"]["exporter"], "none")
        self.assertEqual(config["networks"][0]["network_id"], "synthetic-network")

    def test_fixed_mac_recipe_keeps_five_gib_and_exports_the_existing_simplefb(self):
        config = self.make_recipe("macos")
        self.assertEqual(config["memory_mb"], 5120)
        self.assertEqual(config["cpu_count"], 8)
        self.assertEqual(config["cpu_clusters"], "0-5;6-7")
        self.assertEqual(config["screens"]["simplefb"]["exporter"], "native")
        self.assertEqual(config["screens"]["simplefb"]["width"], 1920)
        self.assertEqual(config["screens"]["simplefb"]["height"], 1080)
        self.assertTrue(config["screens"]["simplefb"]["enabled"])
        self.assertEqual(config["screens"]["simplefb"]["retained"], "kept")
        self.assertEqual(config["screens"]["gpu-0"]["exporter"], "native")

    def test_ipad_mmio_disks_match_shared_storage_lock_policy_in_both_profiles(self):
        directory = "/storage/emulated/0/Chosen folder/iPad (2)"
        paths = {name: directory + "/" + name for name in ("os.img", "systemos.img", "data-store.img")}
        for profile in ("full", "basic"):
            with self.subTest(profile=profile):
                args = extra_options("ipados", profile, 12123, paths, directory + "/runtime.dtb")
                block_values = [args[index + 1] for index, arg in enumerate(args) if arg == "--virtio-mmio-block"]
                self.assertEqual(block_values, [paths["os.img"] + ",ro=true,lock=false",
                                               paths["systemos.img"] + ",ro=true,lock=false",
                                               paths["data-store.img"] + ",lock=false"])
                self.assertEqual(args[1], directory + "/runtime.dtb")
                self.assertNotIn("ro=true", block_values[2])
                if profile == "full":
                    self.assertIn("kind=decoder,uid=12123", args)

    def test_mac_pci_configuration_does_not_gain_mmio_block_disks(self):
        args = extra_options("macos", "full", 12124, {}, "/storage/emulated/0/macOS/runtime.dtb")
        self.assertNotIn("--virtio-mmio-block", args)
        self.assertEqual(args[args.index("--mbi-spis") + 1], "64")
        media_values = [args[index + 1] for index, arg in enumerate(args) if arg == "--virtio-media"]
        self.assertEqual(media_values, ["kind=decoder,uid=12124", "kind=encoder,uid=12124"])
        self.assertIn("--virtio-mmio-media", args)
        self.assertIn("kind=encoder,uid=12124", args)


if __name__ == "__main__":
    unittest.main()
