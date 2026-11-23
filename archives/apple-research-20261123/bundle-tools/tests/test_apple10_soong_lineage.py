"""Schema2 source/patch admission fixtures; no Android build or binary execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BUNDLE = Path(__file__).resolve().parents[2]
TOOLS = BUNDLE / "tools"
sys.dont_write_bytecode = True
sys.path.insert(0, str(TOOLS))
import runtime_artifact as runtime

NEW_SOONG_SHA = "253ef1a117c6f46986cb91773ea7e11e5069bcc2182efd4898a2662e7efcdc32"
OLD_SOONG_SHA = "4c39e11c5466a9480f7f77c7fedd016d31373521b3bb29c309f57fc2246355e8"
SYSROOT_SHA = "34e197a83754f41d4f288aad04f0060ac9021ade47ac0801adb11ad5d4a31f85"
COMPANION_MEMBER = "diagnostics/rust-sysroot-unwind.patch"


def lineage_fixture():
    """Source metadata only; the applied flags model the future producer contract."""
    host = runtime.apple10_source_manifest("host")
    soong = runtime.apple10_source_manifest("soong")
    return {
        "native_lifecycle_source": {
            "source_manifest_sha256": runtime.APPLE10_SOURCE_LINEAGE["host"][1],
            "lifecycle": host["lifecycle"], "source_provenance": host["source_provenance"],
            "verification_scope": host["verification"],
        },
        "soong_unwind_source": {
            **soong, "source_manifest_sha256": NEW_SOONG_SHA,
            "applied_only_to_ci_build_tree": True, "device_panic_execution_verified": False,
            "source_lock_commits_changed": False,
            "sysroot_companion_retained_patch": COMPANION_MEMBER,
            "sysroot_companion_patch_sha256": SYSROOT_SHA,
            "sysroot_companion_applied": True, "sysroot_source_bytes_verified": True,
        },
        "source_manifest_sha256": {kind: row[1] for kind, row in runtime.APPLE10_SOURCE_LINEAGE.items()},
    }


class Apple10SoongLineageTest(unittest.TestCase):
    def test_formal_source_root_and_exact_schema2_snapshot(self):
        self.assertEqual(Path(runtime.__file__).resolve(), (TOOLS / "runtime_artifact.py").resolve())
        path = TOOLS / "release-source-lineage/apple10-soong-unwind-source.json"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), NEW_SOONG_SHA)
        self.assertEqual(runtime.APPLE10_SOURCE_LINEAGE["soong"][1], NEW_SOONG_SHA)
        source = runtime.apple10_source_manifest("soong")
        self.assertEqual(source["schema_version"], 2)
        self.assertEqual(source["source_provenance"]["first_stage_source_manifest_sha256"], OLD_SOONG_SHA)
        self.assertEqual(len(source["sysroot_companion"]["runtime_dependency_modules"]), 8)
        self.assertEqual(len(source["sysroot_companion"]["unchanged_runtime_source_identities"]), 3)

    def test_source_fixture_matches_the_new_producer_contract(self):
        lineage = lineage_fixture()
        self.assertIs(runtime.validate_apple10_source_lineage(lineage), lineage)
        self.assertIs(lineage["soong_unwind_source"]["device_panic_execution_verified"], False)

    def test_old_schema1_is_failure_provenance_and_cannot_be_admitted(self):
        source = copy.deepcopy(runtime.apple10_source_manifest("soong"))
        source["schema_version"] = 1
        source["limits"].pop()
        source.pop("sysroot_companion")
        source.pop("source_provenance")
        raw = (json.dumps(source, indent=2) + "\n").encode()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), OLD_SOONG_SHA)
        lineage = lineage_fixture()
        lineage["soong_unwind_source"] = {
            **source, "source_manifest_sha256": OLD_SOONG_SHA,
            "applied_only_to_ci_build_tree": True, "device_panic_execution_verified": False,
            "source_lock_commits_changed": False,
        }
        lineage["source_manifest_sha256"]["soong"] = OLD_SOONG_SHA
        with self.assertRaises(ValueError): runtime.validate_apple10_source_lineage(lineage)

    def test_missing_or_wrong_new_companion_fields_are_rejected(self):
        fields = ("sysroot_companion", "sysroot_companion_retained_patch", "sysroot_companion_patch_sha256",
                  "sysroot_companion_applied", "sysroot_source_bytes_verified")
        for field in fields:
            lineage = lineage_fixture()
            lineage["soong_unwind_source"].pop(field)
            with self.subTest(missing=field), self.assertRaises(ValueError):
                runtime.validate_apple10_source_lineage(lineage)
        for field, value in (("sysroot_companion_retained_patch", "diagnostics/unreviewed.patch"),
                             ("sysroot_companion_patch_sha256", "0" * 64),
                             ("sysroot_companion_applied", False), ("sysroot_source_bytes_verified", False)):
            lineage = lineage_fixture()
            lineage["soong_unwind_source"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                runtime.validate_apple10_source_lineage(lineage)

    def test_dependency_declarations_and_unchanged_sources_are_bound(self):
        for failure in ("module_omitted", "declaration_hash", "dependency", "runtime_source", "stdlib_unwind"):
            lineage = lineage_fixture()
            source = lineage["soong_unwind_source"]["sysroot_companion"]
            if failure == "module_omitted": source["runtime_dependency_modules"].pop()
            elif failure == "declaration_hash": source["runtime_dependency_modules"][0]["source_declaration_sha256"] = "0" * 64
            elif failure == "dependency": source["runtime_dependency_modules"][0]["rlibs"].pop()
            elif failure == "runtime_source": source["unchanged_runtime_source_identities"][0]["sha256"] = "0" * 64
            else: source["stdlib_target_rlibs_after"] = source["stdlib_target_rlibs_before"]
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                runtime.validate_apple10_source_lineage(lineage)

    def test_boolean_source_flags_cannot_be_numeric_success_claims(self):
        for field, value in (("applied_only_to_ci_build_tree", 1), ("sysroot_companion_applied", 1),
                             ("sysroot_source_bytes_verified", 1), ("device_panic_execution_verified", 0),
                             ("source_lock_commits_changed", 0), ("system_or_phone_changes", 0)):
            lineage = lineage_fixture()
            lineage["soong_unwind_source"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "boolean"):
                runtime.validate_apple10_source_lineage(lineage)

    def test_original_companion_patch_bytes_and_extraction_hash_are_both_required(self):
        # The fixture runs only this source/patch boundary. It does not fabricate
        # a complete runtime extraction or execute the host-helper binaries.
        evidence = Path(os.environ.get("APPLE10_SOONG_TEST_OUTPUT",
                        str(BUNDLE / "output/apple10-soong-intake-schema2-tests"))).resolve()
        self.assertTrue(evidence.is_relative_to((BUNDLE / "output").resolve()))
        evidence.mkdir(parents=True, exist_ok=True)
        fixtures = Path(__file__).parent / "fixtures"
        primary_raw = (fixtures / "apple10-soong-device-unwind.patch").read_bytes()
        companion_raw = (fixtures / "apple10-rust-sysroot-unwind.patch").read_bytes()
        source = runtime.apple10_source_manifest("soong")
        self.assertEqual(hashlib.sha256(primary_raw).hexdigest(), source["patch_sha256"])
        self.assertEqual(hashlib.sha256(companion_raw).hexdigest(), SYSROOT_SHA)
        with tempfile.TemporaryDirectory(prefix="soong-source-fixture-", dir=evidence) as temporary:
            directory = Path(temporary)
            lineage = lineage_fixture()
            native = lineage["native_lifecycle_source"]
            soong = lineage["soong_unwind_source"]
            memory, lease = {}, {"host_fragment_smoke": {"fixture_sha256": hashlib.sha256(b"metadata-only fragment fixture").hexdigest()}}
            values = {"native-lifecycle-source.json": native, "soong-unwind-source.json": soong,
                      "diagnostics/gunyah-host-boundary-tests/host-boundary-test-receipt.json": memory,
                      "diagnostics/gunyah-lease-boundary-tests/lease-boundary-test-receipt.json": lease}
            build = {"native_lifecycle_source": native, "soong_unwind_source": soong,
                     "host_memory_boundary_tests": memory, "lease_production_helper_tests": lease}
            members = {"diagnostics/soong-device-unwind.patch": primary_raw, COMPANION_MEMBER: companion_raw,
                       "diagnostics/gunyah-lease-boundary-tests/labelled-owner-fence-host-fragment.rs": b"metadata-only fragment fixture"}
            hashes = {}
            for name, raw in members.items():
                target = directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                hashes[name] = hashlib.sha256(raw).hexdigest()
            with patch.object(runtime, "_checked_record", side_effect=lambda _dir, name, _hashes: values[name]), \
                    patch.object(runtime, "validate_apple10_helper_receipts", return_value=(memory, lease)):
                self.assertEqual(runtime._apple10_build_lineage(directory, build, hashes), lineage)
                changed = dict(hashes)
                changed[COMPANION_MEMBER] = "0" * 64
                with self.assertRaisesRegex(ValueError, "sysroot companion"):
                    runtime._apple10_build_lineage(directory, build, changed)
                (directory / COMPANION_MEMBER).write_bytes(companion_raw + b"changed")
                with self.assertRaisesRegex(ValueError, "sysroot companion"):
                    runtime._apple10_build_lineage(directory, build, hashes)
                (directory / COMPANION_MEMBER).unlink()
                with self.assertRaisesRegex(ValueError, "regular input"):
                    runtime._apple10_build_lineage(directory, build, hashes)


if __name__ == "__main__":
    unittest.main()
