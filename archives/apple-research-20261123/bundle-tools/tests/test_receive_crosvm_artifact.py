"""Real tiny ZIP boundaries; metadata and runtime bytes are synthetic fixtures.

The admitted fixture checks reception/owner compatibility only. It never calls
GitHub, builds or runs crosvm, packages an APK, or contacts a phone. Only the
reviewed small patch, source lock and original shim are read from local evidence.
"""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
import zlib


TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import receive_crosvm_artifact as receiver
import runtime_artifact as runtime_owner


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def native_patch_record():
    return {
        "project_path": "packages/modules/Virtualization",
        "project_url": "https://github.com/Droid-VM/Virtualization",
        "upstream_commit": runtime_owner.VIRTUALIZATION_COMMIT,
        "source_path": "libs/android_display_backend/crosvm_android_display_client.cpp",
        "source_sha256_before": runtime_owner.NATIVE_DISPLAY_SOURCE_BEFORE,
        "source_sha256_after": runtime_owner.NATIVE_DISPLAY_SOURCE_AFTER,
        "patch": "diagnostics/android-display-owner.patch",
        "patch_sha256": runtime_owner.NATIVE_DISPLAY_PATCH_SHA256,
        "source_lock_snapshot": "profiles/crosvm-display-source-lock.json",
        "source_lock_snapshot_sha256": runtime_owner.SOURCE_LOCK_SHA256,
        "build_linkage": "libcrosvm_android_display_client (cc_library_static) linked into crosvm",
        "synthetic_boundary_fixture": True,
        "real_android_surface_vulkan_verification": "not performed",
        "phone_apple_guest_boot_verification": "not performed",
    }


class Fixture:
    def __init__(self, directory, *, runtime_stub=False, host_policy=False):
        self.directory = directory
        self.archive = directory / "synthetic-actions.zip"
        self.artifact_json = directory / "synthetic-artifact-api.json"
        self.run_json = directory / "synthetic-run-api.json"
        self.output = directory / "new-runtime"
        self.selection = {}
        patch = (ROOT / "output/native-display-rebuild-source/patches/android-display-owner.patch").read_bytes()
        source_lock = (ROOT / "output/native-display-rebuild-source/profiles/crosvm-display-source-lock.json").read_bytes()
        shim = (ROOT / "output/crosvm-builds/shim/shim.bin").read_bytes()
        assert digest(patch) == runtime_owner.NATIVE_DISPLAY_PATCH_SHA256
        assert digest(source_lock) == runtime_owner.SOURCE_LOCK_SHA256
        assert digest(shim) == runtime_owner.ORIGINAL_SHIM_SHA256
        binary = b"synthetic non-executable crosvm fixture; not a native build\n" + shim
        if host_policy:
            # A tiny synthetic ELF header checks architecture admission only.
            # It is never executable and does not establish a compiled provider.
            header = bytearray(64)
            header[:7] = b"\x7fELF\x02\x01\x01"
            struct.pack_into("<HH", header, 16, 3, 183)
            binary = bytes(header) + binary
        self.members = {
            "runtime/usr/bin/crosvm": binary,
            "full-build/crosvm": binary,
            "full-build/libdl_android.so": b"synthetic retained link stub\n",
            "shim/shim.bin": shim,
            "shim/shim.elf": b"synthetic shim ELF record; not executable\n",
            "source-lock.json": source_lock,
            "source-manifest.xml": b"<manifest synthetic_boundary_fixture='true'/>\n",
            "static-options.json": json_bytes({"synthetic_boundary_fixture": True}),
            "native-display-patch.json": json_bytes(native_patch_record()),
            "diagnostics/android-display-owner.patch": patch,
            "diagnostics/build-exit-code.txt": b"0\n",
            "diagnostics/crosvm-build.log": b"Synthetic ZIP boundary fixture. Native build not performed.\n",
        }
        for index in range(70):
            self.members[f"runtime/usr/lib/library{index:02}.so"] = f"synthetic library {index}\n".encode("ascii")
        if runtime_stub:
            self.members["runtime/usr/lib/libdl_android.so"] = self.members["full-build/libdl_android.so"]
        build = {
            "synthetic_boundary_fixture": True,
            "runtime_files": {name: digest(data) for name, data in self.members.items() if name.startswith("runtime/")},
            "full_build_files": {name: digest(data) for name, data in self.members.items() if name.startswith(("full-build/", "shim/"))},
            "native_display_patch": native_patch_record(),
            "source_lock_snapshot_sha256": runtime_owner.SOURCE_LOCK_SHA256,
            "source_lock_reused_without_ref_resolution": True,
            "shim_sha256": runtime_owner.ORIGINAL_SHIM_SHA256,
            "shim_expected_sha256": runtime_owner.ORIGINAL_SHIM_SHA256,
            "retained_shim_embedded_in_crosvm": True,
            "android_loader_verification": "not performed; synthetic non-executable fixture",
            "phone_apple_guest_boot_verification": "not performed; synthetic fixture",
        }
        build["runtime_file_count"] = len(build["runtime_files"])
        if host_policy:
            review = "apple7" if host_policy is True else host_policy
            expected = runtime_owner.reviewed_host_policy(review)
            fixtures = Path(__file__).parent / "fixtures"
            host_patch = (fixtures / f"crosvm-host-policy-{review}.patch").read_bytes()
            host_source_bytes = (fixtures / f"host-policy-{review}.json").read_bytes()
            host_source = json.loads(host_source_bytes)
            assert digest(host_patch) == expected.patch_sha256
            runtime_owner.validate_host_policy_source(host_source, review=review)
            self.members.update({
                "host-policy-source.json": host_source_bytes,
                "diagnostics/crosvm-host-read-only.patch": host_patch,
                "static-options.json": json_bytes({"host-memory-policy": True}),
            })
            build.update({"host_policy_source": host_source, "crosvm_commit": expected.base_commit,
                          "crosvm_embedded_option_names": {"host-memory-policy": True}})
        self.members["crosvm-build.json"] = json_bytes(build)
        self.members["SHA256SUMS"] = self.checksum_bytes(self.members)
        self.run = {
            "synthetic_boundary_fixture": True, "id": receiver.RUN_ID,
            "repository": {"full_name": receiver.REPOSITORY}, "head_sha": receiver.HEAD_SHA,
            "status": "completed", "conclusion": "success",
            "url": receiver.RUN_API_URL, "html_url": receiver.RUN_URL,
            "caller_selected_token_label": "preserve this literal fixture metadata",
        }
        artifact_id = 9000000001
        api_url = f"https://api.github.com/repos/{receiver.REPOSITORY}/actions/artifacts/{artifact_id}"
        self.artifact = {
            "synthetic_boundary_fixture": True, "id": artifact_id, "name": receiver.ARTIFACT_NAME,
            "url": api_url, "archive_download_url": api_url + "/zip", "expired": False,
            "expires_at": "2099-01-01T00:00:00Z",
            "workflow_run": {"id": receiver.RUN_ID, "head_sha": receiver.HEAD_SHA},
        }
        self.write_zip()

    @staticmethod
    def checksum_bytes(members):
        return "".join(f"{digest(data)}  {name}\n" for name, data in sorted(members.items()) if name != "SHA256SUMS").encode("utf-8")

    def write_metadata(self, *, artifact_list=False):
        self.run_json.write_bytes(json_bytes(self.run))
        value = {"total_count": 1, "artifacts": [self.artifact]} if artifact_list else self.artifact
        self.artifact_json.write_bytes(json_bytes(value))

    def refresh_archive_metadata(self):
        raw = self.archive.read_bytes()
        self.artifact.update(size_in_bytes=len(raw), digest="sha256:" + digest(raw))
        self.write_metadata()

    def write_zip(self, entries=None, *, directory_entries=True):
        entries = list(self.members.items()) if entries is None else entries
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_STORED) as archive:
                if directory_entries:
                    for name in sorted(receiver.DIRECTORIES):
                        info = zipfile.ZipInfo(name + "/")
                        info.create_system = 3
                        info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                        archive.writestr(info, b"")
                for name, data in entries:
                    if isinstance(name, zipfile.ZipInfo):
                        info = name
                    else:
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, data)
        self.refresh_archive_metadata()

    def select_source(self, repository, run_id, head_sha, artifact_name):
        self.selection = {"repository": repository, "run_id": run_id, "head_sha": head_sha,
                          "artifact_name": artifact_name}
        self.run.update(id=run_id, head_sha=head_sha, repository={"full_name": repository},
                        url=f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
                        html_url=f"https://github.com/{repository}/actions/runs/{run_id}")
        api_url = f"https://api.github.com/repos/{repository}/actions/artifacts/{self.artifact['id']}"
        self.artifact.update(name=artifact_name, workflow_run={"id": run_id, "head_sha": head_sha},
                             url=api_url, archive_download_url=api_url + "/zip")
        self.write_metadata()

    def receive(self, **options):
        return receiver.receive(self.archive, self.artifact_json, self.run_json, self.output,
                                **self.selection, **options)

    def failure(self):
        return json.loads((self.output / "extraction-record.json").read_text(encoding="utf-8"))


class ReceiveArtifactTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="crosvm-receive-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def fixture(self, **kwargs):
        return Fixture(self.directory, **kwargs)

    def reject(self, fixture, pattern=None, **options):
        with self.assertRaisesRegex(receiver.ArtifactError, pattern or ".+"):
            fixture.receive(**options)
        record = fixture.failure()
        self.assertEqual(record["status"], "incomplete")
        self.assertNotEqual(record.get("runtime_consumer_validation", {}).get("status"), "complete")
        self.assertTrue(fixture.archive.is_file())
        self.assertTrue(fixture.artifact_json.is_file())
        self.assertTrue(fixture.run_json.is_file())
        with self.assertRaises(ValueError):
            runtime_owner.load_completed_runtime(fixture.output, require_display_patch=True)
        return record

    def test_admitted_synthetic_zip_uses_real_owner_and_preserves_original_inputs(self):
        fixture = self.fixture(runtime_stub=True)
        originals = {path: path.read_bytes() for path in (fixture.archive, fixture.artifact_json, fixture.run_json)}
        fixture.write_metadata(artifact_list=True)
        originals[fixture.artifact_json] = fixture.artifact_json.read_bytes()
        record = fixture.receive()
        self.assertEqual(record["status"], "complete")
        self.assertTrue(record["original_SHA256SUMS_verified"])
        self.assertTrue(record["source"]["size_verified"])
        self.assertTrue(record["source"]["sha256_verified"])
        self.assertEqual(record["source"]["digest"], fixture.artifact["digest"])
        self.assertEqual(record["source"]["original_api_url"], fixture.artifact["archive_download_url"])
        self.assertEqual(record["source"]["artifact_metadata_selection"]["container"], "artifacts")
        for path, raw in originals.items():
            self.assertEqual(path.read_bytes(), raw)
        runtime = runtime_owner.load_completed_runtime(fixture.output, require_display_patch=True)
        self.assertEqual(len(runtime.members), 71)
        self.assertEqual(set(runtime.excluded), {"runtime/usr/lib/libdl_android.so"})
        self.assertEqual(len(runtime.build["runtime_files"]), 72)
        self.assertTrue((fixture.output / "full-build/libdl_android.so").is_file())
        for row in record["files"]:
            self.assertEqual((fixture.output / row["path"]).read_bytes(), fixture.members[row["path"]])
            self.assertEqual(row["bytes"], len(fixture.members[row["path"]]))
            self.assertEqual(row["sha256"], digest(fixture.members[row["path"]]))
            self.assertTrue(row["zip_crc_verified"])
        self.assertFalse(record["target_binary_executed"])
        self.assertFalse(record["phone_boot_verified"])

    def test_downloaded_digest_and_size_are_api_owned(self):
        fixture = self.fixture()
        fixture.artifact["digest"] = "sha256:" + "0" * 64
        fixture.write_metadata()
        record = self.reject(fixture, "API digest")
        self.assertTrue(record["source"]["size_verified"])
        self.assertFalse(record["source"]["sha256_verified"])

    def test_explicit_new_run_retains_api_checks_and_complete_host_provenance(self):
        fixture = self.fixture(host_policy=True)
        fixture.select_source(receiver.REPOSITORY, 44976576515,
                              "584c1bf77ad1e3673198bd4928f1401d8303db22", "droidvm-crosvm-apple-3")
        with contextlib.redirect_stdout(io.StringIO()):
            code = receiver.main(["--archive", str(fixture.archive), "--artifact-json", str(fixture.artifact_json),
                                  "--run-json", str(fixture.run_json), "--output", str(fixture.output),
                                  "--repository", fixture.selection["repository"], "--run-id", "44976576515",
                                  "--head-sha", fixture.selection["head_sha"],
                                  "--artifact-name", fixture.selection["artifact_name"], "--require-native-host-policy"])
        self.assertEqual(code, 0)
        record = fixture.failure()
        self.assertEqual(record["requested_source_selection"], fixture.selection)
        self.assertEqual(record["source"]["head_sha"], fixture.selection["head_sha"])
        self.assertTrue(record["source"]["sha256_verified"])
        runtime = runtime_owner.load_completed_runtime(fixture.output, require_host_policy=True)
        self.assertEqual(len(runtime.host_policy_source["files"]), 8)
        self.assertEqual(runtime.host_policy_source, json.loads(fixture.members["host-policy-source.json"]))
        self.assertFalse(record["target_binary_executed"])
        self.assertTrue(record["runtime_consumer_validation"]["require_host_policy"])

    def test_explicit_selector_cannot_accept_mismatched_new_api_head_or_name(self):
        fixture = self.fixture()
        fixture.select_source("example/selected-builds", 123456, "c" * 40, "selected artifact")
        run, artifact = copy.deepcopy(fixture.run), copy.deepcopy(fixture.artifact)
        for index, target in enumerate(("run_head", "artifact_head", "name")):
            with self.subTest(target=target):
                fixture.run, fixture.artifact = copy.deepcopy(run), copy.deepcopy(artifact)
                fixture.output = self.directory / f"new-selector-{index}"
                if target == "run_head":
                    fixture.run["head_sha"] = "d" * 40
                elif target == "artifact_head":
                    fixture.artifact["workflow_run"]["head_sha"] = "d" * 40
                else:
                    fixture.artifact["name"] = "another artifact"
                fixture.write_metadata()
                self.assertEqual(self.reject(fixture)["failure"]["stage"], "API metadata validation")

    def test_host_policy_cannot_be_bypassed_by_old_payload_or_incomplete_new_provenance(self):
        old = self.fixture()
        self.reject(old, "host-policy-source.json", require_host_policy=True)
        fixture = self.fixture(host_policy=True)
        original = copy.deepcopy(fixture.members)
        for index, failure in enumerate(("manifest", "patch", "build", "option", "architecture", "full_binary")):
            with self.subTest(failure=failure):
                fixture.members = copy.deepcopy(original)
                fixture.output = self.directory / f"host-provenance-{index}"
                build = json.loads(fixture.members["crosvm-build.json"])
                if failure == "manifest":
                    manifest = json.loads(fixture.members["host-policy-source.json"])
                    manifest["files"].pop()
                    fixture.members["host-policy-source.json"] = json_bytes(manifest)
                    build["host_policy_source"] = manifest
                elif failure == "patch":
                    fixture.members["diagnostics/crosvm-host-read-only.patch"] += b"changed\n"
                elif failure == "build":
                    build["crosvm_commit"] = "e" * 40
                elif failure == "option":
                    fixture.members["static-options.json"] = json_bytes({"host-memory-policy": False})
                    build["crosvm_embedded_option_names"] = {"host-memory-policy": False}
                elif failure == "architecture":
                    binary = fixture.members["runtime/usr/bin/crosvm"]
                    binary = binary[:18] + struct.pack("<H", 62) + binary[20:]
                    for name in ("runtime/usr/bin/crosvm", "full-build/crosvm"):
                        fixture.members[name] = binary
                else:
                    fixture.members["full-build/crosvm"] = b"a different compiled binary"
                build["runtime_files"] = {name: digest(data) for name, data in fixture.members.items() if name.startswith("runtime/")}
                build["full_build_files"] = {name: digest(data) for name, data in fixture.members.items() if name.startswith(("full-build/", "shim/"))}
                fixture.members["crosvm-build.json"] = json_bytes(build)
                fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
                fixture.write_zip()
                record = self.reject(fixture, require_host_policy=True)
                self.assertTrue(record["original_SHA256SUMS_verified"])
                self.assertEqual(record["failure"]["stage"], "completed runtime owner validation")

    def test_apple8_explicit_review_retains_nested_diagnostics_without_a_fixed_total_count(self):
        fixture = self.fixture(host_policy="apple8")
        fixture.select_source(receiver.REPOSITORY, 44987826532,
                              "ec35ccf73f8205a49e0f9db1e3954f3a896b2d1f", "droidvm-crosvm-apple-4")
        for index in range(100):
            fixture.members[f"diagnostics/host-policy-harness/results/check-{index}.txt"] = f"synthetic check {index}\n".encode()
        fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
        nested = []
        for name in ("diagnostics/host-policy-harness/", "diagnostics/host-policy-harness/results/"):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
            nested.append((info, b""))
        fixture.write_zip(list(fixture.members.items()) + nested)
        with contextlib.redirect_stdout(io.StringIO()):
            code = receiver.main(["--archive", str(fixture.archive), "--artifact-json", str(fixture.artifact_json),
                                  "--run-json", str(fixture.run_json), "--output", str(fixture.output),
                                  "--repository", fixture.selection["repository"], "--run-id", "44987826532",
                                  "--head-sha", fixture.selection["head_sha"], "--artifact-name", fixture.selection["artifact_name"],
                                  "--host-policy-review", "apple8"])
        self.assertEqual(code, 0)
        record = fixture.failure()
        self.assertGreater(len(record["files"]), 173)
        self.assertTrue(record["original_SHA256SUMS_verified"])
        self.assertEqual(record["requested_source_selection"], fixture.selection)
        self.assertEqual(record["runtime_consumer_validation"]["host_policy_review"], "apple8")
        self.assertTrue(record["runtime_consumer_validation"]["require_host_policy"])
        runtime = runtime_owner.load_completed_runtime(fixture.output, host_policy_review="apple8")
        self.assertEqual(runtime.host_policy_review, "apple8")
        self.assertEqual(len(runtime.members), 71)
        self.assertEqual(len(runtime.host_policy_source["files"]), 9)
        for row in record["files"]:
            self.assertEqual((fixture.output / row["path"]).read_bytes(), fixture.members[row["path"]])

    def test_host_review_cannot_cross_accept_new_and_legacy_manifests(self):
        for index, (producer, review) in enumerate((("apple8", None), ("apple8", "apple7"), ("apple7", "apple8"))):
            with self.subTest(producer=producer, review=review):
                fixture = self.fixture(host_policy=producer)
                fixture.output = self.directory / f"cross-review-{index}"
                record = self.reject(fixture, require_host_policy=True, host_policy_review=review)
                self.assertTrue(record["original_SHA256SUMS_verified"])
                self.assertEqual(record["failure"]["stage"], "completed runtime owner validation")
        fixture = self.fixture(host_policy="apple8")
        source = json.loads(fixture.members["host-policy-source.json"])
        source["files"][-1]["final_lf_sha256"] = "f" * 64
        fixture.members["host-policy-source.json"] = json_bytes(source)
        build = json.loads(fixture.members["crosvm-build.json"])
        build["host_policy_source"] = source
        fixture.members["crosvm-build.json"] = json_bytes(build)
        fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
        fixture.write_zip()
        fixture.output = self.directory / "altered-ninth-file"
        self.assertEqual(self.reject(fixture, host_policy_review="apple8")["failure"]["stage"],
                         "completed runtime owner validation")

    def test_downloaded_size_mismatch_cannot_be_admitted(self):
        fixture = self.fixture()
        fixture.artifact["size_in_bytes"] += 1
        fixture.write_metadata()
        self.reject(fixture, "API size")

    def test_altered_member_with_refreshed_zip_digest_fails_original_checksums(self):
        fixture = self.fixture()
        fixture.members["runtime/usr/lib/library00.so"] = b"altered extracted fixture member\n"
        fixture.write_zip()
        record = self.reject(fixture, "Producer SHA256SUMS differs")
        self.assertEqual(record["source"]["status"], "complete")
        self.assertFalse(record["original_SHA256SUMS_verified"])
        self.assertEqual((fixture.output / "runtime/usr/lib/library00.so").read_bytes(), fixture.members["runtime/usr/lib/library00.so"])

    def test_stored_member_crc_failure_preserves_partial_output(self):
        fixture = self.fixture()
        with zipfile.ZipFile(fixture.archive) as archive:
            info = archive.getinfo("runtime/usr/lib/library00.so")
        raw = bytearray(fixture.archive.read_bytes())
        name_length, extra_length = struct.unpack_from("<HH", raw, info.header_offset + 26)
        payload_start = info.header_offset + 30 + name_length + extra_length
        raw[payload_start] ^= 1
        fixture.archive.write_bytes(raw)
        fixture.refresh_archive_metadata()
        record = self.reject(fixture, "CRC")
        self.assertTrue(record["source"]["sha256_verified"])
        self.assertTrue(any(row["status"] == "incomplete" for row in record["files"]))

    def test_clipped_stored_and_deflated_bytes_cannot_hide_behind_a_projected_crc(self):
        fixture = self.fixture()
        name = "diagnostics/clipped.log"
        fixture.members[name] = b"ok"
        fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
        for index, method in enumerate((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            with self.subTest(method=method):
                fixture.output = self.directory / f"clipped-{index}"
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = method
                entries = [(key, data) for key, data in fixture.members.items() if key != name]
                fixture.write_zip(entries + [(info, b"okJUNK")])
                with zipfile.ZipFile(fixture.archive) as archive:
                    local = archive.getinfo(name).header_offset
                raw = bytearray(fixture.archive.read_bytes())
                crc = zlib.crc32(b"ok")
                struct.pack_into("<I", raw, local + 14, crc)
                struct.pack_into("<I", raw, local + 22, 2)
                central = raw.find(b"PK\x01\x02")
                while central != -1:
                    name_size, extra_size, comment_size = struct.unpack_from("<HHH", raw, central + 28)
                    current_name = bytes(raw[central + 46:central + 46 + name_size]).decode("utf-8")
                    if current_name == name:
                        struct.pack_into("<I", raw, central + 16, crc)
                        struct.pack_into("<I", raw, central + 24, 2)
                        break
                    central = raw.find(b"PK\x01\x02", central + 46 + name_size + extra_size + comment_size)
                self.assertNotEqual(central, -1)
                fixture.archive.write_bytes(raw)
                fixture.refresh_archive_metadata()
                # This reproduces why ZipExtFile/testzip alone cannot own the
                # complete entry: they expose only the declared projection.
                with zipfile.ZipFile(fixture.archive) as archive:
                    self.assertEqual(archive.read(name), b"ok")
                record = self.reject(fixture, "inconsistent stored|expanded beyond")
                self.assertEqual(record["failure"]["stage"], "ZIP member extraction")

    def test_complete_deflated_stream_with_bounded_multi_chunk_output_is_admitted(self):
        fixture = self.fixture()
        name = "diagnostics/compressible.log"
        fixture.members[name] = b"fixture\n" * (receiver.CHUNK_BYTES // 8 + 33)
        fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        fixture.write_zip([(key, data) for key, data in fixture.members.items() if key != name]
                          + [(info, fixture.members[name])])
        record = fixture.receive()
        self.assertEqual(record["status"], "complete")
        self.assertEqual((fixture.output / name).read_bytes(), fixture.members[name])

    def test_deflated_member_requires_eof_and_no_trailing_compressed_data(self):
        fixture = self.fixture()
        name = "diagnostics/deflate-ending.log"
        fixture.members[name] = b"synthetic complete fixture data\n"
        fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
        for index, ending in enumerate(("trailing", "truncated")):
            with self.subTest(ending=ending):
                fixture.output = self.directory / f"deflate-ending-{index}"
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                fixture.write_zip([(key, data) for key, data in fixture.members.items() if key != name]
                                  + [(entry, fixture.members[name])])
                with zipfile.ZipFile(fixture.archive) as archive:
                    info = archive.getinfo(name)
                raw = bytearray(fixture.archive.read_bytes())
                name_size, extra_size = struct.unpack_from("<HH", raw, info.header_offset + 26)
                start = info.header_offset + 30 + name_size + extra_size
                old_size = info.compress_size
                payload = bytes(raw[start:start + old_size])
                replacement = payload + b"TAIL" if ending == "trailing" else payload[:-1]
                delta = len(replacement) - old_size
                raw[start:start + old_size] = replacement
                struct.pack_into("<I", raw, info.header_offset + 18, len(replacement))
                central = raw.find(b"PK\x01\x02", start + len(replacement))
                while central != -1:
                    current_name_size, current_extra_size, comment_size = struct.unpack_from("<HHH", raw, central + 28)
                    current_name = bytes(raw[central + 46:central + 46 + current_name_size]).decode("utf-8")
                    if current_name == name:
                        struct.pack_into("<I", raw, central + 20, len(replacement))
                        break
                    central = raw.find(b"PK\x01\x02", central + 46 + current_name_size + current_extra_size + comment_size)
                self.assertNotEqual(central, -1)
                end = raw.rfind(b"PK\x05\x06")
                original_directory_offset = struct.unpack_from("<I", raw, end + 16)[0]
                struct.pack_into("<I", raw, end + 16, original_directory_offset + delta)
                fixture.archive.write_bytes(raw)
                fixture.refresh_archive_metadata()
                record = self.reject(fixture, "trailing compressed data|DEFLATE EOF")
                self.assertEqual(record["failure"]["stage"], "ZIP member extraction")

    def test_in_memory_owner_candidate_does_not_publish_complete_status(self):
        fixture = self.fixture()
        record = fixture.receive()
        record["status"] = "incomplete"
        receiver.write_record(fixture.output, record)
        with self.assertRaises(ValueError):
            runtime_owner.load_completed_runtime(fixture.output, require_display_patch=True)
        candidate = {**record, "status": "complete"}
        runtime = runtime_owner.load_completed_runtime(fixture.output, require_display_patch=True,
                                                      extraction_record=candidate)
        self.assertEqual(len(runtime.members), 71)
        self.assertEqual(fixture.failure()["status"], "incomplete")
        candidate["original_SHA256SUMS_verified"] = False
        with self.assertRaises(ValueError):
            runtime_owner.load_completed_runtime(fixture.output, require_display_patch=True,
                                                 extraction_record=candidate)

    def test_unsafe_member_cannot_escape_new_output(self):
        fixture = self.fixture()
        fixture.write_zip(list(fixture.members.items()) + [("../escape.txt", b"outside")])
        self.reject(fixture, "canonical relative path")
        self.assertFalse((self.directory / "escape.txt").exists())

    def test_zip_nul_name_is_rejected_before_zipfile_truncation(self):
        fixture = self.fixture()
        fixture.write_zip(list(fixture.members.items()) + [("diagnostics/nulA.log", b"fixture")])
        raw = fixture.archive.read_bytes().replace(b"diagnostics/nulA.log", b"diagnostics/nul\x00.log")
        fixture.archive.write_bytes(raw)
        fixture.refresh_archive_metadata()
        self.reject(fixture, "truncated or altered filename")

    def test_duplicate_regular_member_cannot_overwrite(self):
        fixture = self.fixture()
        fixture.write_zip(list(fixture.members.items()) + [("diagnostics/crosvm-build.log", b"duplicate")])
        self.reject(fixture, "duplicates or aliases")

    def test_windows_case_alias_and_parent_file_collisions_are_rejected(self):
        fixture = self.fixture()
        cases = [
            [("diagnostics/A.log", b"upper"), ("diagnostics/a.log", b"lower")],
            [("diagnostics/parent", b"file"), ("diagnostics/parent/child.log", b"child")],
        ]
        for index, entries in enumerate(cases):
            with self.subTest(index=index):
                fixture.output = self.directory / f"collision-{index}"
                fixture.write_zip(list(fixture.members.items()) + entries)
                self.reject(fixture, "duplicates or aliases|regular file as another")

    def test_windows_stream_device_and_trailing_aliases_are_rejected(self):
        fixture = self.fixture()
        for index, name in enumerate(("diagnostics/log.txt:stream", "diagnostics/CON.txt", "diagnostics/log.", "diagnostics/log ")):
            with self.subTest(name=name):
                fixture.output = self.directory / f"windows-{index}"
                fixture.write_zip(list(fixture.members.items()) + [(name, b"invalid Windows path")])
                self.reject(fixture, "unique Windows file path|canonical relative path")

    def test_zip_symlink_and_fifo_types_are_not_materialized(self):
        fixture = self.fixture()
        for index, kind in enumerate((stat.S_IFLNK, stat.S_IFIFO)):
            with self.subTest(kind=kind):
                info = zipfile.ZipInfo("diagnostics/special")
                info.create_system = 3
                info.external_attr = (kind | 0o777) << 16
                fixture.output = self.directory / f"type-{index}"
                fixture.write_zip(list(fixture.members.items()) + [(info, b"special entry")])
                self.reject(fixture, "regular file or normal directory")

    def test_preexisting_directory_and_file_are_preserved(self):
        fixture = self.fixture()
        fixture.output.mkdir()
        sentinel = fixture.output / "original-sentinel"
        sentinel.write_bytes(b"preserve existing output")
        with self.assertRaisesRegex(receiver.ArtifactError, "must be new"):
            fixture.receive()
        self.assertEqual(sentinel.read_bytes(), b"preserve existing output")
        self.assertEqual(set(fixture.output.iterdir()), {sentinel})
        fixture.output = self.directory / "existing-file"
        fixture.output.write_bytes(b"preserve existing file")
        with self.assertRaisesRegex(receiver.ArtifactError, "must be new"):
            fixture.receive()
        self.assertEqual(fixture.output.read_bytes(), b"preserve existing file")

    def test_truncated_zip_with_its_own_api_digest_is_still_rejected(self):
        fixture = self.fixture()
        fixture.archive.write_bytes(fixture.archive.read_bytes()[:-22])
        fixture.refresh_archive_metadata()
        self.reject(fixture, "ZIP member extraction failed")

    def test_unfinished_or_mismatched_run_and_expired_artifact_are_rejected(self):
        fixture = self.fixture()
        original_run = copy.deepcopy(fixture.run)
        original_artifact = copy.deepcopy(fixture.artifact)
        cases = [
            ("run", "status", "in_progress"), ("run", "conclusion", "failure"),
            ("run", "id", receiver.RUN_ID + 1), ("run", "head_sha", "0" * 40),
            ("run", "repository", {"full_name": "somebody/other-repository"}),
            ("artifact", "expired", True),
            ("artifact", "workflow_run", {"id": receiver.RUN_ID + 1, "head_sha": receiver.HEAD_SHA}),
            ("artifact", "workflow_run", {"id": receiver.RUN_ID, "head_sha": "0" * 40}),
            ("artifact", "archive_download_url", "https://api.github.com/repos/other/repo/actions/artifacts/1/zip"),
        ]
        for index, (target, key, value) in enumerate(cases):
            with self.subTest(target=target, key=key):
                fixture.run = copy.deepcopy(original_run)
                fixture.artifact = copy.deepcopy(original_artifact)
                (fixture.run if target == "run" else fixture.artifact)[key] = value
                fixture.output = self.directory / f"metadata-{index}"
                fixture.write_metadata()
                record = self.reject(fixture)
                self.assertEqual(record["failure"]["stage"], "API metadata validation")

    def test_producer_checksum_coverage_and_anchored_rows_are_required(self):
        fixture = self.fixture()
        original = fixture.members["SHA256SUMS"]
        omitted = b"\n".join(original.split(b"\n")[1:])
        cases = [omitted, b"unanchored " + original, original + b"\n"]
        for index, manifest in enumerate(cases):
            with self.subTest(index=index):
                fixture.output = self.directory / f"checksum-{index}"
                fixture.members["SHA256SUMS"] = manifest
                fixture.write_zip()
                self.reject(fixture, "cover every regular|anchored SHA-256")

    def test_owner_gate_rejects_build_map_disagreement_after_producer_checks_pass(self):
        fixture = self.fixture()
        build = json.loads(fixture.members["crosvm-build.json"])
        build["runtime_files"]["runtime/usr/lib/library00.so"] = "0" * 64
        fixture.members["crosvm-build.json"] = json_bytes(build)
        fixture.members["SHA256SUMS"] = fixture.checksum_bytes(fixture.members)
        fixture.write_zip()
        record = self.reject(fixture, "Build and completed extraction hashes differ")
        self.assertTrue(record["original_SHA256SUMS_verified"])
        self.assertEqual(record["failure"]["stage"], "completed runtime owner validation")

    def test_cli_reports_failure_without_echoing_transport_url(self):
        fixture = self.fixture()
        fixture.artifact["archive_download_url"] = "https://signed.example.invalid/archive?transport_signature=literal"
        fixture.write_metadata()
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = receiver.main(["--archive", str(fixture.archive), "--artifact-json", str(fixture.artifact_json),
                                  "--run-json", str(fixture.run_json), "--output", str(fixture.output)])
        self.assertEqual(code, 1)
        self.assertIn("artifact API URLs", output.getvalue())
        self.assertNotIn("transport_signature", output.getvalue())
        self.assertIn("transport_signature", fixture.artifact_json.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
