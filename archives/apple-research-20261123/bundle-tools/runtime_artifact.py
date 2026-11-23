"""Own the completed runtime artifact facts used by APK and support packaging.

The extractor owns whole-artifact and producer-checksum verification. Consumers
check its complete record, bind the build maps to those extracted member hashes,
and hash the files they actually copy. Historical full builds are not rehashed.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct

from runtime_payload_policy import select_runtime_members
from verify_vmpkg import validate_archive_path


NATIVE_DISPLAY_PROVENANCE_FILES = (
    "native-display-patch.json", "diagnostics/android-display-owner.patch",
)
NATIVE_DISPLAY_SOURCE_BEFORE = "47d833cf2832ce6c63e4f6e28e6458dd66a3b8d7b2880ca02f7f6e15159e6e61"
NATIVE_DISPLAY_SOURCE_AFTER = "df3a45d4dede4cac0b0d944a04069fad1d374c8da7b4fd0d721d54405fab5986"
NATIVE_DISPLAY_PATCH_SHA256 = "508c025223e29868eb3e9b1f4638d7f41b869221cfb6802c79949e5a6452fbcc"
SOURCE_LOCK_SHA256 = "fe63a6eec0ec48abd7a9551a93e1b60b976ee0171b9a18c1a52f93b9ffccb610"
ORIGINAL_SHIM_SHA256 = "3db0af7122198f1dde9f7fe1ef9794411b519fe153abcc427755f7280078ecad"
VIRTUALIZATION_COMMIT = "c8c132c55d7d5932966e8b2f262e2f86d676cbb1"
HOST_POLICY_BASE_COMMIT = "c69de01daf50ee8a24adf07e994adf8bcd5825cf"
HOST_POLICY_PATCH_SHA256 = "9aa201a5657b64feea4736a229e6e34683911cca699debd4bf58efd8687a9359"
HOST_POLICY_PROVENANCE_FILES = (
    "host-policy-source.json", "diagnostics/crosvm-host-read-only.patch",
)
# The producer owns one manifest of the eight reviewed source boundaries.
# Consumers bind these facts once here, retaining the original manifest.
HOST_POLICY_SOURCE_HASHES = {
    "hypervisor/src/gunyah/mod.rs": (
        "048480dc8a5d494d886d4000403eee041651c52967b808d5b23b9353029310ae",
        "68a44aba339408442e347ffe4e56ae3180ccf26d9ed7df95433e54802c6ce49e"),
    "hypervisor/src/gunyah/mthp.rs": (
        "6cf00574b1f11cb74484403ccabbf85a1533b4dd45196e2c331716907debb459",
        "cc5539ff3796e2570bfd746bd78c9acaabd28ef8d80889ed779ad08b02a49aa0"),
    "hypervisor/src/lib.rs": (
        "3052441c2bbfbba8d6b834c3c73e70fb2fd141f450e510378624470b91ca56d8",
        "09beb72561ab384aff87aa85d5e37f5836b20c37f224a6657ae0581113fe88dd"),
    "src/crosvm/cmdline.rs": (
        "3760aaf61679095f363c27f82c827e8eb3128f908d4d109351b560f76782871a",
        "f1af53ce1b18c4041fead66d549c5f772496f9416ed2e1580597411138b3534f"),
    "src/crosvm/config.rs": (
        "89c2fa2874a2d15946dab3eecf5d5fecc1befaae43fd96258e7fd6375a6235f8",
        "22a795b545a65618b35dfea971006b71cc8974c8dabf6978a623885de080a1d7"),
    "src/crosvm/sys/linux.rs": (
        "d56f75fe8031d360dbe2da572536665ddfc7a1ba9e669e5baf4d83752118f192",
        "7647b64320cdfb2539a4ceae228fa23ce993016634f5d0471b5a7cd6fadad56b"),
    "src/crosvm/sys/linux/device_helpers.rs": (
        "7844b1887d1455bb7cd37fed0ea2df65fc9cf49b6b3dfa807e5a5057001e739d",
        "377bcab621742b49057a6b34f19b3fb7db33f93fdc264eeb46a015b3407fc6a3"),
    "src/sys/windows.rs": (
        "fda15d1b7ff6ff505766a8b2bc18196caf8998db30416159282fc004fdd44c6f",
        "26e1fcdcbf1bff85cb045c4a37f68ce7535fa852aa19f27252a12f0e763adc87"),
}


@dataclass(frozen=True)
class HostPolicyReview:
    name: str
    base_commit: str
    patch_sha256: str
    source_hashes: dict


# Producer manifests retain their original schema and bytes. Callers select a
# named review; a newer manifest is never admitted by weakening an older gate.
HOST_POLICY_REVIEWS = {
    "apple7": HostPolicyReview("apple7", HOST_POLICY_BASE_COMMIT,
                               HOST_POLICY_PATCH_SHA256, HOST_POLICY_SOURCE_HASHES),
    "apple8": HostPolicyReview("apple8", HOST_POLICY_BASE_COMMIT,
        "f01ceb49a8babeba74d5773598e0656d32cda51dcac5a26bee8700d012ef9862", {
            **HOST_POLICY_SOURCE_HASHES,
            "hypervisor/src/gunyah/mod.rs": (
                "048480dc8a5d494d886d4000403eee041651c52967b808d5b23b9353029310ae",
                "7517ae1625a99007803020b7d506f3414ecb2fe0b7b5a572e489fd2a8c92bbb7"),
            "hypervisor/src/gunyah/mthp.rs": (
                "6cf00574b1f11cb74484403ccabbf85a1533b4dd45196e2c331716907debb459",
                "f03a69149c11c97289cad66f225e3ccf2a2c44993faf81234b16fd13aeff7188"),
            "hypervisor/src/gunyah/pin.rs": (
                "78330d7a86788fcf50d7186b436ccdc6b76abd92196cd7484019d0d96f9ef15c",
                "a00ab1a961dc84dc6d9c03664a009962902018e85318479a93997950d1586c19"),
        }),
}

APPLE10_SOURCE_LINEAGE = {
    "host": ("apple10-host-policy-source.json", "b2a69119f9a4f5269a175689e5e07bdd5deb77253f7315d18684752a44601950"),
    "display": ("apple10-native-display-source.json", "5487c83259944829d82a31804938cb2692692cd3613349ae2cd30cf1c2d5ece5"),
    "soong": ("apple10-soong-unwind-source.json", "253ef1a117c6f46986cb91773ea7e11e5069bcc2182efd4898a2662e7efcdc32"),
}
APPLE10_HOST_PATCH_SHA256 = "92d101b43a5f17d620e21d607321a13d502ce460abf2f976852b888b66977186"
APPLE10_DISPLAY_PATCH_SHA256 = "f274fc8217f8d87f27647904bc78d38bd4b31f9df9510957377ed69812134c8f"
APPLE10_LINEAGE_FILES = ("native-display-source.json", "native-lifecycle-source.json", "soong-unwind-source.json")
APPLE10_LEASE_HELPER_TESTS = {
    "hypervisor/src/gunyah/lease_state.rs": (
        "tests::legacy_caps_and_partial_features_are_refused_before_share",
        "tests::zero_maps_and_elapsed_wait_do_not_complete_a_closing_lease",
        "tests::only_complete_after_all_owned_resources_and_inflight_shares_finish",
        "tests::stalled_and_unknown_identity_never_acknowledge_completion",
        "tests::misleading_complete_with_an_owned_map_is_a_permanent_contract_failure",
    ),
    "src/crosvm/sys/linux/run_control_lifecycle.rs": (
        "tests::partial_spawn_cancellation_joins_actual_waiting_threads",
        "tests::release_before_arrival_does_not_leave_late_threads_waiting",
        "tests::cancel_after_release_does_not_revoke_a_started_vcpu",
        "tests::missing_one_shot_handshake_cancels_peers_without_waiting_for_a_missing_vcpu",
    ),
}
APPLE10_MEMORY_TESTS = (
    "gunyah::mthp::tests::read_only_does_not_invoke_host_write",
    "gunyah::mthp::tests::existing_reserve_rejects_short_capacity_and_unknown_policy",
    "gunyah::mthp::tests::local_folding_orders_each_window_before_the_next_population",
    "gunyah::mthp::tests::failed_window_never_reports_partial_success_or_continues",
    "gunyah::mthp::tests::local_folding_rejects_invalid_ranges_before_operations",
    "gunyah::mthp::tests::local_lock_guard_releases_after_verification_failure_and_handoff",
    "gunyah::mthp::tests::readonly_alias_cleanup_preserves_the_same_memfd_owner_lock",
    "gunyah::local_memory_range_tests::owned_range_preserves_file_offset_and_rejects_cross_region",
    "gunyah::pin::sample_coverage_tests::pin_probe_requires_the_entire_requested_sample_grid",
)
HOST_POLICY_REVIEWS["apple10"] = HostPolicyReview("apple10", HOST_POLICY_BASE_COMMIT,
                                                APPLE10_HOST_PATCH_SHA256, {})


def apple10_source_manifest(kind):
    """Load source pins lazily; historical reviews do not depend on new files."""
    filename, digest = APPLE10_SOURCE_LINEAGE[kind]
    path = Path(__file__).resolve().parent / "release-source-lineage" / filename
    if sha256_file(path) != digest:
        raise ValueError("Apple10 source lineage snapshot changed: " + kind)
    return object_from(path)


def reviewed_host_policy(name):
    if not isinstance(name, str) or name not in HOST_POLICY_REVIEWS:
        raise ValueError("Unsupported native host policy review")
    review = HOST_POLICY_REVIEWS[name]
    if name == "apple10":
        manifest = apple10_source_manifest("host")
        hashes = {row["file"]: (row["pinned_sha256"], row["final_lf_sha256"])
                  for row in manifest["files"]}
        return HostPolicyReview(review.name, review.base_commit, review.patch_sha256, hashes)
    return review


def sha256_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular input file: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sha256_value(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"Invalid SHA-256: {label}")
    return value


def object_from(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected an object: {path.name}")
    return value


@dataclass(frozen=True)
class CompletedRuntime:
    directory: Path
    build: dict
    extraction: dict
    file_sha256: dict
    members: dict
    excluded: dict
    native_display_patch: dict | None
    host_policy_source: dict | None = None
    host_policy_review: str | None = None
    source_lineage: dict | None = None


def _complete_source(source):
    if not isinstance(source, dict) or source.get("status") != "complete" \
            or source.get("size_verified") is not True or source.get("sha256_verified") is not True:
        raise ValueError("The runtime artifact source must own complete size/SHA verification")
    size = source.get("expected_size")
    if type(size) is not int or size <= 0 or type(source.get("observed_size")) is not int \
            or source["observed_size"] != size:
        raise ValueError("The runtime artifact source size verification differs")
    expected = sha256_value(source.get("expected_sha256"), "runtime artifact source")
    if source.get("observed_sha256") != expected:
        raise ValueError("The runtime artifact source SHA verification differs")


def _extracted_hashes(extraction):
    if extraction.get("status") != "complete" or extraction.get("original_SHA256SUMS_verified") is not True:
        raise ValueError("The existing completed crosvm verification is required")
    _complete_source(extraction.get("source"))
    rows = extraction.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("The completed extraction must own its member records")
    hashes = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "complete":
            raise ValueError("The runtime extraction contains an incomplete member")
        name = validate_archive_path(row.get("path"), "extracted member path")
        if name in hashes:
            raise ValueError("The runtime extraction repeats a member path")
        size = row.get("bytes")
        if type(size) is not int or size < 0:
            raise ValueError("The runtime extraction contains an invalid member byte count")
        hashes[name] = sha256_value(row.get("sha256"), name)
    return hashes


def _bind_map(values, hashes, label):
    if not isinstance(values, dict):
        raise ValueError(f"The completed build must own its {label} map")
    for name, expected in values.items():
        validate_archive_path(name, label + " path")
        sha256_value(expected, name)
        if hashes.get(name) != expected:
            raise ValueError(f"Build and completed extraction hashes differ: {name}")


def _checked_record(directory, name, hashes):
    if name not in hashes or sha256_file(directory / name) != hashes[name]:
        raise ValueError(f"Completed runtime record bytes changed: {name}")
    return object_from(directory / name)


def validate_native_display_patch(patch_record, *, review=None):
    """Validate the producer's named patch contract without reinterpreting it."""
    if review == "apple10":
        manifest = apple10_source_manifest("display")
        main = next(row for row in manifest["files"]
                    if row["file"] == "libs/android_display_backend/crosvm_android_display_client.cpp")
        expected_fields = {
            "schema_version": 2,
            "project_path": manifest["project_path"], "project_url": manifest["repository"],
            "upstream_commit": manifest["base_commit"], "source_path": main["file"],
            "source_sha256_before": main["pinned_sha256"], "source_sha256_after": main["final_lf_sha256"],
            "source_manifest": "native-display-source.json",
            "source_manifest_snapshot": "profiles/native-display-owner-source.json",
            "source_manifest_sha256": APPLE10_SOURCE_LINEAGE["display"][1],
            "files": manifest["files"],
            "verified_files": [{"file": row["file"], "source_sha256_before": row["pinned_sha256"],
                                "source_sha256_after": row["final_lf_sha256"]} for row in manifest["files"]],
            "source_provenance": manifest["source_provenance"], "stages": manifest["stages"],
            "paired_aidl_sha256": manifest["paired_aidl_sha256"],
            "verification_scope": manifest["verification_scope"],
            "patch": NATIVE_DISPLAY_PROVENANCE_FILES[1], "patch_sha256": APPLE10_DISPLAY_PATCH_SHA256,
            "source_lock_snapshot": "profiles/crosvm-display-source-lock.json",
            "source_lock_snapshot_sha256": SOURCE_LOCK_SHA256,
            "build_linkage": "libcrosvm_android_display_client (cc_library_static) linked into crosvm",
        }
        if not isinstance(patch_record, dict) \
                or any(patch_record.get(key) != expected for key, expected in expected_fields.items()):
            raise ValueError("Apple10 native display provenance must retain the exact three-file paired source lineage")
        return patch_record
    expected_fields = {
        "project_path": "packages/modules/Virtualization",
        "project_url": "https://github.com/Droid-VM/Virtualization",
        "upstream_commit": VIRTUALIZATION_COMMIT,
        "source_path": "libs/android_display_backend/crosvm_android_display_client.cpp",
        "source_sha256_before": NATIVE_DISPLAY_SOURCE_BEFORE,
        "source_sha256_after": NATIVE_DISPLAY_SOURCE_AFTER,
        "patch": NATIVE_DISPLAY_PROVENANCE_FILES[1],
        "patch_sha256": NATIVE_DISPLAY_PATCH_SHA256,
        "source_lock_snapshot": "profiles/crosvm-display-source-lock.json",
        "source_lock_snapshot_sha256": SOURCE_LOCK_SHA256,
        "build_linkage": "libcrosvm_android_display_client (cc_library_static) linked into crosvm",
    }
    if not isinstance(patch_record, dict) \
            or any(patch_record.get(key) != expected for key, expected in expected_fields.items()):
        raise ValueError("Native display patch provenance differs from the reviewed final source")
    return patch_record


def _native_display_patch(directory, build, hashes, review=None):
    patch_record = validate_native_display_patch(
        _checked_record(directory, NATIVE_DISPLAY_PROVENANCE_FILES[0], hashes), review=review)
    if build.get("native_display_patch") != patch_record:
        raise ValueError("Native display patch record and build owner differ")
    patch_sha = APPLE10_DISPLAY_PATCH_SHA256 if review == "apple10" else NATIVE_DISPLAY_PATCH_SHA256
    if hashes.get(NATIVE_DISPLAY_PROVENANCE_FILES[1]) != patch_sha \
            or sha256_file(directory / NATIVE_DISPLAY_PROVENANCE_FILES[1]) != patch_sha:
        raise ValueError("Native display patch bytes changed")
    if review == "apple10":
        name = "native-display-source.json"
        if hashes.get(name) != APPLE10_SOURCE_LINEAGE["display"][1] \
                or _checked_record(directory, name, hashes) != apple10_source_manifest("display"):
            raise ValueError("Apple10 native display source manifest bytes or coverage changed")
    if hashes.get("source-lock.json") != SOURCE_LOCK_SHA256 \
            or sha256_file(directory / "source-lock.json") != SOURCE_LOCK_SHA256 \
            or build.get("source_lock_snapshot_sha256") != SOURCE_LOCK_SHA256 \
            or build.get("source_lock_reused_without_ref_resolution") is not True:
        raise ValueError("The original 96-project source lock must be preserved")
    if hashes.get("shim/shim.bin") != ORIGINAL_SHIM_SHA256 \
            or sha256_file(directory / "shim/shim.bin") != ORIGINAL_SHIM_SHA256 \
            or build.get("shim_sha256") != ORIGINAL_SHIM_SHA256 \
            or build.get("shim_expected_sha256") != ORIGINAL_SHIM_SHA256 \
            or build.get("retained_shim_embedded_in_crosvm") is not True:
        raise ValueError("The original matching Apple/Gunyah shim must be preserved")
    return patch_record


def validate_host_policy_source(source, *, review="apple7"):
    """Bind the complete producer manifest to all reviewed before/after hashes."""
    expected = reviewed_host_policy(review)
    if review == "apple10" and source != apple10_source_manifest("host"):
        raise ValueError("Apple10 must retain the complete fixed schema-v2 fourteen-file host source lineage")
    if not isinstance(source, dict) or source.get("base_commit") != expected.base_commit \
            or source.get("patch_sha256") != expected.patch_sha256:
        raise ValueError("Native host policy provenance differs from the reviewed patch base")
    rows = source.get("files")
    if not isinstance(rows, list) or len(rows) != len(expected.source_hashes):
        raise ValueError(f"Native host policy must retain all {len(expected.source_hashes)} reviewed source files for {review}")
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid native host policy source member")
        name = validate_archive_path(row.get("file"), "native host policy source path")
        if name in seen or name not in expected.source_hashes:
            raise ValueError("Native host policy source coverage differs")
        before, after = expected.source_hashes[name]
        if row.get("pinned_sha256") != before or row.get("final_lf_sha256") != after:
            raise ValueError("Native host policy before/after source hashes differ: " + name)
        seen.add(name)
    return source


def _host_policy_source(directory, build, hashes, review):
    source = validate_host_policy_source(
        _checked_record(directory, HOST_POLICY_PROVENANCE_FILES[0], hashes), review=review.name)
    if review.name == "apple10" and hashes.get(HOST_POLICY_PROVENANCE_FILES[0]) != APPLE10_SOURCE_LINEAGE["host"][1]:
        raise ValueError("Apple10 host source manifest must retain its exact producer bytes")
    if build.get("host_policy_source") != source or build.get("crosvm_commit") != review.base_commit:
        raise ValueError("Native host policy manifest and compiled build owner differ")
    patch = HOST_POLICY_PROVENANCE_FILES[1]
    if hashes.get(patch) != review.patch_sha256 \
            or sha256_file(directory / patch) != review.patch_sha256:
        raise ValueError("Native host policy patch bytes changed")
    options = _checked_record(directory, "static-options.json", hashes)
    if options != build.get("crosvm_embedded_option_names") or options.get("host-memory-policy") is not True:
        raise ValueError("Compiled native runtime must retain the host-memory-policy option")
    binary = "runtime/usr/bin/crosvm"
    if build["full_build_files"].get("full-build/crosvm") != hashes[binary] \
            or sha256_file(directory / binary) != hashes[binary]:
        raise ValueError("Native runtime and full compiled crosvm identities differ")
    with (directory / binary).open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01" \
            or struct.unpack_from("<HH", header, 16) not in ((2, 183), (3, 183)):
        raise ValueError("Compiled native runtime must be a 64-bit little-endian AArch64 ELF")
    return source


def validate_apple10_source_lineage(lineage):
    """Validate source configuration only; this does not certify kernel execution."""
    host = apple10_source_manifest("host")
    soong = apple10_source_manifest("soong")
    expected_native = {"source_manifest_sha256": APPLE10_SOURCE_LINEAGE["host"][1],
                       "lifecycle": host["lifecycle"], "source_provenance": host["source_provenance"],
                       "verification_scope": host["verification"]}
    expected_soong = {**soong, "source_manifest_sha256": APPLE10_SOURCE_LINEAGE["soong"][1],
                      "applied_only_to_ci_build_tree": True, "device_panic_execution_verified": False,
                      "source_lock_commits_changed": False,
                      "sysroot_companion_retained_patch": "diagnostics/rust-sysroot-unwind.patch",
                      "sysroot_companion_patch_sha256": soong["sysroot_companion"]["patch_sha256"],
                      "sysroot_companion_applied": True, "sysroot_source_bytes_verified": True}
    if not isinstance(lineage, dict) \
            or lineage.get("native_lifecycle_source") != expected_native \
            or lineage.get("soong_unwind_source") != expected_soong \
            or lineage.get("source_manifest_sha256") != {kind: row[1] for kind, row in APPLE10_SOURCE_LINEAGE.items()}:
        raise ValueError("Apple10 must retain the exact native lifecycle and CI-only Soong unwind source lineage")
    receipt = lineage["soong_unwind_source"]
    if any(receipt.get(field) is not True for field in (
            "applied_only_to_ci_build_tree", "sysroot_companion_applied", "sysroot_source_bytes_verified")) \
            or any(receipt.get(field) is not False for field in (
                "device_panic_execution_verified", "source_lock_commits_changed", "system_or_phone_changes")):
        raise ValueError("Apple10 Soong/sysroot source verification flags must retain their exact boolean types")
    return lineage


def _apple10_build_lineage(directory, build, hashes):
    native = _checked_record(directory, "native-lifecycle-source.json", hashes)
    soong = _checked_record(directory, "soong-unwind-source.json", hashes)
    if native != build.get("native_lifecycle_source") or soong != build.get("soong_unwind_source"):
        raise ValueError("Apple10 source lineage records and compiled build owner differ")
    patch = "diagnostics/soong-device-unwind.patch"
    expected = apple10_source_manifest("soong")["patch_sha256"]
    if hashes.get(patch) != expected or sha256_file(directory / patch) != expected:
        raise ValueError("Apple10 CI-only Soong unwind patch bytes changed")
    sysroot_patch = "diagnostics/rust-sysroot-unwind.patch"
    sysroot_sha = apple10_source_manifest("soong")["sysroot_companion"]["patch_sha256"]
    if soong.get("sysroot_companion_retained_patch") != sysroot_patch \
            or soong.get("sysroot_companion_patch_sha256") != sysroot_sha \
            or hashes.get(sysroot_patch) != sysroot_sha \
            or sha256_file(directory / sysroot_patch) != sysroot_sha:
        raise ValueError("Apple10 CI-only Rust sysroot companion patch identity or retained bytes changed")
    memory = _checked_record(directory, "diagnostics/gunyah-host-boundary-tests/host-boundary-test-receipt.json", hashes)
    lease = _checked_record(directory, "diagnostics/gunyah-lease-boundary-tests/lease-boundary-test-receipt.json", hashes)
    if memory != build.get("host_memory_boundary_tests") or lease != build.get("lease_production_helper_tests"):
        raise ValueError("Apple10 test receipts and compiled build owner differ")
    validate_apple10_helper_receipts(memory, lease)
    fixture = "diagnostics/gunyah-lease-boundary-tests/labelled-owner-fence-host-fragment.rs"
    if hashes.get(fixture) != lease["host_fragment_smoke"]["fixture_sha256"] \
            or sha256_file(directory / fixture) != hashes[fixture]:
        raise ValueError("Apple10 host fragment receipt and retained fixture bytes differ")
    return validate_apple10_source_lineage({
        "native_lifecycle_source": native, "soong_unwind_source": soong,
        "source_manifest_sha256": {kind: row[1] for kind, row in APPLE10_SOURCE_LINEAGE.items()},
    })


def validate_apple10_helper_receipts(memory, lease):
    """Bind exact test names, counts and production source identities."""
    manifest_sha = APPLE10_SOURCE_LINEAGE["host"][1]
    source_hashes = {row["file"]: row["final_lf_sha256"] for row in apple10_source_manifest("host")["files"]}
    if not isinstance(memory, dict) or memory.get("source_manifest_sha256") != manifest_sha \
            or type(memory.get("test_count")) is not int or memory["test_count"] != len(APPLE10_MEMORY_TESTS) \
            or memory.get("exact_tests") != sorted(APPLE10_MEMORY_TESTS) \
            or memory.get("compile_passed") is not True or memory.get("tests_passed") is not True \
            or not isinstance(lease, dict) or type(lease.get("schema_version")) is not int or lease["schema_version"] != 1 \
            or lease.get("source_manifest_sha256") != manifest_sha \
            or type(lease.get("production_helper_count")) is not int \
            or lease["production_helper_count"] != sum(len(tests) for tests in APPLE10_LEASE_HELPER_TESTS.values()):
        raise ValueError("Apple10 must retain exact completed host helper test coverage")
    helpers = lease.get("production_helpers")
    if not isinstance(helpers, list) or len(helpers) != len(APPLE10_LEASE_HELPER_TESTS):
        raise ValueError("Apple10 production helper source coverage differs")
    seen = set()
    for row in helpers:
        if not isinstance(row, dict):
            raise ValueError("Apple10 production helper receipt is invalid")
        source = row.get("source")
        if not isinstance(source, str) or source in seen or source not in APPLE10_LEASE_HELPER_TESTS:
            raise ValueError("Apple10 production helper source coverage differs")
        expected_tests = APPLE10_LEASE_HELPER_TESTS[source]
        if row.get("source_sha256") != source_hashes[source] \
                or row.get("exact_tests") != sorted(expected_tests) \
                or type(row.get("count")) is not int or row["count"] != len(expected_tests) \
                or row.get("compile_passed") is not True or row.get("execution_passed") is not True:
            raise ValueError("Apple10 helper source identity or exact test coverage differs: " + source)
        seen.add(source)
    fragment = lease.get("host_fragment_smoke")
    if not isinstance(fragment, dict) \
            or fragment.get("production_linux_source_sha256") != source_hashes["src/crosvm/sys/linux.rs"] \
            or type(fragment.get("count")) is not int or fragment["count"] != 1 or fragment.get("passed") is not True:
        raise ValueError("Apple10 host fragment production source identity or count differs")
    sha256_value(fragment.get("verbatim_function_sha256"), "Apple10 host fragment function")
    sha256_value(fragment.get("fixture_sha256"), "Apple10 host fragment fixture")
    return memory, lease


def validate_apple10_runtime_asset_owner(record):
    """Bind a new merge to the completed build's actual members and source owner."""
    validate_apple10_source_lineage(record.get("runtime_source_lineage"))
    _complete_source(record.get("runtime_artifact_source"))
    for name in ("runtime_build_record_sha256", "runtime_extraction_record_sha256"):
        sha256_value(record.get(name), name)
    members = record.get("runtime_members_sha256")
    selected, excluded = select_runtime_members(members)
    if excluded or selected != members or type(record.get("apple_runtime_members")) is not int \
            or record["apple_runtime_members"] != len(members) \
            or type(record.get("runtime_member_count")) is not int or record["runtime_member_count"] != len(members):
        raise ValueError("Apple10 runtime member count must come from its exact completed build map")
    if record.get("compiled_crosvm_sha256") != members["runtime/usr/bin/crosvm"]:
        raise ValueError("Apple10 must retain its actual compiled crosvm identity")
    merged = record.get("merged_member_sha256", {})
    if any(merged.get(name.removeprefix("runtime/")) != digest for name, digest in members.items()):
        raise ValueError("Apple10 merged members differ from the selected new runtime")
    # Reopen the retained completed owner. Relabelling an Apple8 record and
    # pasting new source JSON cannot stand in for a new compiled artifact.
    directory = record.get("runtime_directory")
    if not isinstance(directory, str) or not Path(directory).is_absolute():
        raise ValueError("Apple10 requires the retained absolute completed new runtime directory")
    runtime = load_completed_runtime(Path(directory), require_display_patch=True,
                                     require_host_policy=True, host_policy_review="apple10")
    if runtime.members != members or runtime.extraction["source"] != record["runtime_artifact_source"] \
            or runtime.source_lineage != record["runtime_source_lineage"] \
            or runtime.file_sha256["crosvm-build.json"] != record["runtime_build_record_sha256"] \
            or sha256_file(runtime.directory / "extraction-record.json") != record["runtime_extraction_record_sha256"]:
        raise ValueError("Apple10 asset record and actual completed new runtime owner differ")
    return record


def load_completed_runtime(runtime_dir, *, require_display_patch=False, require_host_policy=False,
                           host_policy_review=None, extraction_record=None):
    """Bind one explicitly selected extraction to its build and deployable maps.

    Source is retained as supplied by the extractor: a release or Actions artifact
    can own the download, without reconstructing URLs or replacing provenance.
    Actual deployable bytes are checked while the consuming operation copies them.
    The extractor can supply its candidate record to run this same owner gate
    before publishing complete status on disk. Other callers read the saved record.
    """
    directory = Path(runtime_dir)
    if not directory.is_absolute():
        raise ValueError("--runtime-dir must be an absolute path")
    directory = directory.resolve()
    extraction = object_from(directory / "extraction-record.json") \
        if extraction_record is None else extraction_record
    if not isinstance(extraction, dict):
        raise ValueError("The completed extraction record must be an object")
    hashes = _extracted_hashes(extraction)
    build = _checked_record(directory, "crosvm-build.json", hashes)
    has_host_policy = "host_policy_source" in build or HOST_POLICY_PROVENANCE_FILES[0] in hashes
    requires_host = require_host_policy or host_policy_review is not None
    review = reviewed_host_policy("apple7" if host_policy_review is None else host_policy_review) \
        if requires_host or has_host_policy else None
    members, excluded = select_runtime_members(build.get("runtime_files"))
    if review is not None and review.name == "apple10":
        if type(build.get("runtime_file_count")) is not int \
                or build["runtime_file_count"] != len(build["runtime_files"]):
            raise ValueError("Apple10 requires the runtime count from the actual completed new build")
    elif len(members) != 71:
        raise ValueError("Expected one crosvm and 70 matching deployable runtime libraries")
    _bind_map(build["runtime_files"], hashes, "runtime file")
    _bind_map(build.get("full_build_files"), hashes, "full build file")
    if "runtime_file_count" in build and build["runtime_file_count"] != len(build["runtime_files"]):
        raise ValueError("The declared runtime file count differs from its recorded map")
    patch_record = None
    has_patch = "native_display_patch" in build or NATIVE_DISPLAY_PROVENANCE_FILES[0] in hashes
    if require_display_patch or has_patch or requires_host or has_host_policy:
        patch_record = _native_display_patch(directory, build, hashes, review.name if review is not None else None)
    host_policy = None
    if review is not None:
        host_policy = _host_policy_source(directory, build, hashes, review)
    lineage = _apple10_build_lineage(directory, build, hashes) \
        if review is not None and review.name == "apple10" else None
    return CompletedRuntime(directory, build, extraction, hashes, members, excluded,
                            patch_record, host_policy, review.name if review is not None else None, lineage)
