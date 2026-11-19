#!/usr/bin/env python3
"""Merge verified local Gunyah firmware into a received actual Windows stage.

The receiver receipt remains unchanged. Its build-record.json digest is retained
by build-record.cloud-original.json after the atomic replacement. Existing or
partial merge outputs are never overwritten. Firmware is reused from the macos
build, not produced by the Windows cloud job; phone compatibility is unverified.

windows-local-merge.json records preparations and an expected merged-record
digest before the final atomic replacement. Its pending state is intentional:
completion is established by comparing the current record with that digest.
No key/credential contents or large disk bytes are read by this tool.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

from verify_vmpkg import PackageError, parse_json

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = "windows-source-receipt.json"
CLOUD_RECORD = "build-record.json"
CLOUD_BACKUP = "build-record.cloud-original.json"
MERGE_RECORD = "windows-local-merge.json"
PENDING_RECORD = "build-record.local-merge.pending.json"
COPY_SPECS = (
    ("firmware", "firmware_sha256", "edk2-windows.fd"),
    ("vars", "vars_sha256", "edk2-windows.vars.fd"),
)
REQUIRED_RECEIVED = {"Windows11.qcow2", CLOUD_RECORD, "private-credentials.json", "windows-image-info.json"}
ALLOWED_RECEIVED = REQUIRED_RECEIVED | {"installed-drivers.json"}
MAX_METADATA_BYTES = 1024**2
MAX_FIRMWARE_BYTES = 16 * 1024**2
CHUNK = 1024**2


def require(condition, message):
    if not condition:
        raise PackageError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def regular_file(path):
    require(path.is_file() and not path.is_symlink(), f"Required regular file is missing or linked: {path}")


def read_metadata(path):
    regular_file(path)
    require(0 < path.stat().st_size <= MAX_METADATA_BYTES,
            f"JSON metadata exceeds the 1-MiB budget or is empty: {path.name}")
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    require(0 < len(raw) <= MAX_METADATA_BYTES, f"JSON metadata exceeds the 1-MiB budget or is empty: {path.name}")
    try:
        value = parse_json(raw, path.name)
    except ValueError as error:
        raise PackageError(f"Invalid strict UTF-8 JSON metadata: {path.name}") from error
    require(isinstance(value, dict), f"JSON object is required: {path.name}")
    return value, raw


def digest_small(path, maximum):
    regular_file(path)
    require(0 < path.stat().st_size <= maximum, f"Small file size is outside its read budget: {path.name}")
    count, digest = 0, hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(min(CHUNK, maximum - count + 1)):
            count += len(block)
            require(count <= maximum, f"Small file grew beyond its read budget: {path.name}")
            digest.update(block)
    require(count > 0, f"Small file is empty: {path.name}")
    return count, digest.hexdigest()


def require_absent(path):
    require(not path.exists() and not path.is_symlink(),
            f"Merge output already exists; preserve the prior or partial attempt instead of overwriting: {path}")


def write_new(path, raw):
    require(0 < len(raw) <= MAX_METADATA_BYTES, f"Prepared metadata exceeds the 1-MiB budget: {path.name}")
    require_absent(path)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(digest_small(path, MAX_METADATA_BYTES) == (len(raw), sha(raw)),
            f"Written metadata size/SHA-256 differs: {path.name}")


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def validate_receipt(receipt):
    require(isinstance(receipt, dict) and receipt.get("format") == "droidvm-windows-source-receipt-v1"
            and receipt.get("operation") == "receive_windows_source"
            and receipt.get("status") == "received_and_verified", "A successful actual Windows receiver receipt is required")
    require(not any(receipt.get(key) is True for key in ("fixture_only", "synthetic", "test_only")),
            "Synthetic receipts cannot finalize a Windows stage")
    require(all(receipt.get(key) is True for key in (
        "source_stage_complete", "all_numbered_parts_verified", "all_plaintext_member_hashes_match_producer")),
        "Windows receiver did not complete every transport/member verification")
    require(receipt.get("local_firmware_merge_completed") is False,
            "Receiver receipt must describe the original stage before local firmware merge")
    encryption, compression, archive = (receipt.get(key) for key in ("encryption", "compression", "tar"))
    require(isinstance(encryption, dict) and encryption.get("pkcs7_padding_verified") is True,
            "Receiver AES-CBC padding verification is missing")
    require(isinstance(compression, dict) and compression.get("format") == "gzip"
            and compression.get("complete_stream_verified") is True, "Receiver gzip completion verification is missing")
    require(isinstance(archive, dict) and archive.get("two_zero_end_blocks_verified") is True
            and archive.get("complete_archive_verified") is True, "Receiver tar completion verification is missing")
    producer = receipt.get("producer_record")
    require(isinstance(producer, dict) and producer.get("path") == CLOUD_RECORD
            and valid_digest(producer.get("sha256")) and producer.get("self_hash_owned_by_receipt") is True
            and producer.get("reported_status") == "complete"
            and producer.get("reported_evidence_mode") == "actual_windows_build",
            "Receiver lacks the completed actual cloud-record digest binding")
    return producer["sha256"].lower()


def validate_cloud_record(record):
    require(isinstance(record, dict) and record.get("format") == "droidvm-windows-build-record-v1"
            and record.get("status") == "complete" and record.get("evidence_mode") == "actual_windows_build",
            "An actual completed Windows cloud build record is required")
    require(not any(record.get(key) is True for key in ("fixture_only", "synthetic", "test_only")),
            "Synthetic cloud records cannot finalize a Windows stage")
    require(isinstance(record.get("windows"), dict) and record["windows"].get("architecture") == "arm64",
            "Cloud record must identify the actual Windows ARM64 image")
    require(isinstance(record.get("source"), dict) and bool(record["source"]), "Actual cloud build/source provenance is missing")
    require(isinstance(record.get("files"), dict), "Cloud record requires its received files map")
    require("local_firmware_reuse" not in record["source"] and "local_firmware_merge" not in record,
            "Cloud record already contains a local merge; the original input is required")


def verify_record_binding(raw, expected):
    require(sha(raw) == expected, "Current cloud build-record.json SHA-256 differs from the receiver producer_record digest")


def received_stage(stage):
    require(stage.is_dir(), f"Actual received Windows stage is missing: {stage}; receive the completed cloud build first")
    stage = stage.resolve(strict=True)
    for name in (CLOUD_BACKUP, MERGE_RECORD, PENDING_RECORD, *(spec[2] for spec in COPY_SPECS)):
        require_absent(stage / name)
    receipt, receipt_raw = read_metadata(stage / RECEIPT)
    cloud_sha = validate_receipt(receipt)
    record, record_raw = read_metadata(stage / CLOUD_RECORD)
    verify_record_binding(record_raw, cloud_sha)
    validate_cloud_record(record)
    rows = receipt.get("files")
    require(isinstance(rows, list) and len(rows) in (4, 5), "Receiver must list every admitted plaintext file")
    received = {}
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("path"), str) and row["path"] in ALLOWED_RECEIVED,
                "Receiver member is outside the Windows root-file contract")
        name, size, digest = row["path"], row.get("bytes"), row.get("sha256")
        require(name not in received and row.get("status") == "complete" and type(size) is int and size > 0
                and valid_digest(digest), "Receiver member is repeated, incomplete or lacks a valid size/SHA-256")
        received[name] = (size, digest.lower())
        path = stage / name
        regular_file(path)
        require(path.stat().st_size == size, f"Received file size changed: {name}")
    require(REQUIRED_RECEIVED <= set(received) <= ALLOWED_RECEIVED, "Receiver lacks required Windows source members")
    require(received[CLOUD_RECORD] == (len(record_raw), cloud_sha), "Receiver cloud-record member differs from its producer binding")
    require(set(record["files"]) == set(received) - {CLOUD_RECORD},
            "Cloud file map must match every received member except its own record")
    for name, item in record["files"].items():
        require(isinstance(item, dict) and type(item.get("bytes")) is int and valid_digest(item.get("sha256"))
                and (item["bytes"], item["sha256"].lower()) == received[name],
                f"Cloud file size/SHA-256 differs from the receiver: {name}")
    return stage, receipt, receipt_raw, record, record_raw


def firmware_plan(directory):
    require(directory.is_dir(), f"Existing local firmware-builds directory is missing: {directory}")
    directory = directory.resolve(strict=True)
    metadata_path = directory / "firmware-builds.json"
    metadata, raw = read_metadata(metadata_path)
    rows = metadata.get("firmware_builds")
    require(isinstance(rows, list), "Local firmware record lacks its build list")
    selected = [row for row in rows if isinstance(row, dict) and row.get("guest") == "macos"]
    require(len(selected) == 1, "Exactly one existing macos firmware build must be selected for reuse")
    row = selected[0]
    require(row.get("target") == "RELEASE_GCC / AARCH64" and row.get("pci_cam_mode") is False
            and row.get("virtio_gpu_enable") is False, "Selected firmware must be the existing AARCH64 build without virtio GPU")
    require(all(isinstance(metadata.get(key), str) and metadata[key] for key in
                ("edk2_repository", "edk2_commit", "edk2_submodule_commit")), "Local firmware repository/commit provenance is missing")
    copies = []
    for source_key, digest_key, destination in COPY_SPECS:
        name = row.get(source_key)
        require(isinstance(name, str) and name and "\\" not in name, "Firmware source must be a relative POSIX path")
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and str(relative) == name and ".." not in relative.parts,
                "Firmware source path escapes or is not canonical")
        candidate = directory.joinpath(*relative.parts)
        regular_file(candidate)
        source = candidate.resolve(strict=True)
        require(source.is_relative_to(directory), "Firmware source resolves outside the selected local build directory")
        size, digest = digest_small(source, MAX_FIRMWARE_BYTES)
        require(valid_digest(row.get(digest_key)) and digest == row[digest_key].lower(),
                f"Actual local firmware SHA-256 differs from its build record: {name}")
        copies.append({"source_path": str(source), "source_record_path": name, "destination": destination,
                       "bytes": size, "sha256": digest})
    provenance = {"origin": "reuse_existing_local_gunyah_firmware", "selected_guest_build": "macos",
                  "firmware_built_in_windows_cloud_job": False,
                  "firmware_build_record": {"path": str(metadata_path), "bytes": len(raw), "sha256": sha(raw)},
                  **{key: metadata[key] for key in ("edk2_repository", "edk2_commit", "edk2_submodule_commit")},
                  "selected_build": copy.deepcopy(row), "copies": copies,
                  "windows_phone_boot_verified": False}
    return provenance


def copy_firmware(stage, item):
    source, destination = Path(item["source_path"]), stage / item["destination"]
    require_absent(destination)
    count, digest = 0, hashlib.sha256()
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        while block := input_stream.read(min(CHUNK, MAX_FIRMWARE_BYTES - count + 1)):
            count += len(block)
            require(count <= MAX_FIRMWARE_BYTES, "Firmware source grew beyond its small-file copy budget")
            digest.update(block)
            output_stream.write(block)
        output_stream.flush()
        os.fsync(output_stream.fileno())
    expected = (item["bytes"], item["sha256"])
    require((count, digest.hexdigest()) == expected, f"Firmware source changed while copying: {source.name}")
    require(digest_small(destination, MAX_FIRMWARE_BYTES) == expected,
            f"Copied firmware size/SHA-256 differs: {destination.name}")
    item["source_sha256_verified_before_copy"] = True
    item["source_sha256_verified_while_copying"] = True
    item["destination_sha256_verified_after_copy"] = True


def finalize(stage, firmware_builds):
    stage, receipt, receipt_raw, cloud, cloud_raw = received_stage(Path(stage))
    provenance = firmware_plan(Path(firmware_builds))
    source_receipt = {"path": RECEIPT, "bytes": len(receipt_raw), "sha256": sha(receipt_raw), "unchanged": True}
    original = {"path": CLOUD_BACKUP, "bytes": len(cloud_raw), "sha256": sha(cloud_raw)}
    # Preflight is complete before the first mutation. Any failed output stays for inspection.
    write_new(stage / CLOUD_BACKUP, cloud_raw)
    for item in provenance["copies"]:
        copy_firmware(stage, item)
    merged = copy.deepcopy(cloud)
    merged["source"]["local_firmware_reuse"] = provenance
    for item in provenance["copies"]:
        name = item["destination"]
        merged["files"][name] = {"path": name, "bytes": item["bytes"], "sha256": item["sha256"],
                                  "origin": provenance["origin"], "source_path": item["source_path"],
                                  "firmware_build_record_sha256": provenance["firmware_build_record"]["sha256"]}
    mapping = {CLOUD_RECORD: CLOUD_BACKUP}
    phone_flags = {"phone_operated": False, "phone_boot_verified": False, "android_runtime_loaded": False}
    merged["local_firmware_merge"] = {"source_receipt": source_receipt, "cloud_original_record": original,
                                      "received_name_to_backup": mapping, "manifest_path": MERGE_RECORD,
                                      "firmware_copy_verification_completed": True, **phone_flags}
    merged_raw = json_bytes(merged)
    merged_digest = sha(merged_raw)
    write_new(stage / PENDING_RECORD, merged_raw)
    local = {"format": "droidvm-windows-local-merge-v1", "operation": "finalize_windows_stage",
             "status": "prepared_for_atomic_record_commit", "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
             "stage": str(stage), "source_receipt": source_receipt, "cloud_original_record": original,
             "received_name_to_backup": mapping,
             "merged_build_record": {"path": CLOUD_RECORD, "bytes": len(merged_raw), "sha256": merged_digest},
             "atomic_record_commit": {"state_at_manifest_write": "pending",
                                      "completion_criterion": "Current build-record.json bytes/SHA-256 must match merged_build_record; original backup and unchanged receiver receipt must match their recorded bytes/SHA-256",
                                      "completion_asserted_at_manifest_write": False},
             "local_firmware_reuse": provenance, "large_disk_sha256_recomputed": False,
             "large_disk_sha256_authority": "Original cloud file map and successful receiver receipt; only current file sizes are checked here",
             "cloud_run_status_independently_queried_by_finalizer": False, **phone_flags}
    write_new(stage / MERGE_RECORD, json_bytes(local))
    # The record replacement is the last file mutation, after every preparation/copy check.
    require(digest_small(stage / RECEIPT, MAX_METADATA_BYTES) == (len(receipt_raw), sha(receipt_raw)),
            "Receiver receipt changed before record commit; preserve the partial merge")
    require(digest_small(stage / CLOUD_RECORD, MAX_METADATA_BYTES) == (len(cloud_raw), sha(cloud_raw)),
            "Cloud record changed before record commit; preserve the partial merge")
    require(digest_small(stage / CLOUD_BACKUP, MAX_METADATA_BYTES) == (len(cloud_raw), sha(cloud_raw)),
            "Cloud-original backup changed before record commit")
    require(digest_small(stage / PENDING_RECORD, MAX_METADATA_BYTES) == (len(merged_raw), merged_digest),
            "Prepared merged record changed before record commit")
    os.replace(stage / PENDING_RECORD, stage / CLOUD_RECORD)
    return {"operation": "finalize_windows_stage", "stage": str(stage), "local_merge_manifest": str(stage / MERGE_RECORD),
            "cloud_original_record": str(stage / CLOUD_BACKUP), "merged_build_record_sha256": merged_digest,
            "atomic_record_commit_completed": True, "receiver_receipt_unchanged": True,
            "firmware_built_in_windows_cloud_job": False, **phone_flags}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=ROOT / "output/windows-stage")
    parser.add_argument("--firmware-builds", type=Path, default=ROOT / "output/firmware-builds")
    args = parser.parse_args()
    try:
        result = finalize(args.stage, args.firmware_builds)
    except (PackageError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error_type": type(error).__name__, "error": str(error)}, ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, **result}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
