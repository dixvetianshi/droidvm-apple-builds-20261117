#!/usr/bin/env python3
"""Restore the exact Windows VMPKG from its encrypted source and small supplement.

Normal mode receives the five already published encrypted source parts. The
local verification mode references an existing decrypted QCOW2 read only and
copies its small metadata; it never copies or modifies that source disk.
All output is confined to a new directory. Received/support files and failure
reports are preserved. The unchanged packer owns cleanup of its partial package.
No network, phone, guest execution or source deletion is performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import time

from pack_vmpkg import pack_package
from prepare_windows_package import qcow2_header
from receive_windows_artifact import receive_windows
from windows_support import (
    ArtifactError, FINAL_PACKAGE, MAX_SUPPORT_BYTES, PACKAGE_INPUTS, PACKAGE_NAMES,
    SOURCE_RELEASE, check_no_links, directory, json_bytes, load_support,
    new_directory, read_small, regular_file, require, sha, verify_package_manifest,
    write_new,
)


SOURCE_METADATA_NAMES = (
    "build-record.json", "private-credentials.json", "windows-image-info.json", "installed-drivers.json",
)
MAX_SOURCE_METADATA_BYTES = 1024**2


def verify_source_stage(stage, support_blobs):
    stage = directory(stage)
    image = regular_file(stage / SOURCE_RELEASE["qcow2"]["name"])
    require(image.stat().st_size == SOURCE_RELEASE["qcow2"]["bytes"],
            "Source QCOW2 size differs from the exact released Windows image")
    header = qcow2_header(image, SOURCE_RELEASE["qcow2"]["virtual_size"])
    metadata = {}
    for name in SOURCE_METADATA_NAMES:
        raw = read_small(stage / name, MAX_SOURCE_METADATA_BYTES)
        expected = {sha(support_blobs["output/windows-stage/" + name])}
        if name == "build-record.json":
            # The receiver keeps the cloud record; the original local stage also
            # retains the record after its independently recorded firmware merge.
            expected.add(sha(support_blobs["output/windows-stage/build-record.cloud-original.json"]))
        require(sha(raw) in expected, "Source metadata differs from the sealed original: " + name)
        metadata[name] = raw
    return image, header, metadata


def restore_windows(source_parts, prepared_source_stage, support_dir, key_file, output):
    require((source_parts is None) != (prepared_source_stage is None), "Select exactly one Windows source mode")
    output_path = check_no_links(output)
    require(not output_path.exists(), "Output already exists; preserve it and select a new directory")
    input_stage = "support-verification"
    # Verify the entire small encrypted archive before creating any plaintext file.
    support_record, support_manifest, blobs = load_support(support_dir, key_file)
    source_directory = directory(source_parts if source_parts is not None else prepared_source_stage)
    started = time.monotonic()
    record = {
        "format": "droidvm-windows-release-restore-v1", "status": "restoring",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_mode": "encrypted_source_parts" if source_parts is not None else "prepared_source_stage",
        "source_release": SOURCE_RELEASE, "source_directory": str(source_directory),
        "support_directory": str(directory(support_dir)), "output_directory": str(output_path),
        "support_verified": {
            "encrypted": support_record["encrypted"], "support_manifest": support_record["support_manifest"],
            "files": len(blobs), "all_member_sizes_and_hashes_verified": True,
            "exact_allowlist_verified": True, "gzip_crc_and_trailer_verified": True,
            "cbc_padding_and_salt_verified": True, "tar_complete_regular_members_verified": True,
        },
        "final_package_expected": FINAL_PACKAGE,
        "key_material_recorded": False, "credential_contents_logged": False,
        "original_source_modified": False, "phone_operated": False, "phone_boot_verified": False,
    }
    destination = new_directory(output_path)
    try:
        input_stage = "destination-capacity"
        required_free = FINAL_PACKAGE["bytes"] + MAX_SUPPORT_BYTES + 64 * 1024**2
        if source_parts is not None:
            required_free += SOURCE_RELEASE["qcow2"]["bytes"]
        require(shutil.disk_usage(destination).free >= required_free,
                "Insufficient destination free space for Windows recovery and its reserve")
        record["destination_required_free_bytes"] = required_free

        input_stage = "support-materialization"
        support_output = new_directory(destination / "support")
        for name, raw in blobs.items():
            write_new(support_output / name, raw)
        write_new(support_output / "support-encryption-record.json", json_bytes(support_record))
        write_new(support_output / "support-manifest.json", json_bytes(support_manifest))
        print(f"Verified encrypted Windows supplement: {len(blobs)} original files", flush=True)

        source_output = destination / "source-stage"
        if source_parts is not None:
            input_stage = "encrypted-source-receipt"
            receipt = receive_windows(
                source_directory, key_file, source_output,
                max_image_bytes=SOURCE_RELEASE["qcow2"]["bytes"],
                max_metadata_bytes=MAX_SOURCE_METADATA_BYTES,
            )
            record["source_receipt"] = receipt
            image, header, metadata = verify_source_stage(source_output, blobs)
        else:
            input_stage = "prepared-source-verification"
            image, header, metadata = verify_source_stage(source_directory, blobs)
            new_directory(source_output)
            for name, raw in metadata.items():
                write_new(source_output / name, raw)
            record["source_image_referenced_read_only"] = True
            record["source_image_copied"] = False
        record["qcow2_header"] = header
        record["source_metadata"] = [
            {"name": name, "bytes": len(raw), "sha256": sha(raw)} for name, raw in metadata.items()
        ]
        record["source_image_path"] = str(image)
        record["source_image_digest_validation"] = "Full source digest is checked by the unchanged packer during the next step"

        input_stage = "original-package-inputs"
        prepared = new_directory(destination / "package-inputs")
        for name in PACKAGE_NAMES:
            if name != "source-map.json":
                write_new(prepared / name, blobs["output/windows-package/" + name])
        manifest_path = prepared / "manifest.json"
        verify_package_manifest(read_small(manifest_path))
        source_map = {}
        for name, identity in PACKAGE_INPUTS.items():
            source_map[name] = str(image if name == "disks/Windows11.qcow2" else
                                   support_output / "output/windows-stage" / identity["name"])
        source_map_path = prepared / "source-map.json"
        write_new(source_map_path, json_bytes(source_map))
        record["source_manifest_bytes_preserved"] = True
        record["current_source_map"] = str(source_map_path)

        input_stage = "packing-and-complete-package-verification"
        package_path = destination / FINAL_PACKAGE["name"]
        print("Packing the original Windows package and verifying every member and container byte", flush=True)
        package_report = pack_package(manifest_path, source_map_path, package_path, compression="none")
        write_new(destination / "vmpkg-verification-report.json", json_bytes(package_report))
        input_stage = "exact-original-package-identity"
        require(package_report["package_bytes"] == FINAL_PACKAGE["bytes"]
                and package_report["package_sha256"] == FINAL_PACKAGE["sha256"],
                "Rebuilt package differs from the pinned original size/SHA-256; preserve output for diagnosis")
        record.update({
            "status": "complete", "exact_original_package_verified": True,
            "package_path": str(package_path), "package_bytes": package_report["package_bytes"],
            "package_sha256": package_report["package_sha256"],
            "complete_package_verification_report": str(destination / "vmpkg-verification-report.json"),
            "source_image_digest_validation": "Verified against original manifest during packing and complete package verification",
            "source_image_sha256_verified_against_original": True,
        })
    except BaseException as error:
        record.update({"status": "interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                       "failure_stage": input_stage, "error_type": type(error).__name__,
                       "error": str(error) if isinstance(error, (ArtifactError, OSError, ValueError)) else "Windows recovery failed",
                       "source_support_outputs_preserved": True})
        raise
    finally:
        record["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_new(destination / "restore-report.json", json_bytes(record))
    return {
        "ok": True, "operation": "restored_and_verified_exact_original_windows_package",
        "output": str(destination), "package": str(package_path),
        "bytes": record["package_bytes"], "sha256": record["package_sha256"],
        "report": str(destination / "restore-report.json"),
        "source_manifest_bytes_preserved": True, "key_material_recorded": False,
        "credential_contents_logged": False, "phone_operated": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-parts", type=Path, help="downloaded .000-.004 source parts and original SHA256SUMS")
    source.add_argument("--prepared-source-stage", type=Path, help="existing decrypted stage; references QCOW2 read only")
    parser.add_argument("--support-dir", type=Path, required=True, help="downloaded encrypted final supplement and its two public records")
    parser.add_argument("--key-file", type=Path, required=True, help="private original one-line artifact key; never logged")
    parser.add_argument("--output", type=Path, required=True, help="new absent restoration directory")
    args = parser.parse_args()
    try:
        result = restore_windows(args.source_parts, args.prepared_source_stage, args.support_dir, args.key_file, args.output)
    except (Exception, KeyboardInterrupt) as error:
        message = str(error) if isinstance(error, (ArtifactError, OSError, ValueError)) else "Windows recovery failed"
        print(json.dumps({"ok": False, "error_type": type(error).__name__, "error": message}), file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 2
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
