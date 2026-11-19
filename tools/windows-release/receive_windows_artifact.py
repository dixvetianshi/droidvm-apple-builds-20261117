#!/usr/bin/env python3
"""Receive the encrypted Windows ARM64 source artifact without contacting a phone.

Uses the existing bounded OpenSSL-compatible crypto/stream and sparse file writer.
Only regular root-level producer files are admitted. No Apple kind is selected.
The producer record owns every other member's size/hash; it cannot hash itself.
An independent receipt retains the original record digest before local FW merge.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

from unpack_apple_artifact import (
    ArtifactError, CHUNK, DecryptedReader, PartsReader, StrictTarInfo,
    extract_member, load_key, verify_parts,
)
from prepare_windows_package import qcow2_header
from verify_vmpkg import parse_json

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "Windows11-26H2-ARM64.source.tar.gz.enc"
DEFAULT_PART_BYTES = 1800 * 1024**2
MAX_IMAGE_BYTES = 80 * 1024**3
MAX_METADATA_BYTES = 1024**2
MAX_CIPHERTEXT_BYTES = MAX_IMAGE_BYTES + MAX_METADATA_BYTES * 4 + MAX_IMAGE_BYTES // 32 + 1024**2
MAX_TAR_PADDING = 1024**2
REQUIRED_FILES = {"Windows11.qcow2", "build-record.json", "private-credentials.json", "windows-image-info.json"}
ALLOWED_FILES = REQUIRED_FILES | {"installed-drivers.json"}
IMAGE_NAME = "Windows11.qcow2"
RECEIPT_NAME = "windows-source-receipt.json"


def require(condition, message):
    if not condition:
        raise ArtifactError(message)


def load_windows_parts(parts_dir, prefix=PREFIX, part_bytes=DEFAULT_PART_BYTES,
                       max_ciphertext_bytes=MAX_CIPHERTEXT_BYTES, manifest_path=None):
    parts_dir = Path(parts_dir).resolve(strict=True)
    require(parts_dir.is_dir(), "Windows parts directory is missing")
    require(type(part_bytes) is int and part_bytes > 0 and type(max_ciphertext_bytes) is int
            and max_ciphertext_bytes >= 32, "Invalid ciphertext resource budget")
    require(prefix == PREFIX, "Windows source artifact prefix differs from the selected producer contract")
    manifest = Path(manifest_path) if manifest_path is not None else parts_dir / "SHA256SUMS"
    require(manifest.is_file() and not manifest.is_symlink(), "A regular publisher SHA256SUMS file is required")
    with manifest.open("rb") as stream:
        raw = stream.read(64 * 1024 + 1)
    require(0 < len(raw) <= 64 * 1024, "Publisher checksum table exceeds the 64-KiB budget")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise ArtifactError("Publisher checksum table is not UTF-8") from error
    rows, seen = [], set()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](" + re.escape(prefix) + r"\.([0-9]{3}))", line)
        require(match is not None, f"Unexpected publisher checksum row {number}")
        digest, name, index = match.groups()
        require(name not in seen, "Publisher checksum table repeats a ciphertext part")
        path = parts_dir / name
        require(path.is_file() and not path.is_symlink(), "A publisher-listed ciphertext part is missing or linked")
        size = path.stat().st_size
        require(0 < size <= part_bytes, "Ciphertext part size is outside the producer split profile")
        seen.add(name)
        rows.append({"name": name, "path": path, "number": int(index), "expected_sha256": digest.lower(), "size": size})
    rows.sort(key=lambda row: row["number"])
    require(rows and [row["number"] for row in rows] == list(range(len(rows))),
            "Ciphertext parts must be complete and consecutive from .000")
    present = {path.name for path in parts_dir.iterdir() if re.fullmatch(re.escape(prefix) + r"\.[0-9]{3}", path.name)}
    require(present == seen, "Numbered ciphertext files differ from the publisher table")
    require(all(row["size"] == part_bytes for row in rows[:-1]), "Only the final ciphertext part may be short")
    total = sum(row["size"] for row in rows)
    require(32 <= total <= max_ciphertext_bytes and total % 16 == 0,
            "Ciphertext size exceeds the budget or salted AES-CBC alignment")
    return manifest, rows


class BoundedGzipSource:
    def __init__(self, source, maximum):
        self.source, self.maximum, self.count = source, maximum, 0
        self.eof_observed = False

    def read(self, size=-1):
        require(type(size) is int and size >= 0, "An unbounded decompression read was requested")
        block = self.source.read(min(size, CHUNK))
        self.count += len(block)
        require(self.count <= self.maximum, "Gzip output exceeds the selected extraction budget")
        if size > 0 and not block:
            self.eof_observed = True
        return block


def windows_tarinfo(max_image_bytes, max_metadata_bytes):
    class WindowsTarInfo(StrictTarInfo):
        def _proc_member(self, archive):
            require(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE),
                    "Windows source tar requires regular files; directories, links, sparse, PAX and longname records are not supported")
            name = self.name[2:] if self.name.startswith("./") else self.name
            require(name in ALLOWED_FILES, "Tar member is outside the strict Windows root-file allowlist")
            maximum = max_image_bytes if name == IMAGE_NAME else max_metadata_bytes
            require(0 < self.size <= maximum, "Tar member size exceeds its Windows file resource budget")
            self.windows_path = name
            return super()._proc_member(archive)
    return WindowsTarInfo


def extract_windows_tar(source, output, record, *, max_image_bytes=MAX_IMAGE_BYTES,
                        max_metadata_bytes=MAX_METADATA_BYTES):
    require(type(max_image_bytes) is int and max_image_bytes > 0
            and type(max_metadata_bytes) is int and max_metadata_bytes > 0, "Invalid Windows extraction budgets")
    output = Path(output)
    files, seen = [], set()
    record["files"] = files
    with tarfile.open(fileobj=source, mode="r|", bufsize=128 * 1024,
                      tarinfo=windows_tarinfo(max_image_bytes, max_metadata_bytes), errorlevel=2) as archive:
        archive.verified_end_markers = False
        for member in archive:
            name = member.windows_path
            require(name not in seen, "Windows source tar repeats a root filename")
            seen.add(name)
            require(shutil.disk_usage(output).free >= member.size + 16 * 1024**2,
                    "Insufficient destination space for the current Windows member and extraction reserve")
            item = {"archive_name": member.name, "path": name, "status": "extracting",
                    "expected_bytes": member.size, "bytes": None, "sha256": None}
            files.append(item)
            extract_member(archive, member, output / name, item)
            print(f"Extracted Windows source member {name} ({item['bytes']} bytes)", flush=True)
        require(archive.verified_end_markers, "Windows tar two-block end marker was not verified")
        trailing = 0
        while block := archive.fileobj.read(CHUNK):
            require(not block.strip(b"\0"), "Nonzero bytes follow the Windows tar end marker")
            trailing += len(block)
            require(trailing <= MAX_TAR_PADDING, "Windows tar trailing padding exceeds the 1-MiB budget")
        require(trailing % 512 == 0, "Windows tar trailing padding ends inside a block")
        record["tar"] = {"two_zero_end_blocks_verified": True, "trailing_zero_padding_bytes": trailing,
                         "complete_archive_verified": True, "only_regular_root_files": True}
    require(REQUIRED_FILES <= seen <= ALLOWED_FILES, "Windows source tar lacks required producer files")


def decode_transport(rows, password, output, record, *, max_image_bytes=MAX_IMAGE_BYTES,
                     max_metadata_bytes=MAX_METADATA_BYTES):
    maximum = max_image_bytes + 4 * max_metadata_bytes + MAX_TAR_PADDING + 5 * 1024
    with PartsReader(rows) as parts:
        with DecryptedReader(parts, password, 200000, 8, record) as decrypted:
            bounded = None
            try:
                with gzip.GzipFile(fileobj=decrypted, mode="rb") as compressed:
                    bounded = BoundedGzipSource(compressed, maximum)
                    extract_windows_tar(bounded, output, record, max_image_bytes=max_image_bytes,
                                        max_metadata_bytes=max_metadata_bytes)
                    require(not bounded.read(1), "Unexpected gzip bytes after the complete Windows tar stream")
                require(decrypted.padding_verified and decrypted.finished, "Windows AES-CBC padding/EOF was not completely verified")
            except (gzip.BadGzipFile, EOFError, tarfile.TarError) as error:
                raise ArtifactError("Windows gzip/tar integrity or truncation check failed") from error
            finally:
                record["encryption"]["pkcs7_padding_verified"] = decrypted.padding_verified
                if bounded is not None and bounded.eof_observed:
                    record["compression"] = {"format": "gzip", "complete_stream_verified": True,
                                             "crc_and_size_trailers_verified": True, "decompressed_bytes": bounded.count}


def verify_declared_files(build_record, file_rows):
    require(isinstance(build_record, dict) and isinstance(build_record.get("files"), dict),
            "Windows producer record requires a files map")
    actual = {row["path"]: row for row in file_rows}
    require(len(actual) == len(file_rows), "Received file list repeats a member")
    declared = build_record["files"]
    require("build-record.json" not in declared, "Producer record cannot contain a self-referential hash; use the independent receipt")
    require(set(declared) == set(actual) - {"build-record.json"},
            "Producer file map must cover every plaintext member except its own record")
    for name, expected in declared.items():
        require(isinstance(expected, dict), "Malformed Windows producer file record")
        size, digest = expected.get("bytes"), expected.get("sha256")
        require(type(size) is int and size > 0 and isinstance(digest, str)
                and re.fullmatch(r"[0-9a-fA-F]{64}", digest) is not None, "Invalid producer file size or SHA-256")
        require(actual[name]["bytes"] == size and actual[name]["sha256"] == digest.lower(),
                f"Received Windows member differs from its producer size/SHA-256: {name}")
    return True


def json_metadata(output, name, max_metadata_bytes):
    path = Path(output) / name
    require(path.stat().st_size <= max_metadata_bytes, "Windows JSON metadata exceeds its read budget")
    try:
        return parse_json(path.read_bytes(), name)
    except ValueError as error:
        # In particular, never expose raw private-credentials parse data in an error.
        raise ArtifactError(f"Windows JSON metadata is malformed: {name}") from error


def verify_windows_source(output, record, max_metadata_bytes=MAX_METADATA_BYTES):
    build = json_metadata(output, "build-record.json", max_metadata_bytes)
    verify_declared_files(build, record["files"])
    record["all_plaintext_member_hashes_match_producer"] = True
    require(build.get("format") == "droidvm-windows-build-record-v1" and build.get("status") == "complete"
            and build.get("evidence_mode") == "actual_windows_build", "A completed actual Windows producer record is required")
    require(not any(build.get(key) is True for key in ("fixture_only", "synthetic", "test_only")),
            "Synthetic fixtures cannot finalize a real Windows source stage")
    require(isinstance(build.get("windows"), dict) and build["windows"].get("architecture") == "arm64",
            "Producer must identify the actual Windows ARM64 image")
    require(isinstance(build.get("source"), dict) and bool(build["source"]), "Actual Windows build/source provenance is missing")
    for name in ["private-credentials.json", "windows-image-info.json", "installed-drivers.json"]:
        if (Path(output) / name).exists():
            value = json_metadata(output, name, max_metadata_bytes)
            require(isinstance(value, (dict, list)), "Windows metadata must be a JSON object or array")
    try:
        record["qcow2_header"] = qcow2_header(Path(output) / IMAGE_NAME, 64 * 1024**3)
    except ValueError as error:
        raise ArtifactError("Windows source QCOW2 header validation failed: " + str(error)) from error
    record["producer_record"] = {"path": "build-record.json", "sha256": next(
        row["sha256"] for row in record["files"] if row["path"] == "build-record.json"),
        "self_hash_owned_by_receipt": True, "reported_status": build["status"],
        "reported_evidence_mode": build["evidence_mode"], "cloud_run_status_independently_queried": False}
    record["private_credentials"] = {"path": "private-credentials.json", "kept_local": True, "contents_logged": False}


def receive_windows(parts_dir, key_file, output, *, prefix=PREFIX, part_bytes=DEFAULT_PART_BYTES,
                    max_image_bytes=MAX_IMAGE_BYTES, max_metadata_bytes=MAX_METADATA_BYTES,
                    manifest_path=None):
    require(type(max_image_bytes) is int and max_image_bytes > 0
            and type(max_metadata_bytes) is int and max_metadata_bytes > 0, "Invalid Windows extraction resource budgets")
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), "Output must be a new absent directory; existing data is preserved")
    maximum_ciphertext = max_image_bytes + 4 * max_metadata_bytes + max_image_bytes // 32 + 1024**2
    manifest, rows = load_windows_parts(parts_dir, prefix, part_bytes, maximum_ciphertext, manifest_path)
    key_path = Path(key_file).resolve(strict=True)
    password = load_key(key_path)
    record = {"format": "droidvm-windows-source-receipt-v1", "operation": "receive_windows_source",
              "started_at_utc": datetime.now(timezone.utc).isoformat(), "status": "verifying_parts",
              "parts_directory": str(Path(parts_dir).resolve()), "output_directory": str(output),
              "key_file_path": str(key_path), "key_material_recorded": False,
              "budgets": {"max_image_bytes": max_image_bytes, "max_metadata_bytes": max_metadata_bytes,
                          "max_ciphertext_bytes": maximum_ciphertext},
              "files": [], "phone_operated": False, "phone_boot_verified": False}
    # No destination is created until every source ciphertext part has passed its publisher hash.
    verify_parts(manifest, rows, record)
    output.mkdir(parents=True, exist_ok=False)
    try:
        record["status"] = "receiving"
        decode_transport(rows, password, output, record, max_image_bytes=max_image_bytes,
                         max_metadata_bytes=max_metadata_bytes)
        verify_windows_source(output, record, max_metadata_bytes)
        record.update(status="received_and_verified", source_stage_complete=True,
                      local_firmware_merge_completed=False,
                      next_step="Root must copy the selected private firmware/vars and merge their actual provenance before prepare_windows_package; preserve the producer record bytes or backup with this receipt digest.")
    except Exception as error:
        record["status"] = "failed"
        record["source_stage_complete"] = False
        record["error_type"] = type(error).__name__
        record["error"] = str(error) if isinstance(error, (ArtifactError, OSError)) else "Windows source validation failed"
        raise
    finally:
        record["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        with (output / RECEIPT_NAME).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    return {"operation": record["operation"], "output": str(output), "receipt": str(output / RECEIPT_NAME),
            "members": len(record["files"]), "source_stage_complete": True, "phone_operated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parts-dir", type=Path, default=ROOT / "output/windows-parts")
    parser.add_argument("--sha256sums", type=Path, help="publisher checksum table; default is parts-dir/SHA256SUMS")
    parser.add_argument("--key-file", type=Path, default=ROOT / "secrets/ARTIFACT_KEY.txt")
    parser.add_argument("--output", type=Path, required=True, help="a new source stage directory")
    parser.add_argument("--part-bytes", type=int, default=DEFAULT_PART_BYTES)
    parser.add_argument("--max-image-bytes", type=int, default=MAX_IMAGE_BYTES)
    parser.add_argument("--max-metadata-bytes", type=int, default=MAX_METADATA_BYTES)
    args = parser.parse_args()
    try:
        result = receive_windows(args.parts_dir, args.key_file, args.output, part_bytes=args.part_bytes,
                                 max_image_bytes=args.max_image_bytes, max_metadata_bytes=args.max_metadata_bytes,
                                 manifest_path=args.sha256sums)
    except (ArtifactError, OSError, ValueError, tarfile.TarError) as error:
        message = str(error) if isinstance(error, (ArtifactError, OSError)) else "Windows source validation failed"
        print(json.dumps({"ok": False, "error_type": type(error).__name__, "error": message}, ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, **result}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
