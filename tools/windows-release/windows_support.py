#!/usr/bin/env python3
"""Bounded encrypted supplement for the exact November 2026 Windows result.

The source QCOW2 is already in the named encrypted GitHub release. This module
owns the supplement's member list, crypto profile, identities and strict parser.
It never uploads anything and never writes a plaintext intermediate archive.
"""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import zlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unpack_apple_artifact import ArtifactError, CHUNK, DecryptedReader, StrictTarInfo, load_key
from verify_vmpkg import parse_json, validate_manifest


ARCHIVE_NAME = "Windows11-26H2-ARM64.final-support.tar.gz.enc"
RECORD_NAME = "support-encryption-record.json"
SUMS_NAME = "support-SHA256SUMS"
MANIFEST_NAME = "support-manifest.json"
MAX_SUPPORT_BYTES = 16 * 1024**2
MAX_FILE_BYTES = 8 * 1024**2
MAX_JSON_BYTES = 128 * 1024
ITERATIONS = 200000
SALT_BYTES = 8

FINAL_PACKAGE = {
    "name": "Windows11-26H2-ARM64-DroidVM-NX736J.vmpkg",
    "bytes": 8561582080,
    "sha256": "b370096917d231d1e9da793f91042cf93ee49f129981b4fd0a5e9b2aac00783a",
    "compression": "none",
    "manifest": {
        "path": "output/windows-package/manifest.json",
        "bytes": 3402,
        "sha256": "87da988b5983395e7b1c9f5409c7d01df939b29e32f64b1f00e2e3f32b0e5046",
    },
}
SOURCE_RELEASE = {
    "repository": "dixvetianshi/droidvm-apple-builds-20261117",
    "tag": "windows11-26h2-arm64-run-6",
    "prefix": "Windows11-26H2-ARM64.source.tar.gz.enc",
    "qcow2": {
        "name": "Windows11.qcow2",
        "bytes": 8556576768,
        "sha256": "26ee8583dc11164964d34abbad26e069fcce5f8d554b41ce40bfbcbb1317dd4b",
        "virtual_size": 64 * 1024**3,
    },
}
PACKAGE_INPUTS = {
    "disks/Windows11.qcow2": SOURCE_RELEASE["qcow2"],
    "disks/edk2-windows.vars.fd": {
        "name": "edk2-windows.vars.fd", "bytes": 786432,
        "sha256": "8b634c1e6bd11607850b69111f6c4dbd1583dbbd1460dac72dbacbdc1a4a130a",
    },
    "boots/edk2-windows.fd": {
        "name": "edk2-windows.fd", "bytes": 4194304,
        "sha256": "124ca25827ddb328a666dbac8698e079f47f7208c2dfa582d07cc33fd0a24141",
    },
}
STAGE_NAMES = (
    "build-record.cloud-original.json", "build-record.json", "edk2-windows.fd",
    "edk2-windows.vars.fd", "installed-drivers.json", "private-credentials.json",
    "windows-image-info.json", "windows-local-merge.json", "windows-source-receipt.json",
)
PACKAGE_NAMES = ("manifest.json", "preparation-report.json", "README.zh-CN.md", "source-map.json")
VERIFICATION_NAMES = (
    "windows-build-success-20261119.png", "windows-ci-wrapper-static-check.json",
    "windows-cloud-success-20261119.json", "windows-delivery-qa-20261119.json",
    "windows-download-profile-20261119.json", "windows-driver-fix-public-verification-20261118.json",
    "windows-driver-source-recheck-20261118.json", "windows-efi-observation-20261119.json",
    "windows-encryption-record-20261119.json", "windows-final-delivery-20261119.json",
    "windows-finalizer-check-20261118.json", "windows-import-directory-comparison-20261118.json",
    "windows-iso-cli-metadata-20261118.json", "windows-local-finalization-20261119.json",
    "windows-native-volume-public-verification-20261119.json", "windows-package-helper-check-20261118.json",
    "windows-public-source-manifest-20261118.json", "windows-public-source-verification-20261118.json",
    "windows-readme-public-verification-20261119.json", "windows-received-provenance-20261119.json",
    "windows-receiver-check-20261118.json", "windows-release-20261119.json",
    "windows-runner-fix-public-verification-20261118.json", "windows-safe-provisioning-work-path.json",
    "windows-source-preflight-public-verification-20261118.json", "windows-transport-cleanup-20261119.json",
    "windows-vmpkg-pack-report.json", "windows-volume-fix-public-verification-20261119.json",
)
DOC_NAMES = ("Windows11-ARM64-使用说明.md",)
APPROVED_MEMBERS = tuple(sorted(
    ["output/windows-stage/" + name for name in STAGE_NAMES]
    + ["output/windows-package/" + name for name in PACKAGE_NAMES]
    + ["verification/" + name for name in VERIFICATION_NAMES]
    + ["docs/" + name for name in DOC_NAMES]
))


def require(condition, message):
    if not condition:
        raise ArtifactError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def json_object(raw, label):
    try:
        value = parse_json(raw, label)
    except ValueError as error:
        raise ArtifactError("Malformed JSON in " + label) from error
    require(isinstance(value, dict), "Expected a JSON object in " + label)
    return value


def check_no_links(path):
    """Reject both symlinks and Windows junctions before following a local path."""
    path = Path(os.path.abspath(path))
    for candidate in (path, *path.parents):
        try:
            item = candidate.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(item.st_mode)
                and not (getattr(item, "st_file_attributes", 0) & 0x400),
                "A linked/reparse-point input or output path is not supported")
    return path


def regular_file(path):
    path = check_no_links(path)
    require(stat.S_ISREG(path.stat().st_mode), "A regular input file is required: " + path.name)
    return path


def directory(path):
    path = check_no_links(path)
    require(path.is_dir(), "An existing input directory is required")
    return path


def read_small(path, maximum=MAX_FILE_BYTES):
    path = regular_file(path)
    before = path.stat().st_size
    require(0 < before <= maximum, "Input exceeds its small-file budget: " + path.name)
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == before and len(raw) <= maximum, "Small input changed size during reading: " + path.name)
    return raw


def new_directory(path):
    path = check_no_links(path)
    require(not path.exists(), "Output already exists; preserve it and select a new directory")
    path.mkdir(parents=True, exist_ok=False)
    return path


def write_new(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def verify_package_manifest(raw):
    expected = FINAL_PACKAGE["manifest"]
    require(len(raw) == expected["bytes"] and sha(raw) == expected["sha256"],
            "The original package manifest bytes differ from the pinned Windows result")
    manifest = validate_manifest(raw)
    require(manifest.value["compression"] == "none" and set(manifest.entries) == set(PACKAGE_INPUTS),
            "The original Windows package contract differs")
    for name, expected_input in PACKAGE_INPUTS.items():
        entry = manifest.entries[name]
        require(entry.size == expected_input["bytes"] and entry.value.get("sha256") == expected_input["sha256"],
                "A pinned Windows package member identity differs")
    return manifest


def capture_support(root):
    root = directory(root)
    groups = (
        ("output/windows-stage", STAGE_NAMES, lambda name: name != "Windows11.qcow2"),
        ("output/windows-package", PACKAGE_NAMES, lambda name: True),
        ("verification", VERIFICATION_NAMES, lambda name: name.startswith("windows")),
        ("docs", DOC_NAMES, lambda name: "windows" in name.lower()),
    )
    for relative, expected, selected in groups:
        folder = directory(root / relative)
        present = {path.name for path in folder.iterdir() if path.is_file() and selected(path.name)}
        require(present == set(expected), "Support input inventory differs from the approved list: " + relative)
    image = regular_file(root / "output/windows-stage/Windows11.qcow2")
    package = regular_file(root / "output/packages" / FINAL_PACKAGE["name"])
    require(image.stat().st_size == SOURCE_RELEASE["qcow2"]["bytes"], "Original QCOW2 size differs")
    require(package.stat().st_size == FINAL_PACKAGE["bytes"], "Original final-package size differs")
    blobs, total = {}, 0
    for name in APPROVED_MEMBERS:
        raw = read_small(root / name)
        total += len(raw)
        require(total <= MAX_SUPPORT_BYTES, "Support plaintext members exceed the 16-MiB budget")
        blobs[name] = raw
    verify_package_manifest(blobs[FINAL_PACKAGE["manifest"]["path"]])
    for name, item in PACKAGE_INPUTS.items():
        if name == "disks/Windows11.qcow2":
            continue
        raw = blobs["output/windows-stage/" + item["name"]]
        require(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "Original firmware/vars identity differs")
    return blobs


def build_support_archive(blobs):
    require(set(blobs) == set(APPROVED_MEMBERS), "Support members differ from the approved list")
    manifest = {
        "format": "droidvm-windows-final-support-v1", "source_release": SOURCE_RELEASE,
        "final_package": FINAL_PACKAGE,
        "files": [{"path": name, "bytes": len(blobs[name]), "sha256": sha(blobs[name])}
                  for name in APPROVED_MEMBERS],
    }
    manifest_raw = json_bytes(manifest)
    require(len(manifest_raw) <= MAX_JSON_BYTES, "Support manifest exceeds its JSON budget")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT,
                      encoding="utf-8", errors="strict") as archive:
        for name, raw in [(MANIFEST_NAME, manifest_raw), *[(name, blobs[name]) for name in APPROVED_MEMBERS]]:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(raw))
    tar_raw = output.getvalue()
    require(len(tar_raw) <= MAX_SUPPORT_BYTES, "Support tar exceeds the 16-MiB decompression budget")
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", compresslevel=6, mtime=0) as stream:
        stream.write(tar_raw)
    gzip_raw = compressed.getvalue()
    require(0 < len(gzip_raw) <= MAX_SUPPORT_BYTES - 32, "Compressed support exceeds its encrypted-file budget")
    return manifest_raw, tar_raw, gzip_raw


def encrypt_support(raw, password):
    salt = os.urandom(SALT_BYTES)
    material = hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, dklen=48)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(raw) + padder.finalize()
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CBC(material[32:])).encryptor()
    ciphertext = b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize()
    require(len(ciphertext) <= MAX_SUPPORT_BYTES, "Encrypted support exceeds the 16-MiB budget")
    return ciphertext, salt


def seal_support(root, key_file, output):
    output_path = check_no_links(output)
    require(not output_path.exists(), "Output already exists; preserve it and select a new directory")
    blobs = capture_support(root)
    manifest_raw, tar_raw, gzip_raw = build_support_archive(blobs)
    password = load_key(regular_file(key_file))
    ciphertext, salt = encrypt_support(gzip_raw, password)
    del password
    record = {
        "format": "droidvm-windows-support-encryption-v1", "status": "complete",
        "created_at_utc": datetime.now(timezone.utc).isoformat(), "archive_name": ARCHIVE_NAME,
        "source_release": SOURCE_RELEASE, "final_package": FINAL_PACKAGE,
        "original_package_identity_source": "Previously verified original; restore checks exact size and SHA-256",
        "encryption": {
            "cipher": "AES-256-CBC", "padding": "PKCS7", "salt_header": "Salted__",
            "salt_bytes": SALT_BYTES, "salt_hex": salt.hex(), "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": ITERATIONS, "key_material_recorded": False,
        },
        "encrypted": {"bytes": len(ciphertext), "sha256": sha(ciphertext)},
        "plaintext_archive": {"compression": "gzip", "bytes": len(gzip_raw), "sha256": sha(gzip_raw),
                              "tar_bytes": len(tar_raw), "tar_sha256": sha(tar_raw)},
        "support_manifest": {"path": MANIFEST_NAME, "bytes": len(manifest_raw), "sha256": sha(manifest_raw)},
        "members": {"files": len(blobs), "file_bytes": sum(map(len, blobs.values()))},
        "limits": {"support_bytes": MAX_SUPPORT_BYTES, "file_bytes": MAX_FILE_BYTES,
                   "json_bytes": MAX_JSON_BYTES},
        "private_credentials_encrypted": True, "plaintext_credentials_published": False,
        "qcow2_included": False, "original_files_modified": False,
    }
    record_raw = json_bytes(record)
    destination = new_directory(output_path)
    write_new(destination / ARCHIVE_NAME, ciphertext)
    write_new(destination / RECORD_NAME, record_raw)
    sums = f"{sha(ciphertext)}  {ARCHIVE_NAME}\n{sha(record_raw)}  {RECORD_NAME}\n".encode("ascii")
    write_new(destination / SUMS_NAME, sums)
    return {"ok": True, "operation": "sealed_windows_final_support", "output": str(destination),
            "files": len(blobs), "ciphertext_bytes": len(ciphertext), "ciphertext_sha256": sha(ciphertext),
            "qcow2_included": False, "key_material_recorded": False, "plaintext_credentials_published": False}


def check_size_hash(raw, expected, label, maximum):
    require(isinstance(expected, dict) and type(expected.get("bytes")) is int
            and 0 < expected["bytes"] <= maximum, "Invalid declared size for " + label)
    digest = expected.get("sha256")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "Invalid declared SHA-256 for " + label)
    require(len(raw) == expected["bytes"] and sha(raw) == digest, "Size/SHA-256 mismatch for " + label)


def verify_support_record(record):
    require(record.get("format") == "droidvm-windows-support-encryption-v1"
            and record.get("status") == "complete" and record.get("archive_name") == ARCHIVE_NAME,
            "Unsupported or incomplete support encryption record")
    require(record.get("source_release") == SOURCE_RELEASE and record.get("final_package") == FINAL_PACKAGE,
            "Support record belongs to a different Windows result")
    encryption = record.get("encryption")
    require(isinstance(encryption, dict), "Support encryption profile is missing")
    for key, expected in {"cipher": "AES-256-CBC", "padding": "PKCS7", "salt_header": "Salted__",
                          "salt_bytes": SALT_BYTES, "kdf": "PBKDF2-HMAC-SHA256", "iterations": ITERATIONS,
                          "key_material_recorded": False}.items():
        require(type(encryption.get(key)) is type(expected) and encryption[key] == expected,
                "Support encryption profile differs: " + key)
    require(isinstance(encryption.get("salt_hex"), str)
            and re.fullmatch(r"[0-9a-f]{16}", encryption["salt_hex"]) is not None,
            "Support salt must contain exactly eight bytes")
    require(record.get("qcow2_included") is False and record.get("plaintext_credentials_published") is False,
            "Support record does not identify the encrypted small supplement")


def decrypt_support(ciphertext, password, record):
    check_size_hash(ciphertext, record.get("encrypted"), "encrypted support", MAX_SUPPORT_BYTES)
    require(len(ciphertext) >= 32 and len(ciphertext) % 16 == 0 and ciphertext[:8] == b"Salted__",
            "Support ciphertext lacks its salted AES-CBC header/alignment")
    require(ciphertext[8:16].hex() == record["encryption"]["salt_hex"], "Support ciphertext salt differs from its record")
    crypto_record, raw = {}, bytearray()
    with DecryptedReader(io.BytesIO(ciphertext), password, ITERATIONS, SALT_BYTES, crypto_record) as stream:
        while block := stream.read(CHUNK):
            raw.extend(block)
            require(len(raw) <= MAX_SUPPORT_BYTES, "Decrypted support exceeds its budget")
        require(stream.finished and stream.padding_verified, "Support CBC padding/EOF was not verified")
    gzip_raw = bytes(raw)
    plain = record.get("plaintext_archive")
    require(isinstance(plain, dict) and plain.get("compression") == "gzip", "Support compression profile differs")
    check_size_hash(gzip_raw, plain, "decrypted gzip support", MAX_SUPPORT_BYTES)
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        tar_raw = decoder.decompress(gzip_raw, MAX_SUPPORT_BYTES + 1)
    except zlib.error as error:
        raise ArtifactError("Support gzip header, CRC or trailer verification failed") from error
    require(len(tar_raw) <= MAX_SUPPORT_BYTES and not decoder.unconsumed_tail,
            "Support gzip expansion exceeds the 16-MiB budget")
    require(decoder.eof and not decoder.unused_data, "Support gzip is truncated or has trailing/concatenated streams")
    check_size_hash(tar_raw, {"bytes": plain.get("tar_bytes"), "sha256": plain.get("tar_sha256")},
                    "decompressed support tar", MAX_SUPPORT_BYTES)
    return tar_raw


class SupportTarInfo(StrictTarInfo):
    def _proc_member(self, archive):
        require(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE),
                "Support tar admits regular files only; links, sparse and extended records are rejected")
        require(self.name in {*APPROVED_MEMBERS, MANIFEST_NAME}, "Support tar member is outside the exact approved list")
        maximum = MAX_JSON_BYTES if self.name == MANIFEST_NAME else MAX_FILE_BYTES
        require(0 < self.size <= maximum, "Support tar member exceeds its small-file budget")
        return super()._proc_member(archive)


def parse_support_tar(tar_raw, record):
    blobs, seen = {}, set()
    source = io.BytesIO(tar_raw)
    with tarfile.open(fileobj=source, mode="r:", tarinfo=SupportTarInfo, errorlevel=2,
                      encoding="utf-8", errors="strict") as archive:
        archive.verified_end_markers = False
        for member in archive:
            require(member.name not in seen, "Support tar repeats a member")
            require(seen or member.name == MANIFEST_NAME, "Support manifest must be the first tar member")
            seen.add(member.name)
            stream = archive.extractfile(member)
            require(stream is not None, "Support regular member has no readable content")
            with stream:
                raw = stream.read(member.size + 1)
            require(len(raw) == member.size, "Support tar member is truncated")
            padding_raw = tar_raw[member.offset_data + member.size:archive.offset]
            require(not padding_raw.strip(b"\0"), "Support tar member has nonzero block padding")
            blobs[member.name] = raw
        require(archive.verified_end_markers, "Support tar lacks its two-block zero end marker")
        trailing = source.read(MAX_SUPPORT_BYTES + 1)
        require(not trailing.strip(b"\0") and len(trailing) % 512 == 0,
                "Support tar has nonzero or incomplete trailing block padding")
    require(seen == {*APPROVED_MEMBERS, MANIFEST_NAME}, "Support tar lacks approved members")
    manifest_raw = blobs.pop(MANIFEST_NAME)
    check_size_hash(manifest_raw, record.get("support_manifest"), "internal support manifest", MAX_JSON_BYTES)
    manifest = json_object(manifest_raw, MANIFEST_NAME)
    require(manifest.get("format") == "droidvm-windows-final-support-v1"
            and manifest.get("source_release") == SOURCE_RELEASE and manifest.get("final_package") == FINAL_PACKAGE,
            "Internal support manifest belongs to a different Windows result")
    rows = manifest.get("files")
    require(isinstance(rows, list) and len(rows) == len(APPROVED_MEMBERS), "Support manifest file coverage differs")
    declared = set()
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("path"), str)
                and row["path"] in APPROVED_MEMBERS and row["path"] not in declared,
                "Support manifest contains an unknown or duplicate path")
        name = row["path"]
        declared.add(name)
        check_size_hash(blobs[name], row, "support member " + name, MAX_FILE_BYTES)
    require(declared == set(blobs), "Support manifest coverage is incomplete")
    require(record.get("members") == {"files": len(blobs), "file_bytes": sum(map(len, blobs.values()))},
            "Support public member count/size differs")
    verify_package_manifest(blobs[FINAL_PACKAGE["manifest"]["path"]])
    return manifest, blobs


def load_support(support_dir, key_file):
    support_dir = directory(support_dir)
    raw_sums = read_small(support_dir / SUMS_NAME, MAX_JSON_BYTES)
    try:
        lines = raw_sums.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ArtifactError("Support SHA256SUMS is not ASCII") from error
    sums = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "Malformed support SHA256SUMS row")
        digest, name = match.groups()
        require(name in {ARCHIVE_NAME, RECORD_NAME} and name not in sums,
                "Support SHA256SUMS has an unknown or repeated filename")
        sums[name] = digest
    require(set(sums) == {ARCHIVE_NAME, RECORD_NAME}, "Support SHA256SUMS coverage is incomplete")
    record_raw = read_small(support_dir / RECORD_NAME, MAX_JSON_BYTES)
    require(sha(record_raw) == sums[RECORD_NAME], "Support encryption-record SHA-256 differs from the publisher table")
    record = json_object(record_raw, RECORD_NAME)
    verify_support_record(record)
    ciphertext = read_small(support_dir / ARCHIVE_NAME, MAX_SUPPORT_BYTES)
    require(sha(ciphertext) == sums[ARCHIVE_NAME], "Encrypted support SHA-256 differs from the publisher table")
    password = load_key(regular_file(key_file))
    tar_raw = decrypt_support(ciphertext, password, record)
    del password
    manifest, blobs = parse_support_tar(tar_raw, record)
    return record, manifest, blobs
