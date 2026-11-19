"""Bounded synthetic transport regressions, never a real Windows build or stage.

Successful fixtures exercise only crypto/tar decoding and declared file hashes.
The production entry point is exercised only to reject explicitly tagged fixtures.
All payloads and keys belong to TemporaryDirectory instances or memory.
"""
from __future__ import annotations

import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import receive_windows_artifact as receiver
from unpack_apple_artifact import ArtifactError

PASSWORD = b"FIXTURE_PASSWORD_SENTINEL_NOT_A_REAL_CREDENTIAL"
SALT = b"fixture8"
PART_BYTES = 128


def encoded_json(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def fixture_payloads(*, installed_drivers=True, production_tags=False):
    payloads = {
        "Windows11.qcow2": b"SYNTHETIC_TRANSPORT_BYTES_NOT_A_WINDOWS_IMAGE",
        "private-credentials.json": encoded_json({
            "fixture_only": True, "password": PASSWORD.decode("ascii"),
        }),
        "windows-image-info.json": encoded_json({
            "fixture_only": True, "architecture": "arm64",
        }),
    }
    if installed_drivers:
        payloads["installed-drivers.json"] = encoded_json({
            "fixture_only": True, "drivers": [],
        })
    build_record = {
        "format": "droidvm-windows-build-record-v1",
        "status": "complete" if production_tags else "fixture_transport_only",
        "evidence_mode": "actual_windows_build" if production_tags else "synthetic_transport_only",
        "fixture_only": True,
        "windows": {"architecture": "arm64"},
        "source": {"fixture_only": True, "purpose": "bounded transport regression"},
        "files": {
            name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in payloads.items()
        },
    }
    # The producer owns other file digests, never its own recursively defined digest.
    payloads["build-record.json"] = encoded_json(build_record)
    return payloads, build_record


def regular_members(payloads):
    return [(name, data, tarfile.REGTYPE, "") for name, data in payloads.items()]


def tar_header(name, size, kind=tarfile.REGTYPE, link=""):
    info = tarfile.TarInfo(name)
    info.size = size
    info.type = kind
    info.linkname = link
    info.mode = 0o600
    info.mtime = 0
    return info.tobuf(format=tarfile.GNU_FORMAT)


def small_gnu_tar(members, *, end_blocks=2, trailing=b""):
    result = bytearray()
    for name, data, kind, link in members:
        result.extend(tar_header(name, len(data), kind, link))
        result.extend(data)
        result.extend(b"\0" * ((-len(data)) % 512))
    result.extend(b"\0" * (512 * end_blocks))
    result.extend(trailing)
    return bytes(result)


def salted_ciphertext(compressed, *, password=PASSWORD, salt=SALT, bad_padding=False):
    material = hashlib.pbkdf2_hmac("sha256", password, salt, 200000, dklen=48)
    if bad_padding:
        # Zero is always invalid PKCS7 padding. Encrypt that invalid block ourselves:
        # do not depend on randomly corrupting ciphertext into probably-bad padding.
        padded = compressed + b"\0" * (16 - len(compressed) % 16)
    else:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(compressed) + padder.finalize()
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CBC(material[32:])).encryptor()
    return b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize()


class WindowsTransportFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="droidvm-windows-transport-fixture-")
        self.directory = Path(self.temporary.name).resolve()
        self.assertTrue(self.directory.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temporary.cleanup)
        self.serial = 0

    def new_path(self, label):
        self.serial += 1
        return self.directory / f"{label}-{self.serial}"

    def write_parts(self, ciphertext, *, part_bytes=PART_BYTES):
        directory = self.new_path("parts")
        directory.mkdir()
        rows = []
        for index, offset in enumerate(range(0, len(ciphertext), part_bytes)):
            name = f"{receiver.PREFIX}.{index:03d}"
            block = ciphertext[offset:offset + part_bytes]
            (directory / name).write_bytes(block)
            rows.append(f"{hashlib.sha256(block).hexdigest()}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")
        return directory

    def transport_record(self):
        return {
            "fixture_only": True,
            "evidence_mode": "synthetic_transport_only",
            "status": "fixture_transport_only",
            "source_stage_complete": False,
            "phone_operated": False,
        }

    def decode(self, ciphertext, *, password=PASSWORD, max_image_bytes=4096,
               max_metadata_bytes=4096):
        directory = self.write_parts(ciphertext)
        manifest, rows = receiver.load_windows_parts(directory, part_bytes=PART_BYTES)
        record = self.transport_record()
        output = self.new_path("decoded")
        output.mkdir()
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                receiver.verify_parts(manifest, rows, record)
                receiver.decode_transport(rows, password, output, record,
                                          max_image_bytes=max_image_bytes,
                                          max_metadata_bytes=max_metadata_bytes)
        except ArtifactError as error:
            self.assertNotIn(password.decode("ascii"), str(error))
            raise
        finally:
            captured = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(PASSWORD.decode("ascii"), captured)
            self.assertNotIn(password.decode("ascii"), captured)
        return record, output

    def encode_tar(self, raw_tar, **kwargs):
        return salted_ciphertext(gzip.compress(raw_tar, mtime=0), **kwargs)

    def test_transport_roundtrip_checks_hashes_and_all_end_layers_without_actual_completion(self):
        payloads, build_record = fixture_payloads()
        record, output = self.decode(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        self.assertTrue(receiver.verify_declared_files(build_record, record["files"]))
        self.assertEqual({item["path"] for item in record["files"]}, set(payloads))
        for name, expected in payloads.items():
            self.assertEqual((output / name).read_bytes(), expected)
        self.assertTrue(record["all_numbered_parts_verified"])
        self.assertTrue(record["encryption"]["pkcs7_padding_verified"])
        self.assertEqual(record["encryption"]["salt_bytes"], 8)
        self.assertEqual(record["encryption"]["iterations"], 200000)
        self.assertFalse(record["encryption"]["key_material_recorded"])
        self.assertTrue(record["compression"]["crc_and_size_trailers_verified"])
        self.assertTrue(record["compression"]["complete_stream_verified"])
        self.assertTrue(record["tar"]["two_zero_end_blocks_verified"])
        self.assertTrue(record["tar"]["complete_archive_verified"])
        self.assertTrue(record["fixture_only"])
        self.assertEqual(record["evidence_mode"], "synthetic_transport_only")
        self.assertFalse(record["source_stage_complete"])

    def test_optional_driver_metadata_can_be_absent(self):
        payloads, build_record = fixture_payloads(installed_drivers=False)
        record, _ = self.decode(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        self.assertTrue(receiver.verify_declared_files(build_record, record["files"]))

    def test_missing_ciphertext_part_is_rejected(self):
        payloads, _ = fixture_payloads()
        directory = self.write_parts(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        (directory / f"{receiver.PREFIX}.001").unlink()
        with self.assertRaisesRegex(ArtifactError, "missing"):
            receiver.load_windows_parts(directory, part_bytes=PART_BYTES)

    def test_extra_numbered_part_is_rejected(self):
        payloads, _ = fixture_payloads()
        directory = self.write_parts(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        (directory / f"{receiver.PREFIX}.999").write_bytes(b"x")
        with self.assertRaisesRegex(ArtifactError, "differ"):
            receiver.load_windows_parts(directory, part_bytes=PART_BYTES)

    def test_nonconsecutive_manifest_is_rejected(self):
        payloads, _ = fixture_payloads()
        directory = self.write_parts(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        original = directory / f"{receiver.PREFIX}.001"
        original.rename(directory / f"{receiver.PREFIX}.777")
        manifest = directory / "SHA256SUMS"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace(".001", ".777"),
                            encoding="utf-8")
        with self.assertRaisesRegex(ArtifactError, "consecutive"):
            receiver.load_windows_parts(directory, part_bytes=PART_BYTES)

    def test_publisher_ciphertext_digest_mismatch_blocks_output_creation(self):
        payloads, _ = fixture_payloads()
        directory = self.write_parts(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        first = directory / f"{receiver.PREFIX}.000"
        changed = bytearray(first.read_bytes())
        changed[-1] ^= 1
        first.write_bytes(changed)
        key_file = self.new_path("fixture-key")
        key_file.write_bytes(PASSWORD + b"\n")
        output = self.new_path("must-not-exist")
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ArtifactError, "SHA-256"):
            receiver.receive_windows(directory, key_file, output, part_bytes=PART_BYTES)
        self.assertFalse(output.exists())

    def test_ciphertext_budget_is_checked_from_stat(self):
        payloads, _ = fixture_payloads()
        directory = self.write_parts(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        with self.assertRaisesRegex(ArtifactError, "budget"):
            receiver.load_windows_parts(directory, part_bytes=PART_BYTES, max_ciphertext_bytes=32)

    def test_bad_key_cannot_decode_transport(self):
        payloads, _ = fixture_payloads()
        ciphertext = self.encode_tar(small_gnu_tar(regular_members(payloads)))
        with self.assertRaises(ArtifactError):
            self.decode(ciphertext, password=b"DIFFERENT_FIXTURE_KEY")

    def test_wrong_salt_length_is_not_guessed(self):
        payloads, _ = fixture_payloads()
        ciphertext = self.encode_tar(small_gnu_tar(regular_members(payloads)),
                                     salt=b"fixture-salt-16!")
        # A 16-byte salt is never accepted by the fixed 8-byte production profile.
        with self.assertRaises(ArtifactError):
            self.decode(ciphertext)

    def test_missing_salted_header_is_rejected(self):
        payloads, _ = fixture_payloads()
        ciphertext = self.encode_tar(small_gnu_tar(regular_members(payloads)))
        with self.assertRaisesRegex(ArtifactError, "Salted__"):
            self.decode(b"BadHead!" + ciphertext[8:])

    def test_deterministically_invalid_pkcs7_padding_is_rejected(self):
        payloads, _ = fixture_payloads()
        ciphertext = self.encode_tar(small_gnu_tar(regular_members(payloads)), bad_padding=True)
        with self.assertRaisesRegex(ArtifactError, "[Pp]adding|[Dd]ecryption"):
            self.decode(ciphertext)

    def test_gzip_crc_and_truncated_stream_are_rejected(self):
        payloads, _ = fixture_payloads()
        compressed = gzip.compress(small_gnu_tar(regular_members(payloads)), mtime=0)
        wrong_crc = bytearray(compressed)
        wrong_crc[-8] ^= 1
        for candidate in (bytes(wrong_crc), compressed[:-1]):
            with self.subTest(case="crc" if candidate == bytes(wrong_crc) else "truncated"):
                with self.assertRaisesRegex(ArtifactError, "integrity|truncation"):
                    self.decode(salted_ciphertext(candidate))

    def test_truncated_member_and_missing_tar_end_blocks_are_rejected(self):
        payloads, _ = fixture_payloads()
        members = regular_members(payloads)
        complete = small_gnu_tar(members)
        truncated_member = complete[:512 + len(payloads["Windows11.qcow2"]) // 2]
        for candidate in (truncated_member, small_gnu_tar(members, end_blocks=0),
                          small_gnu_tar(members, end_blocks=1)):
            with self.subTest(bytes=len(candidate)):
                with self.assertRaises(ArtifactError):
                    self.decode(self.encode_tar(candidate))

    def test_nonzero_or_unaligned_trailing_tar_bytes_are_rejected(self):
        payloads, _ = fixture_payloads()
        for trailing in (b"x" * 512, b"\0" * 513):
            with self.subTest(bytes=len(trailing)):
                with self.assertRaisesRegex(ArtifactError, "follow|padding|block"):
                    self.decode(self.encode_tar(small_gnu_tar(regular_members(payloads),
                                                             trailing=trailing)))

    def test_path_and_nonregular_members_are_rejected_without_escaping_output(self):
        payloads, _ = fixture_payloads()
        invalid = [
            ("../escape", b"x", tarfile.REGTYPE, ""),
            ("/Windows11.qcow2", b"x", tarfile.REGTYPE, ""),
            ("nested/Windows11.qcow2", b"x", tarfile.REGTYPE, ""),
            ("windows-image-info.json", b"", tarfile.SYMTYPE, "../escape"),
            ("windows-image-info.json", b"", tarfile.LNKTYPE, "Windows11.qcow2"),
            ("ignored", b"", tarfile.DIRTYPE, ""),
        ]
        for member in invalid:
            with self.subTest(name=member[0], kind=member[2]):
                with self.assertRaisesRegex(ArtifactError, "allowlist|regular"):
                    self.decode(self.encode_tar(small_gnu_tar(regular_members(payloads) + [member])))
                self.assertFalse((self.directory / "escape").exists())

    def test_duplicate_member_including_dot_slash_alias_is_rejected(self):
        payloads, _ = fixture_payloads()
        for name in ("Windows11.qcow2", "./Windows11.qcow2"):
            with self.subTest(name=name):
                duplicate = (name, payloads["Windows11.qcow2"], tarfile.REGTYPE, "")
                with self.assertRaisesRegex(ArtifactError, "repeats"):
                    self.decode(self.encode_tar(small_gnu_tar(regular_members(payloads) + [duplicate])))

    def test_plaintext_source_digest_and_coverage_are_verified(self):
        payloads, build_record = fixture_payloads()
        record, _ = self.decode(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        wrong_sha = copy.deepcopy(build_record)
        wrong_sha["files"]["Windows11.qcow2"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ArtifactError, "producer size/SHA-256"):
            receiver.verify_declared_files(wrong_sha, record["files"])
        wrong_size = copy.deepcopy(build_record)
        wrong_size["files"]["Windows11.qcow2"]["bytes"] += 1
        with self.assertRaisesRegex(ArtifactError, "producer size/SHA-256"):
            receiver.verify_declared_files(wrong_size, record["files"])
        missing = copy.deepcopy(build_record)
        missing["files"].pop("private-credentials.json")
        with self.assertRaisesRegex(ArtifactError, "cover every"):
            receiver.verify_declared_files(missing, record["files"])
        self_hash = copy.deepcopy(build_record)
        self_hash["files"]["build-record.json"] = {"bytes": 1, "sha256": "0" * 64}
        with self.assertRaisesRegex(ArtifactError, "self-referential"):
            receiver.verify_declared_files(self_hash, record["files"])

    def test_metadata_and_image_caps_reject_declared_size_before_body_read(self):
        for name, size, budgets in (
            ("private-credentials.json", 257, {"max_metadata_bytes": 256}),
            ("Windows11.qcow2", 257, {"max_image_bytes": 256}),
        ):
            with self.subTest(name=name):
                # Header alone: the resource check must win over the missing body.
                raw = tar_header(name, size) + b"\0" * 1024
                with self.assertRaisesRegex(ArtifactError, "resource budget"):
                    self.decode(self.encode_tar(raw), **budgets)

    def test_explicit_fixture_cannot_finalize_a_source_stage_or_log_credentials(self):
        payloads, _ = fixture_payloads(production_tags=True)
        directory = self.write_parts(self.encode_tar(small_gnu_tar(regular_members(payloads))))
        key_file = self.new_path("fixture-key")
        original_key = PASSWORD + b"\r\n"
        key_file.write_bytes(original_key)
        output = self.new_path("rejected-fixture")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaisesRegex(ArtifactError, "Synthetic fixtures"):
                receiver.receive_windows(directory, key_file, output, part_bytes=PART_BYTES)
        receipt = json.loads((output / receiver.RECEIPT_NAME).read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "failed")
        self.assertFalse(receipt["source_stage_complete"])
        self.assertFalse(receipt["key_material_recorded"])
        self.assertFalse(receipt["phone_operated"])
        self.assertFalse(receipt["phone_boot_verified"])
        self.assertEqual(key_file.read_bytes(), original_key)
        self.assertNotIn(PASSWORD.decode("ascii"), stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(PASSWORD.decode("ascii"), json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
