"""Tiny real CBC/zstd/gzip/tar boundaries with a synthetic fixture key only.

These tests never read a build secret, download an artifact, execute a target,
or contact a phone. They exercise the public CLI and retained failure records.
"""

import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import zstandard

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import unpack_apple_artifact as unpacker

FIXTURE_KEY = b"synthetic extractor boundary key; not the actual build secret"
KERNEL = b"synthetic non-executable kernel collection fixture\n" * 19


def tar_bytes(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return result.getvalue()


def encrypt(compressed, salt_bytes, iterations):
    salt = bytes(range(1, salt_bytes + 1))
    material = hashlib.pbkdf2_hmac("sha256", FIXTURE_KEY, salt, iterations, dklen=48)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(compressed) + padder.finalize()
    cipher = Cipher(algorithms.AES(material[:32]), modes.CBC(material[32:])).encryptor()
    return b"Salted__" + salt + cipher.update(padded) + cipher.finalize()


class Fixture:
    def __init__(self, directory, *, kind="macos-kernel", salt_bytes=8, members=None,
                 raw_tar=None, compressed=None, prefix=None):
        self.directory = directory
        directory.mkdir()
        self.parts = directory / "parts"
        self.parts.mkdir()
        self.output = directory / "new-output"
        self.key = directory / "synthetic-key.txt"
        self.key.write_bytes(FIXTURE_KEY + b"\r\n")
        self.kind = kind
        self.salt_bytes = salt_bytes
        self.prefix = prefix or ("kc.tar.zst.enc" if kind == "macos-kernel"
                                 else "image.tar.zst.enc" if kind == "macos"
                                 else "image.tar.gz.enc")
        self.manifest = self.parts / (self.prefix + ".sha256")
        if compressed is None:
            raw_tar = tar_bytes(members if members is not None else [(unpacker.MACOS_KERNEL_MEMBER, KERNEL)]) if raw_tar is None else raw_tar
            compressed = (gzip.compress(raw_tar) if kind == "ipados"
                          else zstandard.ZstdCompressor(level=1, write_checksum=True).compress(raw_tar))
        self.encrypted = encrypt(compressed, salt_bytes, 200000 if kind == "ipados" else 10000)
        self.write_parts(self.encrypted)

    def write_parts(self, encrypted):
        # Split inside the encrypted header as well as inside ciphertext blocks.
        pieces = (encrypted[:13], encrypted[13:])
        rows = []
        for index, data in enumerate(pieces):
            name = self.prefix + f".{index:03}"
            (self.parts / name).write_bytes(data)
            rows.append(hashlib.sha256(data).hexdigest() + "  " + name + "\n")
        self.manifest.write_text("".join(rows), encoding="utf8")

    def run(self, *, kind=None, explicit_salt=None):
        args = ["unpack_apple_artifact.py", "--kind", kind or self.kind,
                "--parts-dir", str(self.parts), "--key-file", str(self.key), "--output", str(self.output)]
        if explicit_salt is not None:
            args += ["--salt-bytes", str(explicit_salt)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", args), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = unpacker.main()
        record = json.loads((self.output / "extraction-record.json").read_text(encoding="utf8"))
        assert FIXTURE_KEY.decode() not in stdout.getvalue() + stderr.getvalue()
        assert FIXTURE_KEY.decode() not in json.dumps(record)
        return code, record


class UnpackArtifactTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="apple-extractor-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.fixture_number = 0

    def fixture(self, **options):
        self.fixture_number += 1
        return Fixture(self.directory / str(self.fixture_number), **options)

    def test_single_kernel_roundtrips_both_salt_widths_with_explicit_and_inferred_profiles(self):
        for salt_bytes in (8, 16):
            for explicit in (False, True):
                with self.subTest(salt=salt_bytes, explicit=explicit):
                    fixture = self.fixture(salt_bytes=salt_bytes)
                    inputs = {path: path.read_bytes() for path in fixture.parts.iterdir()}
                    inputs[fixture.key] = fixture.key.read_bytes()
                    code, record = fixture.run(explicit_salt=salt_bytes if explicit else None)
                    self.assertEqual(code, 0)
                    self.assertEqual(record["status"], "complete")
                    self.assertTrue(record["all_numbered_parts_verified"])
                    self.assertTrue(record["archive_integrity_verified"])
                    self.assertTrue(record["encryption"]["pkcs7_padding_verified"])
                    self.assertTrue(record["compression"]["complete_frame_verified"])
                    self.assertTrue(record["tar"]["complete_archive_verified"])
                    self.assertEqual(record["encryption"]["iterations"], 10000)
                    self.assertEqual(record["encryption"]["salt_bytes"], salt_bytes)
                    self.assertEqual(record["salt_selection"]["method"],
                                     "caller-selected" if explicit else "unique-decrypted-zstd-magic-candidate")
                    self.assertFalse(record["salt_selection"]["runner_openssl_version_observed"])
                    self.assertEqual([item["path"] for item in record["files"]], [unpacker.MACOS_KERNEL_MEMBER])
                    self.assertEqual(record["files"][0]["sha256"], hashlib.sha256(KERNEL).hexdigest())
                    self.assertEqual((fixture.output / unpacker.MACOS_KERNEL_MEMBER).read_bytes(), KERNEL)
                    self.assertFalse(record["phone_boot_verified"])
                    self.assertFalse(record["os_payload_semantics_verified"])
                    for path, original in inputs.items():
                        self.assertEqual(path.read_bytes(), original)

    def test_old_macos_and_ipados_profiles_keep_their_original_contracts(self):
        macos = [(name, (name + " synthetic\n").encode()) for name in sorted(unpacker.MACOS_FILES)]
        ipados = [("upstream-vm-template.json", b"{}\n"), ("build-result.json", b"{}\n"),
                  ("release/kernel.bin", b"fixture kernel"), ("generation/record.json", b"{}\n")]
        for kind, members, salt_bytes in (("macos", macos, 8), ("ipados", ipados, 8), ("ipados", ipados, 16)):
            with self.subTest(kind=kind, salt=salt_bytes):
                fixture = self.fixture(kind=kind, salt_bytes=salt_bytes, members=members)
                code, record = fixture.run(explicit_salt=None if kind == "macos" else salt_bytes)
                self.assertEqual(code, 0)
                self.assertEqual({item["path"] for item in record["files"]}, {name for name, _ in members})
                self.assertEqual(record["encryption"]["iterations"], 10000 if kind == "macos" else 200000)
                self.assertNotIn("kernel_contract", record)
                self.assertNotIn("salt_selection", record)

    def test_kernel_contract_rejects_wrong_extra_duplicate_and_empty_members(self):
        cases = {
            "missing": [],
            "wrong": [("out/k27/other.bin", KERNEL)],
            "extra": [(unpacker.MACOS_KERNEL_MEMBER, KERNEL), ("verification.json", b"{}")],
            "duplicate": [(unpacker.MACOS_KERNEL_MEMBER, KERNEL)] * 2,
            "empty": [(unpacker.MACOS_KERNEL_MEMBER, b"")],
            "image": [(name, b"fixture") for name in sorted(unpacker.MACOS_FILES)],
            "traversal": [("../kc-k27.bin", KERNEL)],
        }
        for name, members in cases.items():
            with self.subTest(case=name):
                fixture = self.fixture(members=members)
                code, record = fixture.run()
                self.assertEqual(code, 1)
                self.assertEqual(record["status"], "failed")
                self.assertFalse(record["archive_integrity_verified"])
                self.assertTrue(fixture.manifest.exists())
                self.assertTrue(fixture.key.exists())
        fixture = self.fixture()
        code, record = fixture.run(kind="macos")
        self.assertEqual(code, 1)
        self.assertIn("six-file", record["error"])

    def test_kernel_type_and_logical_size_are_checked_before_creating_a_member(self):
        for case in ("directory", "root-directory", "symlink", "over-budget"):
            with self.subTest(case=case):
                info = tarfile.TarInfo("." if case == "root-directory" else unpacker.MACOS_KERNEL_MEMBER)
                if case in ("directory", "root-directory"):
                    info.type = tarfile.DIRTYPE
                elif case == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/foreign/target"
                else:
                    info.size = unpacker.MAX_MACOS_KERNEL_BYTES + 1
                raw_tar = info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)
                fixture = self.fixture(raw_tar=raw_tar)
                code, record = fixture.run()
                self.assertEqual(code, 1)
                self.assertEqual(record["files"], [])
                self.assertFalse((fixture.output / unpacker.MACOS_KERNEL_MEMBER).exists())
                self.assertEqual(record["kernel_contract"]["max_member_bytes"], 512 * 1024**2)

    def test_profile_key_and_complete_encrypted_compressed_tar_boundaries_remain_required(self):
        raw_tar = tar_bytes([(unpacker.MACOS_KERNEL_MEMBER, KERNEL)])
        zstd = zstandard.ZstdCompressor(write_checksum=True).compress(raw_tar)
        for case in ("wrong-key", "wrong-salt", "CBC-truncated", "zstd-truncated", "zstd-trailing", "tar-truncated"):
            with self.subTest(case=case):
                if case == "zstd-truncated":
                    fixture = self.fixture(compressed=zstd[:-1])
                elif case == "zstd-trailing":
                    fixture = self.fixture(compressed=zstd + b"trailing compressed bytes")
                elif case == "tar-truncated":
                    # Keep the exact member and its padding, but omit tar's end blocks.
                    member_end = 512 + len(KERNEL) + (-len(KERNEL) % 512)
                    fixture = self.fixture(raw_tar=raw_tar[:member_end])
                else:
                    fixture = self.fixture()
                if case == "wrong-key":
                    fixture.key.write_bytes(b"another synthetic fixture password")
                elif case == "CBC-truncated":
                    fixture.write_parts(fixture.encrypted[:-1])
                code, record = fixture.run(explicit_salt=16 if case == "wrong-salt" else None)
                self.assertEqual(code, 1)
                self.assertEqual(record["status"], "failed")
                self.assertFalse(record["archive_integrity_verified"])

    def test_part_checksums_and_exact_kernel_manifest_prefix_cannot_be_bypassed(self):
        fixture = self.fixture()
        part = fixture.parts / (fixture.prefix + ".001")
        original = part.read_bytes()
        part.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        code, record = fixture.run()
        self.assertEqual(code, 1)
        self.assertEqual(record["failure_stage"], "part-verification")
        self.assertFalse(record["all_numbered_parts_verified"])
        fixture = self.fixture(prefix="other.tar.zst.enc")
        code, record = fixture.run()
        self.assertEqual(code, 1)
        self.assertEqual(record["failure_stage"], "part-manifest")

    def test_existing_output_and_original_ipados_explicit_salt_rule_are_preserved(self):
        fixture = self.fixture()
        fixture.output.mkdir()
        sentinel = fixture.output / "prior-product"
        sentinel.write_bytes(b"preserve existing delivery")
        with self.assertRaises(SystemExit) as result:
            fixture.run()
        self.assertEqual(result.exception.code, 2)
        self.assertEqual(sentinel.read_bytes(), b"preserve existing delivery")
        self.assertEqual(list(fixture.output.iterdir()), [sentinel])
        fixture = self.fixture(kind="ipados")
        with self.assertRaises(SystemExit) as result:
            fixture.run()
        self.assertEqual(result.exception.code, 2)
        self.assertFalse(fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
