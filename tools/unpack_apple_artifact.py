#!/usr/bin/env python3
"""Verify and unpack the task's encrypted Apple CI artifacts with bounded reads.

Requires cryptography; macOS also requires zstandard. A key file contains one
UTF-8 line, with an optional final newline and no BOM. Its bytes are not logged.
Inputs and failed partial output are preserved. This does not verify phone boot.

macOS: AES-256-CBC / PBKDF2-SHA256, 10000 iterations, zstd, GNU sparse tar.
iPadOS: AES-256-CBC / PBKDF2-SHA256, 200000 iterations, gzip, BSD tar.
Use --salt-bytes for the salt length observed in the actual runner's OpenSSL.
The known Ubuntu 24.04 macOS profile defaults to 8; iPadOS requires an explicit
8 or 16 until its runner's OpenSSL has been checked.
"""

import argparse
import ctypes
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import time

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


CHUNK = 4 * 1024 * 1024
ZERO_CHUNK = bytes(CHUNK)
ZERO_TAR_BLOCK = bytes(tarfile.BLOCKSIZE)
MACOS_FILES = {
    "boot.img", "manifest.json", "kernel.macho.trustcache",
    "data-store.img", "scratch-data.img", "disk.json",
}
IPADOS_ROOTS = {
    "release", "generation", "upstream-vm-template.json", "build-result.json",
}


class ArtifactError(Exception):
    pass


def read_exact(source, size, description):
    chunks = []
    left = size
    while left:
        block = source.read(min(left, CHUNK))
        if not block:
            raise ArtifactError(f"Truncated {description}: {left} bytes missing")
        chunks.append(block)
        left -= len(block)
    return b"".join(chunks)


def load_parts(parts_dir, kind):
    suffix = ".tar.zst.enc.sha256" if kind == "macos" else ".tar.gz.enc.sha256"
    manifests = sorted(path for path in parts_dir.iterdir() if path.name.endswith(suffix))
    if len(manifests) != 1:
        raise ArtifactError(f"Expected one *{suffix} manifest in the parts directory; found {len(manifests)}")
    manifest = manifests[0]
    if manifest.is_symlink() or not manifest.is_file():
        raise ArtifactError("The part manifest must be a regular file")
    prefix = manifest.name[:-len(".sha256")]
    rows = []
    names = set()
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if not match:
            raise ArtifactError(f"Malformed SHA-256 manifest row {line_number}")
        sha, name = match.groups()
        number = re.fullmatch(re.escape(prefix) + r"\.([0-9]{3})", name)
        if not number or name in names:
            raise ArtifactError(f"Unexpected or repeated part name at manifest row {line_number}")
        names.add(name)
        path = parts_dir / name
        if path.is_symlink() or not path.is_file():
            raise ArtifactError(f"Missing regular ciphertext part: {name}")
        rows.append({"name": name, "path": path, "number": int(number[1]), "expected_sha256": sha.lower()})
    rows.sort(key=lambda row: row["number"])
    if not rows or [row["number"] for row in rows] != list(range(len(rows))):
        raise ArtifactError("Ciphertext parts must be a complete sequence starting at .000")
    present = {path.name for path in parts_dir.iterdir()
               if re.fullmatch(re.escape(prefix) + r"\.[0-9]{3}", path.name)}
    if present != names:
        raise ArtifactError("The directory's numbered parts differ from the SHA-256 manifest")
    return manifest, rows


def verify_parts(manifest, rows, record):
    whole = hashlib.sha256()
    verified = []
    record["parts"] = verified
    record["parts_manifest"] = str(manifest)
    record["parts_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    total = 0
    for row in rows:
        sha = hashlib.sha256()
        count = 0
        with row["path"].open("rb") as source:
            for block in iter(lambda: source.read(CHUNK), b""):
                sha.update(block)
                whole.update(block)
                count += len(block)
        observed = sha.hexdigest()
        item = {"name": row["name"], "path": str(row["path"]), "bytes": count,
                "expected_sha256": row["expected_sha256"], "observed_sha256": observed,
                "verified": count > 0 and observed == row["expected_sha256"]}
        verified.append(item)
        if not item["verified"]:
            raise ArtifactError(f"Ciphertext part is empty or its SHA-256 differs: {row['name']}")
        total += count
        print(f"Verified {row['name']} ({count} bytes)", flush=True)
    if total < 32:
        raise ArtifactError("The complete ciphertext is too short for the OpenSSL salted format")
    record.update({
        "parts_manifest": str(manifest),
        "parts_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "all_numbered_parts_verified": True,
        "ciphertext_bytes": total,
        "ciphertext_sha256": whole.hexdigest(),
        "ciphertext_whole_sha256_is_self_computed": True,
    })


class PartsReader(io.RawIOBase):
    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self.index = 0
        self.current = None
        self.bytes_read = 0

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            raise ArtifactError("An unbounded ciphertext read was requested")
        size = min(size, CHUNK)
        result = bytearray()
        while len(result) < size and self.index < len(self.rows):
            if self.current is None:
                self.current = self.rows[self.index]["path"].open("rb")
            block = self.current.read(size - len(result))
            if block:
                result.extend(block)
            else:
                self.current.close()
                self.current = None
                self.index += 1
        self.bytes_read += len(result)
        return bytes(result)

    def readinto(self, buffer):
        block = self.read(len(buffer))
        buffer[:len(block)] = block
        return len(block)

    def close(self):
        if self.current is not None:
            self.current.close()
            self.current = None
        super().close()


class DecryptedReader(io.RawIOBase):
    def __init__(self, source, password, iterations, salt_bytes, record):
        super().__init__()
        self.source = source
        self.buffer = bytearray()
        self.finished = False
        self.padding_verified = False
        if read_exact(source, 8, "OpenSSL header") != b"Salted__":
            raise ArtifactError("Ciphertext lacks the OpenSSL Salted__ header")
        salt = read_exact(source, salt_bytes, "OpenSSL salt")
        material = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=48)
        self.decryptor = Cipher(algorithms.AES(material[:32]), modes.CBC(material[32:])).decryptor()
        self.unpadder = padding.PKCS7(128).unpadder()
        record["encryption"] = {
            "cipher": "AES-256-CBC", "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": iterations, "salt_bytes": salt_bytes,
            "salt_hex": salt.hex(), "pkcs7_padding_verified": False,
            "key_material_recorded": False,
        }

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            raise ArtifactError("An unbounded decrypted read was requested")
        size = min(size, CHUNK)
        while len(self.buffer) < size and not self.finished:
            block = self.source.read(CHUNK)
            if block:
                self.buffer.extend(self.unpadder.update(self.decryptor.update(block)))
            else:
                try:
                    self.buffer.extend(self.unpadder.update(self.decryptor.finalize()))
                    self.buffer.extend(self.unpadder.finalize())
                except ValueError as error:
                    raise ArtifactError("AES-CBC length or PKCS#7 padding is invalid; check the key and the explicit salt/profile selection") from error
                self.finished = True
                self.padding_verified = True
        block = bytes(self.buffer[:size])
        del self.buffer[:size]
        return block

    def readinto(self, buffer):
        block = self.read(len(buffer))
        buffer[:len(block)] = block
        return len(block)


class ZstdReader:
    """Feed one format-bounded zstd block at a time, including its final checksum.

    zstandard.stream_reader alone accepts a truncated final frame. The public
    frame-header parser plus 128-KiB zstd blocks keeps allocation bounded while
    decompressobj.eof establishes that this producer's single frame completed.
    """

    def __init__(self, source, record):
        try:
            import zstandard
        except ImportError as error:
            raise ArtifactError("macOS unpacking requires the Python zstandard package") from error
        self.zstd = zstandard
        self.source = source
        self.buffer = bytearray()
        self.finished = False
        first = read_exact(source, 6, "zstd frame header")
        if first[:4] != b"\x28\xb5\x2f\xfd":
            raise ArtifactError("Decrypted macOS bytes lack zstd magic; check the key and --salt-bytes")
        header_size = zstandard.frame_header_size(first)
        header = first + read_exact(source, header_size - len(first), "zstd frame header")
        parameters = zstandard.get_frame_parameters(header)
        # libzstd's standard streaming window budget is 128 MiB. The actual
        # producer's window is parsed and recorded before decoder allocation.
        if parameters.window_size > 128 * 1024**2:
            raise ArtifactError(f"The zstd frame needs a {parameters.window_size}-byte window, exceeding the 128-MiB extraction budget")
        self.decoder = zstandard.ZstdDecompressor(max_window_size=128 * 1024**2).decompressobj()
        if self.decoder.decompress(header):
            raise ArtifactError("Unexpected data from a zstd frame header")
        self.has_checksum = parameters.has_checksum
        self.compression_record = {
            "format": "zstd", "python_zstandard_version": zstandard.__version__,
            "frame_window_bytes": parameters.window_size,
            "frame_content_size": parameters.content_size,
            "frame_has_checksum": parameters.has_checksum,
            "complete_frame_verified": False,
        }
        record["compression"] = self.compression_record

    def read(self, size=-1):
        if size < 0:
            raise ArtifactError("An unbounded decompressed read was requested")
        size = min(size, CHUNK)
        while len(self.buffer) < size and not self.finished:
            header = read_exact(self.source, 3, "zstd block header")
            word = int.from_bytes(header, "little")
            last, kind, length = bool(word & 1), (word >> 1) & 3, word >> 3
            if kind == 3 or length > self.zstd.BLOCKSIZE_MAX:
                raise ArtifactError("Invalid zstd block type or block size")
            payload = read_exact(self.source, 1 if kind == 1 else length, "zstd block payload")
            self.buffer.extend(self.decoder.decompress(header + payload))
            if last:
                if self.has_checksum:
                    self.buffer.extend(self.decoder.decompress(read_exact(self.source, 4, "zstd frame checksum")))
                if not self.decoder.eof or self.decoder.unused_data:
                    raise ArtifactError("The zstd frame did not finish exactly at its advertised end")
                if self.source.read(1):
                    raise ArtifactError("Unexpected decrypted bytes after the producer's zstd frame")
                self.finished = True
                self.compression_record["complete_frame_verified"] = True
        block = bytes(self.buffer[:size])
        del self.buffer[:size]
        return block


class StrictTarInfo(tarfile.TarInfo):
    @classmethod
    def fromtarfile(cls, archive):
        position = archive.fileobj.tell()
        block = archive.fileobj.read(tarfile.BLOCKSIZE)
        if len(block) != tarfile.BLOCKSIZE:
            raise tarfile.ReadError("Truncated tar header or missing two-block end marker")
        if block == ZERO_TAR_BLOCK:
            if archive.fileobj.read(tarfile.BLOCKSIZE) != ZERO_TAR_BLOCK:
                raise tarfile.ReadError("Tar archive lacks its complete two-block zero end marker")
            archive.verified_end_markers = True
            raise tarfile.EOFHeaderError("verified tar end marker")
        try:
            member = cls.frombuf(block, archive.encoding, archive.errors)
            member.offset = position
            return member._proc_member(archive)
        except tarfile.HeaderError as error:
            raise tarfile.ReadError(f"Malformed tar header at byte {position}: {error}") from error


def member_path(member, kind):
    name = member.name
    if name in {".", "./"} and member.isdir():
        return None
    if name.startswith("./"):
        name = name[2:]
    if member.isdir() and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    if (not name or PurePosixPath(name).is_absolute() or
            any(part in {"", ".", ".."} for part in parts) or
            any(char in name for char in '\\:<>"|?*\0') or
            any(ord(char) < 32 for char in name)):
        raise ArtifactError("Archive member is not a supported relative file or directory path")
    if any(part.endswith((".", " ")) for part in parts):
        raise ArtifactError("Archive member has a path component that Windows would rename")
    if os.name == "nt":
        reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        reserved.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10))
        if any(part.split(".", 1)[0].upper() in reserved for part in parts):
            raise ArtifactError("Archive member names a Windows device")
    if kind == "macos" and (name not in MACOS_FILES or member.isdir()):
        raise ArtifactError(f"Unexpected member in the six-file macOS image artifact: {name}")
    if kind == "ipados" and (parts[0] not in IPADOS_ROOTS or
            (len(parts) > 1 and parts[0] not in {"release", "generation"})):
        raise ArtifactError(f"Unexpected member outside the iPadOS staging tree: {name}")
    return name


def mark_sparse(stream):
    if os.name != "nt":
        return "POSIX seek/truncate"
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    control = kernel.DeviceIoControl
    control.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    control.restype = wintypes.BOOL
    returned = wintypes.DWORD()
    if not control(msvcrt.get_osfhandle(stream.fileno()), 0x000900C4,
                   None, 0, None, 0, ctypes.byref(returned), None):
        raise ArtifactError(f"Windows FSCTL_SET_SPARSE failed (error {ctypes.get_last_error()}); partial output is preserved")
    return "Windows FSCTL_SET_SPARSE"


def allocated_bytes(stream):
    if os.name != "nt":
        stat = os.fstat(stream.fileno())
        return stat.st_blocks * 512 if hasattr(stat, "st_blocks") else None
    import msvcrt
    from ctypes import wintypes

    class FileStandardInfo(ctypes.Structure):
        _fields_ = [("AllocationSize", ctypes.c_longlong), ("EndOfFile", ctypes.c_longlong),
                    ("NumberOfLinks", wintypes.DWORD), ("DeletePending", wintypes.BYTE),
                    ("Directory", wintypes.BYTE)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetFileInformationByHandleEx
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    query.restype = wintypes.BOOL
    info = FileStandardInfo()
    if not query(msvcrt.get_osfhandle(stream.fileno()), 1, ctypes.byref(info), ctypes.sizeof(info)):
        return None
    return info.AllocationSize


def hash_zeros(sha, size):
    while size:
        count = min(size, CHUNK)
        sha.update(ZERO_CHUNK if count == CHUNK else ZERO_CHUNK[:count])
        size -= count


def extract_member(archive, member, target, item):
    if member.size < 0:
        raise ArtifactError("Tar member has a negative logical size")
    extents = []
    if member.sparse is None:
        extents = [(0, member.size)] if member.size else []
    else:
        end = 0
        for offset, length in member.sparse:
            if offset < 0 or length < 0 or offset > member.size or length > member.size - offset:
                raise ArtifactError("GNU sparse map exceeds its member's logical file size")
            if not length:
                continue  # GNU uses unused (0,0) slots and an optional (size,0) sentinel.
            if offset < end:
                raise ArtifactError("GNU sparse data ranges overlap or run backwards")
            extents.append((offset, length))
            end = offset + length
    stored = sum(length for offset, length in extents)
    if stored + (-stored % tarfile.BLOCKSIZE) != archive.offset - member.offset_data:
        raise ArtifactError("Tar sparse map does not cover the stored member bytes")
    item.update({"stored_data_bytes": stored, "gnu_sparse_map": member.sparse,
                 "zero_chunks_elided_bytes": 0})
    sha = hashlib.sha256()
    logical_position = 0
    last_progress = time.monotonic()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb", buffering=0) as output:
        item["sparse_method"] = mark_sparse(output)
        for offset, length in extents:
            hash_zeros(sha, offset - logical_position)
            output.seek(offset)
            remaining = length
            while remaining:
                block = read_exact(archive.fileobj, min(remaining, CHUNK), f"tar data for {item['path']}")
                sha.update(block)
                if block == (ZERO_CHUNK if len(block) == CHUNK else ZERO_CHUNK[:len(block)]):
                    output.seek(len(block), os.SEEK_CUR)
                    item["zero_chunks_elided_bytes"] += len(block)
                else:
                    remaining_write = memoryview(block)
                    while remaining_write:
                        count = output.write(remaining_write)
                        if not count:
                            raise ArtifactError("The destination stopped accepting file data")
                        remaining_write = remaining_write[count:]
                remaining -= len(block)
                now = time.monotonic()
                if now - last_progress >= 15:
                    print(f"Extracting {item['path']}: {offset + length - remaining}/{member.size} logical bytes", flush=True)
                    last_progress = now
            logical_position = offset + length
        hash_zeros(sha, member.size - logical_position)
        output.truncate(member.size)
        item["allocated_bytes"] = allocated_bytes(output)
    trailer = archive.offset - archive.fileobj.tell()
    if not 0 <= trailer < tarfile.BLOCKSIZE:
        raise ArtifactError("Tar member data did not finish at its declared boundary")
    if read_exact(archive.fileobj, trailer, "tar member padding").strip(b"\0"):
        raise ArtifactError("Tar member padding contains nonzero bytes")
    if target.stat().st_size != member.size:
        raise ArtifactError("Extracted file length differs from the tar member length")
    item.update({"status": "complete", "bytes": target.stat().st_size, "sha256": sha.hexdigest(),
                 "sha256_source": "self-computed logical file bytes, including holes"})


def extract_tar(source, output, kind, record):
    seen = set()
    files = record["files"]
    directories = record["directories"]
    with tarfile.open(fileobj=source, mode="r|", bufsize=128 * 1024,
                      tarinfo=StrictTarInfo, errorlevel=2) as archive:
        archive.verified_end_markers = False
        for member in archive:
            if not (member.isfile() or member.isdir()):
                raise ArtifactError("Archive links, devices and other non-file members are not supported")
            if member.isdir() and (member.size != 0 or member.sparse is not None):
                raise ArtifactError("A tar directory member unexpectedly contains data")
            name = member_path(member, kind)
            if name is None:
                continue
            identity = name.casefold() if os.name == "nt" else name
            if identity in seen:
                raise ArtifactError(f"Repeated archive member: {name}")
            seen.add(identity)
            target = output.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                directories.append({"archive_name": member.name, "path": name})
                continue
            item = {"archive_name": member.name, "path": name, "status": "extracting",
                    "expected_bytes": member.size, "bytes": None, "sha256": None}
            files.append(item)
            extract_member(archive, member, target, item)
            print(f"Extracted {name} ({item['bytes']} bytes; allocated {item['allocated_bytes']})", flush=True)
        if not archive.verified_end_markers:
            raise ArtifactError("Tar end markers were not verified")
        trailing = 0
        while True:
            block = archive.fileobj.read(CHUNK)
            if not block:
                break
            if block.strip(b"\0"):
                raise ArtifactError("Nonzero trailing bytes follow the tar end markers")
            trailing += len(block)
        if trailing % tarfile.BLOCKSIZE:
            raise ArtifactError("Tar trailing zero padding ends inside a 512-byte block")
        record["tar"] = {"two_zero_end_blocks_verified": True,
                         "trailing_zero_padding_bytes": trailing, "complete_archive_verified": True}
    extracted = {item["path"] for item in files}
    if kind == "macos" and extracted != MACOS_FILES:
        raise ArtifactError(f"Incomplete six-file macOS image artifact; missing {sorted(MACOS_FILES - extracted)}")
    if kind == "ipados" and not ({"upstream-vm-template.json", "build-result.json"} <= extracted and
            any(name.startswith("release/") for name in extracted) and
            any(name.startswith("generation/") for name in extracted)):
        raise ArtifactError("The iPadOS staging archive lacks release, generation or its top-level records")


def load_key(path):
    with path.open("rb") as source:
        value = source.read(CHUNK)
        if source.read(1):
            raise ArtifactError("The key file exceeds the extractor's 4-MiB single-line read budget")
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if not value or value.startswith(b"\xef\xbb\xbf") or any(char in value for char in (b"\r", b"\n", b"\0")):
        raise ArtifactError("The key file must contain one UTF-8 line without a BOM or embedded newline/NUL")
    try:
        value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactError("The key file is not UTF-8 text") from error
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kind", choices=("macos", "ipados"), required=True)
    parser.add_argument("--parts-dir", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="A new directory; existing output is never overwritten")
    parser.add_argument("--salt-bytes", type=int, choices=(8, 16), help="Observed OpenSSL salt length; macOS default 8, iPadOS requires an explicit value")
    args = parser.parse_args()
    if args.kind == "ipados" and args.salt_bytes is None:
        parser.error("iPadOS requires --salt-bytes 8 or 16 from its actual runner's OpenSSL evidence")
    salt_bytes = args.salt_bytes if args.salt_bytes is not None else 8
    output = args.output.resolve()
    if output.exists():
        parser.error("The output directory already exists; choose a new directory")
    output.mkdir(parents=True)
    started = time.monotonic()
    record = {
        "status": "incomplete", "kind": args.kind,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "parts_directory": str(args.parts_dir.resolve()), "output_directory": str(output),
        "key_file_path": str(args.key_file.resolve()),
        "profile_source": "sources/macOS-DroidVM/scripts/ci-blob.sh" if args.kind == "macos" else "tools/build_ipados_ci.sh",
        "files": [], "directories": [], "all_numbered_parts_verified": False,
        "archive_integrity_verified": False, "phone_boot_verified": False,
        "os_payload_semantics_verified": False, "input_files_modified": False,
        "key_file_modified": False, "key_material_recorded": False,
        "extracted_file_sha256_is_publisher_provided": False,
        "read_chunk_bytes": CHUNK,
    }
    profile_source = Path(__file__).resolve().parents[1] / record["profile_source"]
    if profile_source.is_file():
        record["profile_source_sha256"] = hashlib.sha256(profile_source.read_bytes()).hexdigest()
    stage = "part-manifest"
    decrypted = None
    try:
        parts_dir = args.parts_dir.resolve(strict=True)
        if not parts_dir.is_dir():
            raise ArtifactError("The parts directory is not a directory")
        manifest, rows = load_parts(parts_dir, args.kind)
        stage = "part-verification"
        verify_parts(manifest, rows, record)
        stage = "key-and-encryption-header"
        password = load_key(args.key_file.resolve(strict=True))
        with PartsReader(rows) as encrypted:
            decrypted = DecryptedReader(encrypted, password, 10000 if args.kind == "macos" else 200000,
                                        salt_bytes, record)
            del password
            stage = "decompression-and-tar-extraction"
            if args.kind == "macos":
                decompressed = ZstdReader(decrypted, record)
                extract_tar(decompressed, output, args.kind, record)
            else:
                compressed = io.BufferedReader(decrypted, buffer_size=128 * 1024)
                if compressed.peek(3)[:3] != b"\x1f\x8b\x08":
                    raise ArtifactError("Decrypted iPadOS bytes lack gzip magic; check the key and --salt-bytes")
                record["compression"] = {"format": "gzip", "complete_stream_crc_and_size_verified": False}
                with gzip.GzipFile(fileobj=compressed, mode="rb") as decompressed:
                    extract_tar(decompressed, output, args.kind, record)
                record["compression"] = {"format": "gzip", "complete_stream_crc_and_size_verified": True}
            stage = "final-stream-verification"
            if decrypted.read(1):
                raise ArtifactError("Decrypted compressed bytes remain unread after extraction")
            if not decrypted.padding_verified or encrypted.bytes_read != record["ciphertext_bytes"]:
                raise ArtifactError("The complete ciphertext and PKCS#7 padding were not verified")
            record["encryption"]["pkcs7_padding_verified"] = True
        record.update({"status": "complete", "archive_integrity_verified": True,
                       "logical_file_bytes": sum(item["bytes"] for item in record["files"])})
    except (Exception, KeyboardInterrupt) as error:
        record.update({"status": "interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                       "failure_stage": stage, "error_type": type(error).__name__,
                       "error": str(error) or "Extraction interrupted"})
        for item in record["files"]:
            if item["status"] != "complete":
                path = output.joinpath(*PurePosixPath(item["path"]).parts)
                item["bytes"] = path.stat().st_size if path.is_file() else None
                item["sha256_unavailable_reason"] = "Partial extraction did not reach a verified member boundary"
        print(f"Extraction {record['status']} during {stage}: {record['error']}", file=sys.stderr)
    finally:
        if decrypted is not None and "encryption" in record:
            record["encryption"]["pkcs7_padding_verified"] = decrypted.padding_verified
        record["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        record["extractor_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        (output / "extraction-record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if record["status"] != "complete":
        return 1
    print(f"Completed verified archive extraction: {len(record['files'])} files. Phone boot is unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
