#!/usr/bin/env python3
"""Verify DroidVM single-file VMPKG containers without extracting or booting them.

Source contract: DroidVM 33488301c902124d9ddb09fa04b8126443d83230,
app/src/main/java/cn/classfun/droidvm/{lib/pkg,lib/archive,daemon/vm/pkg}.
Supports none/gzip and regular GNU tar entries, including GNU long names and
positive base-256 sizes. The app's native manifest has no digest field; an
optional per-entry ``sha256`` extension provides an independent expected digest.
All supplied JSON fields and file bytes are preserved. VM/OS boot compatibility
and actual Android import are outside this verifier's scope.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
from dataclasses import dataclass
from typing import BinaryIO, Iterator


SOURCE_HEAD = "33488301c902124d9ddb09fa04b8126443d83230"
HEADER = struct.Struct("<6sHHHHHq")
MAGIC = b"VMPKG\0"
ALIGNMENT = 4096
MAX_MANIFEST_SIZE = 0xFFFF
MAX_SIGNED_LONG = (1 << 63) - 1
CHUNK_SIZE = 64 * 1024
COMPRESSION_TYPES = {"none": 0, "gzip": 1}


class PackageError(ValueError):
    """A malformed package or an input inconsistent with its declared content."""


@dataclass(frozen=True)
class FileEntry:
    section: str
    value: dict

    @property
    def archive_path(self) -> str:
        return self.value["archive_path"]

    @property
    def size(self) -> int:
        return self.value["size"]


@dataclass(frozen=True)
class Manifest:
    raw: bytes
    value: dict
    entries: dict[str, FileEntry]


def align_up(value: int) -> int:
    return (value + ALIGNMENT - 1) & ~(ALIGNMENT - 1)


def data_offset(manifest_size: int) -> int:
    # DroidVM uses alignUpStrict, even when the manifest ends on a boundary.
    return ((ALIGNMENT + manifest_size) // ALIGNMENT + 1) * ALIGNMENT


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PackageError(f"non-JSON numeric constant: {value}")


def parse_json(raw: bytes, label: str) -> object:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackageError(f"{label} is not strict UTF-8 JSON: {error}") from error


def _integer(value: object, label: str, low: int = 0, high: int = MAX_SIGNED_LONG) -> int:
    if type(value) is not int or not low <= value <= high:
        raise PackageError(f"{label} must be an integer in [{low}, {high}]")
    return value


def _string(value: object, label: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise PackageError(f"{label} must be {'a' if allow_empty else 'a non-empty'} string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise PackageError(f"{label} contains an invalid Unicode scalar") from error
    return value


def validate_archive_path(value: object, label: str = "archive_path") -> str:
    path = _string(value, label)
    parts = path.split("/")
    if (
        "\\" in path
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
        or any(part in ("", ".", "..") for part in parts)
        or ":" in parts[0]
        or ord(path[0]) <= 32
        or ord(path[-1]) <= 32
    ):
        raise PackageError(f"{label} must be a canonical relative POSIX path: {path!r}")
    return path


def _filename(value: object, label: str) -> str:
    name = validate_archive_path(value, label)
    if "/" in name:
        raise PackageError(f"{label} must be one filename, not a directory path")
    return name


def validate_manifest(raw: bytes) -> Manifest:
    if not 0 < len(raw) <= MAX_MANIFEST_SIZE:
        raise PackageError("manifest must contain 1..65535 UTF-8 bytes")
    value = parse_json(raw, "manifest")
    if not isinstance(value, dict):
        raise PackageError("manifest must be a JSON object")
    version = _integer(value.get("manifest_version"), "manifest_version", 1, 2)
    if value.get("format") != "vmpkg":
        raise PackageError("manifest.format must be 'vmpkg'")
    _integer(value.get("created_at"), "created_at")
    _integer(value.get("app_version_code"), "app_version_code", 0, 0xFFFF)
    _string(value.get("app_version"), "app_version")
    _string(value.get("app_build_type"), "app_build_type")
    if value.get("compression") not in COMPRESSION_TYPES:
        raise PackageError("these tools support manifest.compression 'gzip' or 'none'")
    vm = value.get("vm")
    if not isinstance(vm, dict):
        raise PackageError("manifest.vm must be a JSON object")
    _string(vm.get("name"), "vm.name")
    if "extra_options" in vm:
        options = vm["extra_options"]
        if not isinstance(options, list) or not all(isinstance(arg, str) for arg in options):
            raise PackageError("vm.extra_options must be an array of strings")
    for section in ("disks", "boots", "networks"):
        if not isinstance(value.get(section), list) or not all(
            isinstance(item, dict) for item in value[section]
        ):
            raise PackageError(f"manifest.{section} must be an array of objects")
    entries: dict[str, FileEntry] = {}
    kinds = set()
    for section in ("disks", "boots"):
        for index, item in enumerate(value[section]):
            label = f"{section}[{index}]"
            path = validate_archive_path(item.get("archive_path"), f"{label}.archive_path")
            if path == "manifest.json" or path in entries:
                raise PackageError(f"reserved or duplicate archive path: {path!r}")
            _filename(item.get("name"), f"{label}.name")
            _string(item.get("path"), f"{label}.path")
            _integer(item.get("size"), f"{label}.size")
            if "sha256" in item:
                digest = _string(item["sha256"], f"{label}.sha256")
                if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
                    raise PackageError(f"{label}.sha256 must be 64 hexadecimal characters")
            if section == "disks":
                _integer(item.get("index"), f"{label}.index", -1, (1 << 31) - 1)
                if type(item.get("readonly")) is not bool:
                    raise PackageError(f"{label}.readonly must be boolean")
                bus = _string(item.get("bus"), f"{label}.bus").lower()
                if bus not in {"virtio", "scsi", "pmem", "pflash", "cdrom"}:
                    raise PackageError(f"{label}.bus is not supported by this DroidVM build")
                fmt = _string(item.get("format"), f"{label}.format").lower()
                if fmt not in {"raw", "qcow2", "vhdx", "vdi", "vmdk", "iso"}:
                    raise PackageError(f"{label}.format is not supported by this DroidVM build")
                if type(item.get("attached", True)) is not bool:
                    raise PackageError(f"{label}.attached must be boolean")
                backing = _string(item.get("backing_archive", ""), f"{label}.backing_archive", True)
                if backing:
                    validate_archive_path(backing, f"{label}.backing_archive")
                if (not item.get("attached", True) or backing) and version < 2:
                    raise PackageError("attached=false/backing_archive requires manifest_version 2")
            else:
                kind = _string(item.get("kind"), f"{label}.kind")
                if kind not in {"uefi", "kernel", "initrd"} or kind in kinds:
                    raise PackageError(f"{label}.kind must be a unique uefi/kernel/initrd kind")
                kinds.add(kind)
            entries[path] = FileEntry(section, item)
    if not entries or not any(entry.size for entry in entries.values()):
        raise PackageError("manifest supplies no non-empty disk or boot files")
    disks = {path: entry for path, entry in entries.items() if entry.section == "disks"}
    for start in disks:
        visited = set()
        path = start
        while path:
            if path in visited:
                raise PackageError(f"cyclic backing_archive chain at {path!r}")
            if path not in disks:
                raise PackageError(f"backing_archive is not a packaged disk: {path!r}")
            visited.add(path)
            path = disks[path].value.get("backing_archive", "")
    return Manifest(raw, value, entries)


def load_manifest(path: os.PathLike | str) -> Manifest:
    with open(path, "rb") as source:
        return validate_manifest(source.read(MAX_MANIFEST_SIZE + 1))


def load_source_map(path: os.PathLike | str, manifest: Manifest) -> dict[str, str]:
    with open(path, "rb") as source:
        value = parse_json(source.read(), "source map")
    if not isinstance(value, dict):
        raise PackageError("source map must be archive_path -> absolute source path")
    for archive_path, source_path in value.items():
        validate_archive_path(archive_path, "source map key")
        _string(source_path, f"source map[{archive_path!r}]")
        if not Path(source_path).is_absolute():
            raise PackageError(f"source path must be absolute: {source_path!r}")
    if value.keys() != manifest.entries.keys():
        missing = sorted(manifest.entries.keys() - value.keys())
        extra = sorted(value.keys() - manifest.entries.keys())
        raise PackageError(f"source map differs from manifest: missing={missing!r}, extra={extra!r}")
    return value


@contextlib.contextmanager
def checked_source(path: str, expected_size: int) -> Iterator[BinaryIO]:
    with open(path, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise PackageError(f"source is not a regular file: {path!r}")
        if before.st_size != expected_size:
            raise PackageError(f"source size differs from manifest: {path!r}, {before.st_size} != {expected_size}")
        yield source
        if source.read(1):
            raise PackageError(f"source grew while being read: {path!r}")
        after = os.fstat(source.fileno())
        if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
            raise PackageError(f"source changed while being read: {path!r}")


def source_digest(path: str, expected_size: int) -> str:
    digest = hashlib.sha256()
    count = 0
    with checked_source(path, expected_size) as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            count += len(chunk)
    if count != expected_size:
        raise PackageError(f"short source read: {path!r}")
    return digest.hexdigest()


class HashedReader:
    def __init__(self, source: BinaryIO):
        self.source = source
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self.source.read(size)
        self.digest.update(chunk)
        self.count += len(chunk)
        return chunk


class RegionReader:
    def __init__(self, source: HashedReader, size: int):
        self.source = source
        self.remaining = size
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        count = min(self.remaining, CHUNK_SIZE if size < 0 else size)
        chunk = self.source.read(count)
        self.remaining -= len(chunk)
        self.digest.update(chunk)
        return chunk


def read_exact(source, size: int, label: str) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = source.read(size - len(result))
        if not chunk:
            raise PackageError(f"unexpected EOF in {label}")
        result.extend(chunk)
    return bytes(result)


def read_zero_padding(source, size: int, label: str) -> None:
    while size:
        chunk = read_exact(source, min(size, CHUNK_SIZE), label)
        if any(chunk):
            raise PackageError(f"{label} is not zero-filled")
        size -= len(chunk)


def _tar_number(field: bytes, label: str) -> int:
    if field[0] & 0x80:
        number = int.from_bytes(bytes([field[0] & 0x7F]) + field[1:], "big")
    else:
        digits = field.split(b"\0", 1)[0].strip()
        if any(char not in b"01234567" for char in digits):
            raise PackageError(f"invalid octal tar {label}")
        number = int(digits, 8) if digits else 0
    if number > MAX_SIGNED_LONG:
        raise PackageError(f"tar {label} exceeds the app's signed 64-bit range")
    return number


def _tar_header(block: bytes) -> tuple[int, int]:
    checksum = _tar_number(block[148:156], "checksum")
    if checksum != sum(block[:148]) + 8 * ord(" ") + sum(block[156:]):
        raise PackageError("tar header checksum mismatch")
    if block[257:263] == b"ustar\0" and block[345:500].split(b"\0", 1)[0]:
        raise PackageError("USTAR prefixes are not read by this DroidVM TarReader; use GNU long names")
    return block[156], _tar_number(block[124:136], "size")


def _verify_tar(source, manifest: Manifest, expected_hashes: dict[str, str] | None) -> tuple[list[dict], int]:
    seen = set()
    files = []
    pending_name = None
    while True:
        block = read_exact(source, 512, "tar header")
        if not any(block):
            if pending_name is not None:
                raise PackageError("GNU long name has no following file")
            read_zero_padding(source, 512, "second tar end block")
            end_padding = 1024
            while chunk := source.read(CHUNK_SIZE):
                if any(chunk):
                    raise PackageError("non-zero content follows the tar end blocks")
                end_padding += len(chunk)
                if end_padding > 2 * 10240:
                    raise PackageError("tar end padding exceeds the emitted GNU record padding")
            if end_padding % 512:
                raise PackageError("tar end padding is not block-aligned")
            break
        kind, size = _tar_header(block)
        if kind == ord("L"):
            if pending_name is not None or not 0 < size <= MAX_MANIFEST_SIZE + 1:
                raise PackageError("invalid or oversized GNU long-name entry")
            payload = read_exact(source, size, "GNU long name")
            if not payload.endswith(b"\0"):
                raise PackageError("GNU long name must be NUL-terminated")
            pending_name = payload[:-1].decode("utf-8", errors="strict")
            validate_archive_path(pending_name, "GNU long name")
            read_zero_padding(source, (-size) % 512, "GNU long-name padding")
            continue
        if kind not in (0, ord("0")):
            raise PackageError("only regular files and GNU long names are supported in package tar")
        name = pending_name if pending_name is not None else block[:100].split(b"\0", 1)[0].decode("utf-8", errors="strict")
        pending_name = None
        validate_archive_path(name, "tar entry name")
        if name in seen:
            raise PackageError(f"duplicate tar entry: {name!r}")
        if not seen and name != "manifest.json":
            raise PackageError("first tar entry must be manifest.json")
        seen.add(name)
        entry = manifest.entries.get(name)
        if name != "manifest.json" and entry is None:
            raise PackageError(f"tar entry is absent from manifest: {name!r}")
        declared_size = len(manifest.raw) if name == "manifest.json" else entry.size
        if size != declared_size:
            raise PackageError(f"tar size differs from manifest: {name!r}, {size} != {declared_size}")
        digest = hashlib.sha256()
        inline_copy = bytearray() if name == "manifest.json" else None
        remaining = size
        while remaining:
            chunk = read_exact(source, min(remaining, CHUNK_SIZE), f"tar content {name!r}")
            digest.update(chunk)
            if inline_copy is not None:
                inline_copy.extend(chunk)
            remaining -= len(chunk)
        read_zero_padding(source, (-size) % 512, f"tar padding {name!r}")
        if inline_copy is not None:
            if bytes(inline_copy) != manifest.raw:
                raise PackageError("inline and tar manifest bytes differ")
            continue
        sha256 = digest.hexdigest()
        compared = []
        if "sha256" in entry.value:
            if sha256 != entry.value["sha256"].lower():
                raise PackageError(f"manifest SHA256 mismatch: {name!r}")
            compared.append("manifest.sha256")
        if expected_hashes is not None:
            if expected_hashes.get(name) != sha256:
                raise PackageError(f"written source SHA256 mismatch: {name!r}")
            compared.append("source_stream_during_pack")
        files.append({
            "archive_path": name,
            "section": entry.section,
            "name": entry.value["name"],
            "manifest_path": entry.value["path"],
            "bytes": size,
            "sha256": sha256,
            "sha256_verified_against": compared,
        })
    expected_names = {"manifest.json", *manifest.entries.keys()}
    if seen != expected_names:
        raise PackageError(f"missing tar entries: {sorted(expected_names - seen)!r}")
    return files, end_padding


def verify_package(
    package_path: os.PathLike | str,
    source_map_path: os.PathLike | str | None = None,
    *,
    expected_hashes: dict[str, str] | None = None,
) -> dict:
    with open(package_path, "rb") as source:
        source_stat = os.fstat(source.fileno())
        if not stat.S_ISREG(source_stat.st_mode):
            raise PackageError("package must be a regular file")
        raw = HashedReader(source)
        magic, version, app_code, manifest_size, compression_type, volume_count, data_size = HEADER.unpack(
            read_exact(raw, HEADER.size, "VMPKG header")
        )
        if magic != MAGIC or version not in (1, 2) or manifest_size == 0 or data_size < 0:
            raise PackageError("invalid or unsupported VMPKG header")
        if volume_count:
            raise PackageError("this verifier supports single-file packages, not split volumes")
        compression = next((name for name, value in COMPRESSION_TYPES.items() if value == compression_type), None)
        if compression is None:
            raise PackageError("this verifier supports header compression 0 (none) and 1 (gzip)")
        start = data_offset(manifest_size)
        expected_size = align_up(start + data_size)
        if source_stat.st_size != expected_size:
            raise PackageError(f"package length differs from header/alignment: {source_stat.st_size} != {expected_size}")
        read_zero_padding(raw, ALIGNMENT - HEADER.size, "header padding")
        manifest = validate_manifest(read_exact(raw, manifest_size, "inline manifest"))
        if (
            manifest.value["manifest_version"] != version
            or manifest.value["app_version_code"] != app_code
            or manifest.value["compression"] != compression
        ):
            raise PackageError("header/manifest version, app code or compression mismatch")
        read_zero_padding(raw, start - ALIGNMENT - manifest_size, "manifest padding")
        region = RegionReader(raw, data_size)
        if compression == "gzip":
            with gzip.GzipFile(fileobj=region, mode="rb") as decompressed:
                files, tar_end_padding = _verify_tar(decompressed, manifest, expected_hashes)
        else:
            files, tar_end_padding = _verify_tar(region, manifest, expected_hashes)
        if region.remaining:
            raise PackageError("header data_size was not fully consumed")
        read_zero_padding(raw, expected_size - start - data_size, "package trailing padding")
        if raw.read(1):
            raise PackageError("unexpected bytes after package")
        after = os.fstat(source.fileno())
        if (after.st_size, after.st_mtime_ns) != (source_stat.st_size, source_stat.st_mtime_ns):
            raise PackageError("package changed while being verified")
    if source_map_path is not None:
        source_map = load_source_map(source_map_path, manifest)
        for file in files:
            source_path = source_map[file["archive_path"]]
            if source_digest(source_path, file["bytes"]) != file["sha256"]:
                raise PackageError(f"source map SHA256 mismatch: {file['archive_path']!r}")
            file["source_path"] = source_path
            file["sha256_verified_against"].append("source_map")
    return {
        "ok": True,
        "operation": "verified",
        "package": str(package_path),
        "package_bytes": raw.count,
        "package_sha256": raw.digest.hexdigest(),
        "format_source_head": SOURCE_HEAD,
        "header": {
            "magic": "VMPKG\\0",
            "header_bytes": HEADER.size,
            "manifest_version": version,
            "app_version_code": app_code,
            "manifest_bytes": manifest_size,
            "compression": compression,
            "compression_type": compression_type,
            "volume_count": volume_count,
            "data_bytes": data_size,
            "manifest_offset": ALIGNMENT,
            "data_offset": start,
        },
        "manifest_sha256": hashlib.sha256(manifest.raw).hexdigest(),
        "inline_tar_manifest_byte_identical": True,
        "compressed_data_sha256": region.digest.hexdigest(),
        "file_count": len(files),
        "content_bytes": sum(file["bytes"] for file in files),
        "files": files,
        "tar_end_padding_bytes": tar_end_padding,
        "vm_name": manifest.value["vm"]["name"],
        "extra_options_preserved": manifest.value["vm"].get("extra_options", []),
        "import_path_behavior": "DroidVM remaps placed disks and uefi/kernel/initrd boot paths; extra_options paths are not rewritten.",
        "verification_scope": "Container bytes, alignment, GNU tar checksums/names/coverage, declared sizes and SHA256 comparisons. No OS boot or Android import performed.",
        "independent_expected_digests_for_all_files": all(file["sha256_verified_against"] for file in files),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="existing single-file .vmpkg")
    parser.add_argument("--sources", help="optional archive_path -> absolute source path JSON for independent SHA256 comparison")
    args = parser.parse_args()
    try:
        report = verify_package(args.package, args.sources)
    except (OSError, ValueError, EOFError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
