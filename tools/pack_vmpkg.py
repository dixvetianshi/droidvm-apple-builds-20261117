#!/usr/bin/env python3
"""Pack real input files into a DroidVM VMPKG container, then verify every byte.

Usage:
  python pack_vmpkg.py --manifest manifest.json --sources source-map.json \
      --output system.vmpkg [--compression gzip|none] [--gzip-level 6]

The source map is a JSON object mapping each manifest disk/boot archive_path to
an absolute local source path. The manifest must declare the selected compression
(gzip by default). Its original UTF-8 bytes, paths, metadata and extra fields are
copied unchanged to both manifest locations. Optional sha256 entry fields are
checked. Output creation is exclusive; a failed run removes its own partial
output. No files are extracted, no guest is started, and no OS is fabricated.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

from verify_vmpkg import (
    ALIGNMENT,
    CHUNK_SIZE,
    COMPRESSION_TYPES,
    HEADER,
    MAGIC,
    MAX_SIGNED_LONG,
    HashedReader,
    PackageError,
    align_up,
    checked_source,
    data_offset,
    load_manifest,
    load_source_map,
    verify_package,
)


def _write_zeros(output, count: int) -> None:
    zero = bytes(CHUNK_SIZE)
    while count:
        size = min(count, CHUNK_SIZE)
        output.write(zero[:size])
        count -= size


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mode = 0o644
    info.uid = info.gid = 0
    info.mtime = 0
    # GNU_FORMAT emits 'L' long-name records and positive base-256 sizes >= 8 GiB.
    return info


def _remove_owned_partial(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) == identity:
        path.unlink()


def pack_package(
    manifest_path: os.PathLike | str,
    source_map_path: os.PathLike | str,
    output_path: os.PathLike | str,
    *,
    compression: str = "gzip",
    gzip_level: int = 6,
) -> dict:
    manifest = load_manifest(manifest_path)
    sources = load_source_map(source_map_path, manifest)
    if compression not in COMPRESSION_TYPES:
        raise PackageError("compression must be gzip or none")
    if manifest.value["compression"] != compression:
        raise PackageError("manifest.compression must match --compression; the tool never rewrites the manifest")
    if type(gzip_level) is not int or not 0 <= gzip_level <= 9:
        raise PackageError("gzip level must be an integer in [0, 9]")
    output_path = Path(output_path)
    # Opening in x mode is the final no-overwrite check, including dangling links.
    identity = None
    written_hashes = {}
    try:
        with output_path.open("x+b") as output:
            created = os.fstat(output.fileno())
            identity = (created.st_dev, created.st_ino)
            output.write(bytes(HEADER.size))
            _write_zeros(output, ALIGNMENT - HEADER.size)
            output.write(manifest.raw)
            start = data_offset(len(manifest.raw))
            _write_zeros(output, start - output.tell())
            compressed = gzip.GzipFile(
                filename="", fileobj=output, mode="wb", compresslevel=gzip_level, mtime=0,
            ) if compression == "gzip" else output
            try:
                with tarfile.open(
                    fileobj=compressed, mode="w|", format=tarfile.GNU_FORMAT,
                    encoding="utf-8", errors="strict", bufsize=CHUNK_SIZE,
                    copybufsize=CHUNK_SIZE,
                ) as archive:
                    archive.addfile(_tar_info("manifest.json", len(manifest.raw)), io.BytesIO(manifest.raw))
                    for name, entry in manifest.entries.items():
                        with checked_source(sources[name], entry.size) as source:
                            measured = HashedReader(source)
                            archive.addfile(_tar_info(name, entry.size), measured)
                        if measured.count != entry.size:
                            raise PackageError(f"short source read while packing: {name!r}")
                        digest = measured.digest.hexdigest()
                        if "sha256" in entry.value and digest != entry.value["sha256"].lower():
                            raise PackageError(f"source SHA256 differs from manifest: {name!r}")
                        written_hashes[name] = digest
            finally:
                if compressed is not output:
                    compressed.close()
            end = output.tell()
            data_size = end - start
            if data_size > MAX_SIGNED_LONG:
                raise PackageError("compressed package data exceeds the app's signed 64-bit range")
            _write_zeros(output, align_up(end) - end)
            output.seek(0)
            output.write(HEADER.pack(
                MAGIC, manifest.value["manifest_version"], manifest.value["app_version_code"],
                len(manifest.raw), COMPRESSION_TYPES[compression], 0, data_size,
            ))
            output.flush()
        report = verify_package(output_path, expected_hashes=written_hashes)
        for file in report["files"]:
            file["source_path"] = sources[file["archive_path"]]
        report["operation"] = "packed_and_verified"
        report["manifest_source"] = str(manifest_path)
        report["source_map"] = str(source_map_path)
        report["gzip_level"] = gzip_level if compression == "gzip" else None
        report["source_manifest_bytes_preserved"] = True
        return report
    except BaseException:
        _remove_owned_partial(output_path, identity)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="native DroidVM manifest JSON with declared file sizes")
    parser.add_argument("--sources", required=True, help="archive_path -> absolute source path JSON")
    parser.add_argument("--output", required=True, help="new .vmpkg path; its parent directory must exist")
    parser.add_argument("--compression", choices=tuple(COMPRESSION_TYPES), default="gzip")
    parser.add_argument("--gzip-level", type=int, choices=range(10), default=6)
    args = parser.parse_args()
    try:
        report = pack_package(
            args.manifest, args.sources, args.output,
            compression=args.compression, gzip_level=args.gzip_level,
        )
    except (OSError, ValueError, EOFError, tarfile.TarError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
