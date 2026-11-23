#!/usr/bin/env python3
"""Receive an explicitly selected Actions artifact from local inputs only.

No downloads, target execution, or packaging occur here. The saved public API
responses own the ZIP digest and size; the producer SHA256SUMS owns all extracted
regular members. Failed new outputs and their incomplete records are preserved.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile
import zlib

from runtime_artifact import HOST_POLICY_REVIEWS, load_completed_runtime
from verify_vmpkg import parse_json, validate_archive_path


REPOSITORY = "dixvetianshi/droidvm-apple-builds-20261117"
RUN_ID = 44575863520
HEAD_SHA = "8ac62de20784b3abf2d9d2e13cc928314d5e5e58"
ARTIFACT_NAME = "droidvm-crosvm-apple-2"
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}"
RUN_API_URL = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{RUN_ID}"

# The prior completed build record contains 170 files, about 81 MB in total,
# with a largest member of about 18 MB. These generous reception budgets bound
# disk expansion and streaming work; they do not define a ZIP format limit.
MAX_ENTRIES = 1000  # strictly fewer than this, including directory entries
MAX_MEMBER_BYTES = 256 * 1024 * 1024  # strictly below this
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # strictly below this
MAX_JSON_BYTES = 4 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
ROOT_FILES = frozenset({
    "SHA256SUMS", "crosvm-build.json", "source-lock.json", "source-manifest.xml",
    "static-options.json", "native-display-patch.json", "host-policy-source.json",
})
APPLE10_ROOT_FILES = frozenset({"native-display-source.json", "native-lifecycle-source.json", "soong-unwind-source.json"})
DIRECTORIES = frozenset({
    "full-build", "runtime", "runtime/usr", "runtime/usr/bin", "runtime/usr/lib",
    "shim", "diagnostics",
})
WINDOWS_DEVICE = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


class ArtifactError(ValueError):
    """An input or completed-artifact boundary that cannot be admitted."""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def absolute_path(value, label):
    path = Path(value)
    if not path.is_absolute():
        raise ArtifactError(f"{label} must be an absolute local path")
    return path


def regular_file(path, label):
    if path.is_symlink() or not path.is_file():
        raise ArtifactError(f"{label} must be a regular local file")


def read_metadata(path, label):
    regular_file(path, label)
    size = path.stat().st_size
    if not 0 < size <= MAX_JSON_BYTES:
        raise ArtifactError(f"{label} exceeds the 4-MiB metadata read budget or is empty")
    raw = path.read_bytes()
    try:
        value = parse_json(raw, label)
    except ValueError as error:
        raise ArtifactError(f"{label} must contain strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ArtifactError(f"{label} must contain a JSON object")
    return value, {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def source_selection(repository, run_id, head_sha, artifact_name):
    if not isinstance(repository, str) \
            or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ArtifactError("--repository must identify one GitHub owner/repository")
    if type(run_id) is not int or run_id <= 0:
        raise ArtifactError("--run-id must be positive")
    if not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise ArtifactError("--head-sha must be the complete 40-character lowercase commit SHA")
    if not isinstance(artifact_name, str) or not artifact_name \
            or re.search(r"[\x00-\x1f\x7f]", artifact_name):
        raise ArtifactError("--artifact-name must be a nonempty artifact identity without control characters")
    return {"repository": repository, "run_id": run_id, "head_sha": head_sha,
            "artifact_name": artifact_name}


def source_metadata(artifact_input, run, *, repository=REPOSITORY, run_id=RUN_ID,
                    head_sha=HEAD_SHA, artifact_name=ARTIFACT_NAME):
    """Bind supplied API facts once, retaining the original inputs separately."""
    source_selection(repository, run_id, head_sha, artifact_name)
    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    run_api_url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    if type(run.get("id")) is not int or run["id"] != run_id \
            or run.get("head_sha") != head_sha \
            or not isinstance(run.get("repository"), dict) \
            or run["repository"].get("full_name") != repository \
            or run.get("html_url") != run_url or run.get("url") != run_api_url:
        raise ArtifactError("run-json does not identify the reviewed repository, run and head SHA")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ArtifactError("The reviewed workflow run must be completed successfully")
    if "artifacts" in artifact_input:
        values = artifact_input["artifacts"]
        if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
            raise ArtifactError("artifact-json has an invalid API artifacts list")
        matches = [(index, value) for index, value in enumerate(values)
                   if value.get("name") == artifact_name]
        if len(matches) != 1:
            raise ArtifactError("artifact-json must contain exactly one artifact with the reviewed name")
        index, artifact = matches[0]
        selection = {"container": "artifacts", "index": index}
    else:
        artifact = artifact_input
        selection = {"container": "artifact object"}
    artifact_id = artifact.get("id")
    workflow = artifact.get("workflow_run")
    if type(artifact_id) is not int or artifact_id <= 0 \
            or artifact.get("name") != artifact_name \
            or not isinstance(workflow, dict) \
            or type(workflow.get("id")) is not int or workflow["id"] != run_id \
            or workflow.get("head_sha") != head_sha:
        raise ArtifactError("The artifact must belong to the reviewed workflow run and head SHA")
    api_url = f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
    if artifact.get("url") != api_url or artifact.get("archive_download_url") != api_url + "/zip":
        raise ArtifactError("The artifact API URLs must identify the reviewed repository and artifact")
    if artifact.get("expired") is not False:
        raise ArtifactError("The artifact API metadata must report expired=false")
    expires_at = artifact.get("expires_at")
    if expires_at is not None:
        try:
            expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiration.tzinfo is None or expiration <= datetime.now(timezone.utc):
                raise ValueError("expired or unspecified timezone")
        except (AttributeError, TypeError, ValueError) as error:
            raise ArtifactError("The artifact expiration timestamp is invalid or has passed") from error
    size = artifact.get("size_in_bytes")
    if type(size) is not int or not 0 < size < MAX_TOTAL_BYTES:
        raise ArtifactError("Artifact size_in_bytes must be positive and below the 1-GiB reception budget")
    digest = artifact.get("digest")
    match = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", digest) if isinstance(digest, str) else None
    if match is None:
        raise ArtifactError("The actual artifact API digest must contain a SHA-256")
    source = {
        "source_kind": "github_actions_artifact", "status": "incomplete",
        "repository": run["repository"]["full_name"], "workflow_run_id": run["id"],
        "workflow_run_url": run["html_url"], "workflow_run_api_url": run["url"],
        "head_sha": run["head_sha"], "workflow_run_status": run["status"],
        "workflow_run_conclusion": run["conclusion"], "artifact_id": artifact_id,
        "name": artifact["name"], "original_api_url": artifact["archive_download_url"],
        "artifact_metadata_api_url": artifact["url"], "digest": digest,
        "api_asset_digest": digest, "expected_size": size,
        "expected_sha256": match[1].lower(), "expired": artifact["expired"],
        "size_verified": False, "sha256_verified": False,
        "artifact_metadata_selection": {**selection, "artifact_id": artifact_id},
    }
    for field in ("created_at", "updated_at", "expires_at", "node_id"):
        if field in artifact:
            source[field] = artifact[field]
    return source


def verify_zip_source(stream, source):
    sha = hashlib.sha256()
    observed = 0
    for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
        observed += len(chunk)
        if observed >= MAX_TOTAL_BYTES:
            raise ArtifactError("The ZIP exceeds the 1-GiB reception budget")
        sha.update(chunk)
    source.update(observed_size=observed, observed_sha256=sha.hexdigest())
    source["size_verified"] = observed == source["expected_size"]
    source["sha256_verified"] = sha.hexdigest() == source["expected_sha256"]
    if not source["size_verified"]:
        raise ArtifactError("Downloaded ZIP size differs from the actual artifact API size")
    if not source["sha256_verified"]:
        raise ArtifactError("Downloaded ZIP SHA-256 differs from the actual artifact API digest")
    source.update(status="complete", completed_at_utc=utc_now())
    stream.seek(0)


def member_path(value, label):
    try:
        name = validate_archive_path(value, label)
    except ValueError as error:
        raise ArtifactError(f"{label} is not a canonical relative path") from error
    # NTFS aliases and alternate streams would otherwise escape unique-file
    # ownership even when the relative POSIX path itself is canonical.
    for component in name.split("/"):
        if any(character in '<>:"|?*' for character in component) \
                or component.endswith((".", " ")) or WINDOWS_DEVICE.match(component):
            raise ArtifactError(f"{label} cannot be represented as a unique Windows file path")
    return name


def allowed_member(name, directory, *, host_policy_review=None):
    if directory:
        return name in DIRECTORIES or name.startswith("diagnostics/")
    parts = name.split("/")
    return name in ROOT_FILES or host_policy_review == "apple10" and name in APPLE10_ROOT_FILES \
        or len(parts) == 2 and parts[0] == "full-build" and (parts[1] == "crosvm" or parts[1].endswith(".so")) \
        or name == "runtime/usr/bin/crosvm" \
        or len(parts) == 4 and parts[:3] == ["runtime", "usr", "lib"] and parts[3].endswith(".so") \
        or name in ("shim/shim.bin", "shim/shim.elf") \
        or name.startswith("diagnostics/")


def zip_plan(archive, *, host_policy_review=None):
    values = archive.infolist()
    if not 0 < len(values) < MAX_ENTRIES:
        raise ArtifactError("The ZIP must contain fewer than 1000 entries and cannot be empty")
    plan = []
    identities = {}
    total = 0
    for number, info in enumerate(values, 1):
        label = f"ZIP member {number}"
        if info.orig_filename != info.filename:
            raise ArtifactError(f"{label} contains a truncated or altered filename")
        directory = info.is_dir()
        name = member_path(info.filename[:-1] if directory else info.filename, label)
        if not allowed_member(name, directory, host_policy_review=host_policy_review):
            raise ArtifactError(f"{label} is outside the crosvm build output paths")
        key = name.casefold()
        if key in identities:
            raise ArtifactError(f"{label} duplicates or aliases an earlier ZIP path")
        identities[key] = directory
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFDIR if directory else stat.S_IFREG) \
                or not directory and info.external_attr & 0x10:
            raise ArtifactError(f"{label} is not a regular file or normal directory")
        if info.flag_bits & 1:
            raise ArtifactError(f"{label} is encrypted")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ArtifactError(f"{label} uses a compression method outside the Actions ZIP producer")
        if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
            raise ArtifactError(f"{label} has inconsistent stored and expanded byte counts")
        if not 0 <= info.file_size < MAX_MEMBER_BYTES:
            raise ArtifactError(f"{label} exceeds the 256-MiB member expansion budget")
        if directory and info.file_size != 0:
            raise ArtifactError(f"{label} is a directory with data")
        total += info.file_size
        if total >= MAX_TOTAL_BYTES:
            raise ArtifactError("The ZIP exceeds the 1-GiB total expansion budget")
        plan.append((number, info, name, directory))
    for _, _, name, _ in plan:
        parts = name.casefold().split("/")
        for end in range(1, len(parts)):
            if identities.get("/".join(parts[:end])) is False:
                raise ArtifactError("The ZIP uses a regular file as another member's parent")
    return plan


def member_chunks(archive, archive_stream, info, number):
    """Validate all inflated bytes, rather than ZipExtFile's clipped projection.

    ZipFile owns central-directory and local-name/overlap checks. A local fixed
    header supplies the compressed range; the raw Actions STORED/DEFLATED stream
    must finish exactly, including its inflater EOF and lack of trailing data.
    """
    with archive.open(info):
        pass  # validates the local name/header and member overlap before writes
    archive_stream.seek(info.header_offset)
    header = archive_stream.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ArtifactError(f"ZIP member {number} has an incomplete local header")
    flags, method = struct.unpack_from("<HH", header, 6)
    if flags != info.flag_bits or method != info.compress_type:
        raise ArtifactError(f"ZIP member {number} local and directory encoding facts differ")
    name_size, extra_size = struct.unpack_from("<HH", header, 26)
    archive_stream.seek(info.header_offset + 30 + name_size + extra_size)
    remaining = info.compress_size
    inflater = zlib.decompressobj(-15) if method == zipfile.ZIP_DEFLATED else None
    while remaining:
        requested = min(CHUNK_BYTES, remaining)
        compressed = archive_stream.read(requested)
        if len(compressed) != requested:
            raise ArtifactError(f"ZIP member {number} has truncated compressed data")
        remaining -= requested
        if inflater is None:
            yield compressed
            continue
        pending = compressed
        while True:
            try:
                expanded = inflater.decompress(pending, CHUNK_BYTES)
            except zlib.error as error:
                raise ArtifactError(f"ZIP member {number} has invalid DEFLATE data") from error
            pending = inflater.unconsumed_tail
            if inflater.unused_data or inflater.eof and (remaining or pending):
                raise ArtifactError(f"ZIP member {number} has trailing compressed data")
            if expanded:
                yield expanded
            if pending or len(expanded) == CHUNK_BYTES:
                continue  # also drains bounded buffered output with pending=b''
            break
    if inflater is not None and not inflater.eof:
        raise ArtifactError(f"ZIP member {number} did not reach DEFLATE EOF")


def extract_zip(archive, archive_stream, output, record, *, host_policy_review=None):
    plan = zip_plan(archive, host_policy_review=host_policy_review)
    record["planned_entry_count"] = len(plan)
    record["planned_regular_file_bytes"] = sum(info.file_size for _, info, _, directory in plan if not directory)
    for number, info, name, directory in plan:
        target = output.joinpath(*name.split("/"))
        if directory:
            row = {"archive_name": info.orig_filename, "path": name, "status": "incomplete"}
            record["directories"].append(row)
            try:
                for chunk in member_chunks(archive, archive_stream, info, number):
                    if chunk:
                        raise ArtifactError(f"ZIP directory {number} unexpectedly contains data")
                if info.CRC != 0:
                    raise ArtifactError(f"ZIP directory {number} failed its empty-data CRC check")
                target.mkdir(parents=True, exist_ok=True)
            except (zipfile.BadZipFile, RuntimeError, EOFError) as error:
                raise ArtifactError(f"ZIP directory {number} failed its integrity check") from error
            row.update(status="complete", zip_crc_verified=True)
            continue
        row = {
            "archive_name": info.orig_filename, "path": name, "status": "incomplete",
            "expected_bytes": info.file_size, "archive_crc32": f"{info.CRC:08x}",
            "archive_mode": (info.external_attr >> 16) & 0o777,
        }
        record["files"].append(row)
        sha = hashlib.sha256()
        crc = 0
        observed = 0
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as destination:
                for chunk in member_chunks(archive, archive_stream, info, number):
                    if observed + len(chunk) > info.file_size:
                        raise ArtifactError(f"ZIP member {number} expanded beyond its declared size")
                    destination.write(chunk)
                    observed += len(chunk)
                    sha.update(chunk)
                    crc = zlib.crc32(chunk, crc)
        except (zipfile.BadZipFile, RuntimeError, EOFError) as error:
            raise ArtifactError(f"ZIP member {number} failed its CRC or header check") from error
        finally:
            row.update(bytes=observed, sha256=sha.hexdigest(), sha256_scope="extracted bytes")
        if observed != info.file_size:
            raise ArtifactError(f"ZIP member {number} did not reach its declared size")
        if crc != info.CRC:
            raise ArtifactError(f"ZIP member {number} failed its CRC check")
        row.update(status="complete", zip_crc_verified=True, sha256_scope="complete regular file bytes")
    record["zip_member_crc_and_sizes_verified"] = True


def verify_original_checksums(output, record):
    rows = {row["path"]: row for row in record["files"]}
    checksum = rows.get("SHA256SUMS")
    if checksum is None or checksum["bytes"] > MAX_JSON_BYTES:
        raise ArtifactError("The original SHA256SUMS is missing or exceeds the 4-MiB checksum read budget")
    try:
        raw = (output / "SHA256SUMS").read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ArtifactError("The original SHA256SUMS is not UTF-8") from error
    if not text.endswith("\n"):
        raise ArtifactError("The original SHA256SUMS must end with its producer newline")
    expected = {}
    for number, line in enumerate(text.split("\n")[:-1], 1):
        match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", line)
        if match is None:
            raise ArtifactError(f"Original SHA256SUMS line {number} is not an anchored SHA-256 record")
        name = member_path(match[2], f"SHA256SUMS line {number} path")
        if name == "SHA256SUMS" or name in expected:
            raise ArtifactError("The original SHA256SUMS repeats a path or lists itself")
        expected[name] = match[1].lower()
    if set(expected) != set(rows) - {"SHA256SUMS"}:
        raise ArtifactError("The original SHA256SUMS must cover every regular ZIP member except itself")
    for name, digest in expected.items():
        row = rows[name]
        row["expected_sha256"] = digest
        if row["sha256"] != digest:
            raise ArtifactError(f"Producer SHA256SUMS differs for extracted member: {name}")
        row["original_SHA256SUMS_verified"] = True
    checksum.update(expected_sha256=None,
                    sha256_source="self-computed original checksum file; producer omits its own file")
    record.update(original_SHA256SUMS_verified=True,
                  original_checksum_file=str(output / "SHA256SUMS"),
                  checked_original_record_files=len(expected),
                  checksum_verification_method="anchored producer SHA-256 rows cover all regular ZIP members except SHA256SUMS; compared to streamed extracted bytes")


def write_record(output, record):
    (output / "extraction-record.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def receive(archive_path, artifact_json, run_json, output_path, *, repository=REPOSITORY,
            run_id=RUN_ID, head_sha=HEAD_SHA, artifact_name=ARTIFACT_NAME,
            require_host_policy=False, host_policy_review=None):
    selected = source_selection(repository, run_id, head_sha, artifact_name)
    inputs = {"archive": str(archive_path), "artifact_json": str(artifact_json),
              "run_json": str(run_json), "output": str(output_path)}
    archive_path = absolute_path(archive_path, "--archive")
    artifact_json = absolute_path(artifact_json, "--artifact-json")
    run_json = absolute_path(run_json, "--run-json")
    output = absolute_path(output_path, "--output")
    if output.exists() or output.is_symlink():
        raise ArtifactError("--output must be new; existing files and directories are preserved")
    if not output.parent.is_dir():
        raise ArtifactError("--output requires an existing parent directory")
    output.mkdir()  # exclusive creation; nothing is removed on success or failure
    record = {
        "schema_version": 1, "status": "incomplete", "inputs": inputs,
        "requested_source_selection": selected,
        "source": {"source_kind": "github_actions_artifact", "status": "incomplete"},
        "files": [], "directories": [], "started_at_utc": utc_now(),
        "original_SHA256SUMS_verified": False, "original_download_preserved": True,
        "target_binary_executed": False, "android_loader_verified": False,
        "phone_boot_verified": False,
        "resource_budgets": {"entry_count_exclusive": MAX_ENTRIES,
                             "member_bytes_exclusive": MAX_MEMBER_BYTES,
                             "total_expanded_bytes_exclusive": MAX_TOTAL_BYTES,
                             "archive_bytes_exclusive": MAX_TOTAL_BYTES},
    }
    stage = "API metadata validation"
    consumer_completed = False
    try:
        write_record(output, record)
        artifact_value, artifact_input = read_metadata(artifact_json, "artifact-json")
        run_value, run_input = read_metadata(run_json, "run-json")
        record["metadata_inputs"] = {"artifact": artifact_input, "workflow_run": run_input}
        record["source"] = source_metadata(artifact_value, run_value, **selected)
        record["source"].update(local_path=str(archive_path), local_archive_path=str(archive_path),
                                 artifact_metadata_path=str(artifact_json), workflow_run_metadata_path=str(run_json))
        stage = "ZIP API size/SHA verification"
        write_record(output, record)
        regular_file(archive_path, "--archive")
        with archive_path.open("rb") as stream:
            verify_zip_source(stream, record["source"])
            record["archive_api_sha256_verified"] = True
            stage = "ZIP member extraction"
            write_record(output, record)
            with zipfile.ZipFile(stream) as archive:
                extract_zip(archive, stream, output, record, host_policy_review=host_policy_review)
        stage = "original producer checksum verification"
        write_record(output, record)
        verify_original_checksums(output, record)
        stage = "completed runtime owner validation"
        write_record(output, record)
        candidate = {**record, "status": "complete"}
        runtime = load_completed_runtime(output, require_display_patch=True,
                                         require_host_policy=require_host_policy,
                                         host_policy_review=host_policy_review, extraction_record=candidate)
        record["runtime_consumer_validation"] = {
            "status": "complete", "owner": "tools/runtime_artifact.py:load_completed_runtime",
            "require_display_patch": True,
            "require_host_policy": require_host_policy or host_policy_review is not None,
            "host_policy_review": runtime.host_policy_review,
            "host_policy_source": runtime.host_policy_source,
            "selected_runtime_member_count": len(runtime.members),
            "excluded_runtime_members": runtime.excluded,
        }
        if runtime.host_policy_review == "apple10":
            record["runtime_consumer_validation"]["source_lineage"] = runtime.source_lineage
        record["completed_at_utc"] = utc_now()
        record["status"] = "complete"
        consumer_completed = True
    except BaseException as error:
        record["status"] = "incomplete"
        message = "Artifact reception interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) \
            else str(error) if isinstance(error, ArtifactError) \
            or stage == "completed runtime owner validation" and isinstance(error, ValueError) \
            else f"{stage} failed ({type(error).__name__})"
        record["failure"] = {"stage": stage, "kind": type(error).__name__, "message": message}
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise ArtifactError(message) from error
    finally:
        if not consumer_completed:
            record["status"] = "incomplete"
        write_record(output, record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, help="Absolute path to the downloaded Actions ZIP; preserved")
    parser.add_argument("--artifact-json", required=True, help="Absolute saved public artifact API object or artifacts-list JSON")
    parser.add_argument("--run-json", required=True, help="Absolute saved public Actions run API JSON")
    parser.add_argument("--output", required=True, help="Absolute new output directory; never overwrite an existing path")
    parser.add_argument("--repository", default=REPOSITORY, help="Selected public GitHub owner/repository")
    parser.add_argument("--run-id", type=int, default=RUN_ID, help="Selected Actions workflow run ID")
    parser.add_argument("--head-sha", default=HEAD_SHA, help="Selected full commit SHA; must match both API owners")
    parser.add_argument("--artifact-name", default=ARTIFACT_NAME, help="Selected exact artifact name")
    parser.add_argument("--require-native-host-policy", action="store_true", dest="require_host_policy",
                        help="Require complete native host policy provenance (legacy default review: apple7)")
    parser.add_argument("--host-policy-review", choices=tuple(HOST_POLICY_REVIEWS),
                        help="Require this explicitly selected reviewed native manifest and patch")
    args = parser.parse_args(argv)
    try:
        record = receive(args.archive, args.artifact_json, args.run_json, args.output,
                         repository=args.repository, run_id=args.run_id, head_sha=args.head_sha,
                         artifact_name=args.artifact_name, require_host_policy=args.require_host_policy,
                         host_policy_review=args.host_policy_review)
    except (ArtifactError, OSError) as error:
        print(f"Artifact reception failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified Actions artifact received: {len(record['files'])} regular files. Android loading and phone boot remain unverified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
