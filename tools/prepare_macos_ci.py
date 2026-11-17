#!/usr/bin/env python3
"""Prepare a pinned upstream macOS workflow for the user's own build repository.

This only writes a local workflow. It neither uploads files nor starts a build.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "sources/macOS-DroidVM"
PIN = "524d27bf57ae92375aa39e3a81e11727c08973ff"


def main():
    actual = subprocess.check_output(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != PIN:
        raise SystemExit(f"Source checkout differs from the reviewed pin: {actual}")
    source_file = SOURCE / ".github/workflows/image.yml"
    original = source_file.read_text(encoding="utf-8")
    pattern = re.compile(
        r"(?m)^([ ]*)- uses: actions/checkout@v4\n([ ]*)with:\n([ ]*)path: ws$"
    )

    def checkout(match):
        step, field, value = match.groups()
        return (
            f"{step}- uses: actions/checkout@v4\n{field}with:\n"
            f"{value}repository: Droid-VM/macOS-DroidVM\n"
            f"{value}ref: {PIN}\n"
            f"{value}persist-credentials: false\n"
            f"{value}path: ws"
        )

    workflow, count = pattern.subn(checkout, original)
    if count != 7:
        raise SystemExit(f"Expected seven independent source checkouts, found {count}")
    token = "  GH_TOKEN: ${{ github.token }}\n"
    if workflow.count(token) != 1:
        raise SystemExit("The reviewed global GitHub token environment changed")
    workflow = workflow.replace(
        token, token + "  GH_REPO: ${{ github.repository }}\n", 1
    )
    workflow = workflow.replace("name: image\n", "name: macOS 27.2 image\n", 1)
    workflow = workflow.replace(
        "  group: image-${{ github.ref }}\n",
        "  group: macos-image-${{ github.ref }}\n  cancel-in-progress: false\n",
        1,
    )
    workflow = (
        "# Generated from the pinned upstream image workflow.\n"
        "# Source: https://github.com/Droid-VM/macOS-DroidVM\n"
        f"# Commit: {PIN}\n"
        "# GH_REPO keeps every release operation inside the calling build repository.\n"
        + workflow
    )
    destination = ROOT / ".github/workflows/macos.yml"
    destination.write_text(workflow, encoding="utf-8", newline="\n")
    report = {
        "source_repository": "https://github.com/Droid-VM/macOS-DroidVM",
        "source_commit": PIN,
        "source_workflow_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "generated_workflow_sha256": hashlib.sha256(workflow.encode()).hexdigest(),
        "source_checkouts_pinned": count,
        "release_destination": "${{ github.repository }}",
        "apple_payload_uploads": "AES-encrypted, following upstream ci-blob.sh",
        "executed_cloud_build": False,
        "executed_phone_boot": False,
    }
    (ROOT / "verification/macos-workflow-preparation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
