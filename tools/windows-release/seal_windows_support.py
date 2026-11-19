#!/usr/bin/env python3
"""Seal the small, exact Windows final-package supplement into a NEW folder.

The already released 8-GB QCOW2 is excluded. The original manifest, firmware,
private vars, source/package metadata, Windows verification files and Windows
usage guide are encrypted together. Requires Python 3.10+ and cryptography.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tarfile

from windows_support import ArtifactError, seal_support


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="original local result root (read only)")
    parser.add_argument("--key-file", type=Path, required=True, help="existing one-line artifact key; never logged")
    parser.add_argument("--output", type=Path, required=True, help="new absent directory; failed outputs are preserved")
    args = parser.parse_args()
    try:
        result = seal_support(args.root, args.key_file, args.output)
    except (ArtifactError, OSError, ValueError, tarfile.TarError) as error:
        message = str(error) if isinstance(error, (ArtifactError, OSError)) else "Support sealing validation failed"
        print(json.dumps({"ok": False, "error_type": type(error).__name__, "error": message}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
