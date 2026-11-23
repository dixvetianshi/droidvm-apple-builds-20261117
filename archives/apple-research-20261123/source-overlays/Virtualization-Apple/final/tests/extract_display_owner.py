"""Extract the real display owner for the bounded platform-double harness.

The generated include is an exact slice of production source, not a rewritten
state machine. Android window/Vulkan doubles live only in the test driver.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    relative = "libs/android_display_backend/crosvm_android_display_client.cpp"
    if args.baseline:
        original = subprocess.check_output(
            ["git", "-C", str(args.root), "show", "HEAD:" + relative]
        )
    else:
        original = (args.root / relative).read_bytes()
    source = original.decode("utf-8")
    start = source.index("class SinkANativeWindow_Buffer {")
    stop = source.index("class DisplayService :", start)
    owner = source[start:stop]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "display_owner_under_test.inc").write_bytes(owner.encode("utf-8"))
    (args.output / "source-provenance.json").write_text(
        json.dumps(
            {
                "source": relative,
                "baseline": args.baseline,
                "source_sha256": hashlib.sha256(original).hexdigest(),
                "slice_sha256": hashlib.sha256(owner.encode()).hexdigest(),
                "start_line": source.count("\n", 0, start) + 1,
                "end_line": source.count("\n", 0, stop),
                "scope": "Real SinkANativeWindow_Buffer/copyBuffer/AndroidDisplaySurface; window, binder Surface and Vulkan bridge are doubles",
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
