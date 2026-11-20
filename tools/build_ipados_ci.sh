#!/usr/bin/env bash
# Diagnostic branch only: build the owned arm64e tool with the already selected SDK.
set -Eeuo pipefail
mkdir -p output verification/ipados-diagnostics
python3 tools/build_lsd_memory_probe.py --output output/lsd-memory-probe 2>&1 | tee verification/ipados-diagnostics/lsd-memory-probe-build.txt
tar -czf - -C output lsd-memory-probe | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass env:ARTIFACT_KEY | \
  split -b 1900m -d -a 3 - output/ipados-27.0.1.tar.gz.enc.
shasum -a 256 output/ipados-27.0.1.tar.gz.enc.[0-9][0-9][0-9] > verification/ipados-diagnostics/lsd-memory-probe-parts.txt
