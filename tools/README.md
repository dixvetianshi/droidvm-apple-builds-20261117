# DroidVM Apple build helpers

These helpers accompany the pinned macOS and iPadOS workflows.

- `build_ipados_ci.sh` runs the reviewed, pinned upstream iPadOS build on a disposable macOS runner.
- `stage_ipados_release.py` admits completed upstream images only after checking their recorded bytes and SHA-256 digests, and preserves the Data generation for future updates.
- `pack_vmpkg.py` and `verify_vmpkg.py` create and check the real DroidVM import container from supplied files. Container validation does not establish that an operating system boots.

Apple-containing outputs are encrypted before cloud upload. Build secrets are kept in Actions Secrets and are not committed to this repository.
