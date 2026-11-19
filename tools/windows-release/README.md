# Windows release recovery tools

This directory is a self-contained snapshot for restoring the Windows 11 ARM64 release. Install the pinned `requirements.txt` in a Python environment, then use `restore_windows_release.py` as described in [the recovery guide](../../docs/Windows11-ARM64-成果与恢复.md).

The normal `--source-parts` mode verifies and decrypts the original five source parts. The small encrypted supplement supplies the original manifest, UEFI firmware, variables and delivery records. The unchanged container packer must produce the exact original package size and SHA-256 before recovery succeeds. The tool neither contacts nor modifies a phone.

`--prepared-source-stage` is a local verification mode: it references an already decrypted QCOW2 read only and copies its small metadata. It does not establish that the source-download path was exercised in that run.

The original receiver, unpacker, package preparation and container tools are copied together to preserve their import contracts. The historical `finalize_windows_stage.py` and `check_windows_safe_patch.py` sources retain their original local-project layout assumptions; they are archived here for provenance and are not required by the normal recovery entry point.

Encrypted source and support files are release assets. Private decryption keys and plaintext account credentials are never included in this directory.
