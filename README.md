# droidvm-apple-builds-20261117

Pinned macOS, iPadOS and Windows 11 ARM64 image builds for DroidVM. OS-containing source artifacts are encrypted before upload.

The [Windows workflow](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/actions/workflows/windows.yml) deploys the official Microsoft Simplified Chinese ARM64 Professional image offline, injects the pinned DroidVM guest drivers, and checks a standalone 64 GiB QCOW2 disk before encryption.

The completed Windows package uses 4 vCPUs, 6 GiB RAM, Gunyah, SimpleFB and private UEFI variables on a Nubia Z70 Ultra / Snapdragon 8 Elite. On 2026-11-19 the owner reported completing initial setup after disconnecting the network and finding the system basically usable. This is owner feedback; independent audio, USB, GPU and full driver verification remain unavailable.

The [Windows release](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/releases/tag/windows11-26h2-arm64-run-6) stores the encrypted source disk and final-package support files. The [Chinese recovery and usage guide](docs/Windows11-ARM64-成果与恢复.md) explains how to reconstruct the exact verified VMPKG, import it and retain the required driver test-signing. Encryption keys and account credentials are kept private.
