# droidvm-apple-builds-20261117

Pinned macOS, iPadOS and Windows 11 ARM64 image builds for DroidVM. OS-containing source artifacts are encrypted before upload.

The [Windows workflow](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/actions/workflows/windows.yml) deploys the official Microsoft Simplified Chinese ARM64 Professional image offline, injects the pinned DroidVM guest drivers, and checks a standalone 64 GiB QCOW2 disk before encryption.

The Windows profile uses 4 vCPUs, 6 GiB RAM, Gunyah, SimpleFB and private UEFI variables. Import the final local VMPKG through DroidVM, select that VM's packaged private variables in the native boot editor, and save the configuration. Driver test-signing is required by this port. Phone startup and first-boot driver behavior need device verification.
