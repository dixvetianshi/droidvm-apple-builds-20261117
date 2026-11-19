# Windows 11 ARM64：成果与恢复

2026-11-19，用户反馈：第一次开机的“正在检查更新”停住，断网后完成设置并进入系统，基本可用。这个反馈不替代独立的驱动、性能和长期稳定性测试。

本次为微软官方简体中文 Windows 11 Professional ARM64，26H2，版本 **10.0.26300.9457**，WIM 索引 3。目标手机为努比亚 Z70 Ultra / NX736J、Snapdragon 8 Elite / SM8750、16GB 内存、Android 16；DroidVM **0.0.6.r242.g3348830**，版本码 2720。

## 配置和状态

- 4 个 vCPU、6144MiB 内存，独立 64GiB QCOW2 系统盘。
- crosvm / Gunyah，`protected_without_firmware`，`swiotlb_mb:256`、大页与 `prepare_lend_mthp:chunked`。
- 原生 SimpleFB 1280×720，GPU 关闭；固件与 UEFI vars 使用独立文件。
- 用户已反馈首启可用；音频、USB、GPU 加速、所有驱动功能和关机再启动的完整回归尚未独立验证。

右下角“测试模式”来自 Windows BCD 的 `testsigning on`。这条移植路线需要加载 DroidVM 的自签名 Gunyah / virtio 驱动。保留这个设置，关闭它可能影响启动、磁盘或输入。构建没有启用 `nointegritychecks`，没有打开 RDP、SSH 或自动登录。

## GitHub 保存了什么

[本次 Release](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/releases/tag/windows11-26h2-arm64-run-6)保存两组互补文件：

1. `Windows11-26H2-ARM64.source.tar.gz.enc.000` 至 `.004`、`SHA256SUMS` 和 `encryption-record.json`：已完成云构建的系统盘、账户凭据和原始记录。
2. `Windows11-26H2-ARM64.final-support.tar.gz.enc`、`support-SHA256SUMS` 和 `support-encryption-record.json`：最终包的原始 manifest、独立 UEFI 固件、vars 和本地交付记录。

恢复工具同时提供在 `Windows11-ARM64-restore-tools-20261119.zip` 和仓库的 `tools/windows-release/` 中。补充文件复用已有的加密系统盘；恢复时保留原 manifest 字节，不重新生成创建时间。

系统盘内的无人值守账户配置可能包含初始凭据，所以系统文件继续加密保存。**解密密钥不上传到公开 GitHub。** 本机共用密钥位于 `secrets/ARTIFACT_KEY.txt`；它也供苹果成果恢复使用，清理时保留。不要把密钥、解密后的账户文件或系统盘公开发布。

## 一次恢复原始导入包

在电脑上安装 Python 与 `cryptography`，下载恢复工具 ZIP 并解压；也可使用本机仍保留的 Python 环境。把第一组文件下载到 `windows-source/`，第二组文件下载到 `windows-support/`，私下准备原密钥文件。输出目录必须尚不存在。

```powershell
python tools/windows-release/restore_windows_release.py --source-parts windows-source --support-dir windows-support --key-file ARTIFACT_KEY.txt --output RestoredWindows
```

从工具 ZIP 运行时，使用解压后的 `restore_windows_release.py` 的实际路径。恢复工具检查分片、解密与归档内容，创建原始 `.vmpkg`，再校验整个成品的固定摘要。解密后的账户文件仅保存在恢复目录内，工具不会打印用户名、密码或密钥。

成品 **Windows11-26H2-ARM64-DroidVM-NX736J.vmpkg**：

- 大小：**8,561,582,080 字节**。
- SHA-256：`b370096917d231d1e9da793f91042cf93ee49f129981b4fd0a5e9b2aac00783a`。

恢复会生成约 8.56GB 的系统盘与约 8.56GB 的导入包；还需为下载分片和使用过程预留空间。64GiB 是来宾虚拟磁盘容量，系统盘文件会随使用增长。

## 在 DroidVM 导入与选择 vars

导入恢复出来的 `.vmpkg`。原生导入默认父目录为 `/storage/emulated/0/DroidVM`，也可以另选父目录，以此次真正的导入目录为准。

1. 保持 Windows VM 停机，进入 **编辑 → 启动 → UEFI**。
2. 打开 **启用 UEFI 变量(pflash)**。
3. 在 **UEFI 变量(留空 = 内置 EDK2 变量)** 旁浏览，选择 **选择外部文件**。
4. 选中此次 Windows 导入目录内、与 `Windows11.qcow2` 同层的 **edk2-windows.vars.fd**。
5. 点击右下角勾号保存，再打开编辑页核对开关和实际路径。

固件为该目录 `boot/edk2-windows.fd`。网络通过原生编辑界面选择手机实际存在的网络并保存。首启“正在检查更新”遇到同样停滞时，可采用用户已成功的断网设置路径，进入系统后再恢复网络。

Debian 与苹果系统继续使用各自的磁盘和 vars。共享 crosvm、运行库与 Gunyah 资源需要协调使用，避免两个 VM 同时写同一磁盘。此归档和本地 Windows 清理不修改手机上已经导入的 VM。

## 构建与验收依据

- [实际成功的 Windows 云构建](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/actions/runs/44351863741)，源码 `334ce911c3fc06d668f04c4bca716e6d4943999a`。
- 上游 Windows builder：`Droid-VM/win11-arm64-image-builder`，固定 `cb6469058514401f16dd4b3142fde027f5b3c94a`。
- 官方 ISO：`Windows11_Client_arm64_zh-cn_26300_9457.iso`，SHA-256 `cd573df724862300895d0f5d0836e663756d22cc4e964c752efdc05b4fc09e8b`。
- 云构建、驱动离线注入、QCOW2、加密传输和原始成品均已有验收记录。原始记录中的 `phone_boot_verified:false` 保留其当时的验证范围；本页追加后来的用户反馈。

Windows 许可证和激活按实际账户及设备处理。这里保存构建成果与恢复材料，不包含激活密钥。
