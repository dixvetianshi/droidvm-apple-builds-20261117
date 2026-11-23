# DroidVM Apple 研究归档（2026-11-23）

用户已要求停止 Mac/iPad 研究。本目录保存截止停止时的成果和未解决问题，后续没有继续修复、构建或手机研究操作。此归档不是“全部日常功能已完成”的发布声明。

## 已完成并交付

- Apple10，包名 `cn.classfun.droidvm.apple`，版本码 `2730`，原签名证书保持一致。完整 APK 构建、签名、对齐和 158 个运行资产成员校验通过；已经升级安装到测试手机。
- App 增加与原版隔离的运行资源和只读主机策略；修复输入和显示归属、迟到回调、停止/重启清理以及真实导入配置绑定。App 正常停止不自动强杀 Apple/Gunyah VMM，遗留 VMM 会阻止新后台接管。
- 原生运行组件在 [CI 45047307062](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/actions/runs/45047307062) 完整编译成功。提交 `a9af810fa11ce6479680e4972c7906752bdb4fc5`，实际 crosvm SHA-256 为 `94904ac5e0602704d429335d56496668a5a86a37ac6fe5992694b372dd90829f`。
- 按需 HostShare 在 [CI 45029535267](https://github.com/dixvetianshi/droidvm-apple-builds-20261117/actions/runs/45029535267) 构建成功。保持原节点和模块身份，只在接口与同名模块都不存在时加载 App 自带组件；不替换或卸载现有提供者。
- Mac 新导入准备了 PSCI 内核与 GPT/ESP/APFS 布局。iPad 修复版启动盘和包已经生成并完成所有成员的实际字节比较；App 自动识别新包，并在解压前拒绝已知旧内核包。
- App 测试分两次通过：此前 29 项、最终受影响的 15 项，均无失败和跳过。HostShare 的 22 个场景使用模拟的 VM/GUP/RM，并不等同于真实手机内核验证。
- 用户操作的一次冷启动中，等待两分钟后 Wi-Fi 自动恢复。原版 Debian 配置、原大页模块二进制和共有系统参数的对照未发现非预期变化。大页模块 SHA-256 仍为 `39fd6717d5506dde5b3e036ade97ae8443022c87041006317890223611c41aed`。

## 停止时的实际可用情况

**Mac：**Apple10 可启动，按需共享组件已加载并使用大页；但图形 `CREATE_LIST` 持续报 `EINVAL`。本轮完整桌面、输入、网络、媒体、正常关机和重复启动回池尚未验收。不能据此称为日常可用版本。

**iPad：**修复内核、包、App 导入识别和配置绑定已通过编译及校验；本轮尚未完成启动、实际 `lsd` 双 64 MB 限额、输入/网络/媒体或正常关机验证。

首次 HostShare 加载后，App 单次立即检查曾在设备节点出现前拒绝启动。后续复用已有节点启动成功。`unmerged-candidates/hostshare-node-publication/` 保存等待节点发布的候选；严格 Java 11 编译和 4 个边界测试通过，但它**未合入 Apple10、未生成 Apple11 APK，也未进行手机验证**。

Mac 的 `udmabuf` 问题仍未修复。已有只读证据指出：原先的 override 接口允许列表 65,536 项、单次 4096 MB，而冷启动后的内置接口是 1024 项、64 MB；Rust 会提交未合并的条目列表。尚未测得具体失败列表长度和字节数，因此不能把报错确定归因于其中一个上限。归档后不再推进该研究。

HostShare 的一路独立 C 实现审查未完成；不能将其记录为通过。真实 RM 回收、外部 exporter pin、致命 C 退出或 SIGKILL 下的行为不由模拟测试保证。用户拒绝替换原大页二进制的决定已保留。

## 内容与恢复

- `source-overlays/`：App、显示后端、Mac 来宾源码的基线与修改；`source-manifest.json` 保存实际文件 SHA。
- `bundle-tools/`：最终已有的运行产物接收、资产合并、签名和包工具及测试。
- `guest-repairs/ipados/`：iPad 限额修复的源码补丁和构建入口。`module-startup-repair/` 是此前授权的大页模块启动兼容脚本，不会自动安装或执行。
- `verification-summary.json`、`ci-receipts/`、`release-assets.json` 和 `SHA256SUMS`：去除本机路径与手机配置的归档摘要和校验清单。
- GitHub Release 保存 Apple10 APK、完整 App 源码快照、原始 Native ZIP 和 HostShare ZIP。App 源码继承上游 GPL-3.0 及源码树内各第三方许可。

App 上游基线是 `33488301c902124d9ddb09fa04b8126443d83230`。恢复时先取该基线及固定子模块，再覆盖匹配源码快照；运行资产可从本次 APK 提取，来源和校验见清单。归档的构建与签名工具去除了个人工具链目录，改读 `JAVA_HOME`、`ANDROID_HOME`、`GRADLE_USER_HOME`；这仅是归档路径调整，并未形成新的 APK 版本。归档不包含签名私钥。

苹果系统磁盘镜像、手机配置、密码、调试令牌、原始手机日志和截图没有公开上传。现有加密系统输入版本保持原样。本地清理只针对编译缓存、重复产物与研究临时目录；原始系统镜像、密钥、原版 Debian 文件和独立 Windows 成果保留。手机上的 App 与虚拟机不因电脑清理而卸载或删除。
