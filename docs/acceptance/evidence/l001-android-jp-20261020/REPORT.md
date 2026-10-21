# L-001 JP Android Docker 测试报告 — 2026-10-20

**远端原生实验与独立 VPN API 实验通过，容器重启后整轮复验通过。L-001 正式发布仍为 blocked。** 在用户授权的 `jp.tingjusting.fun` 上运行 Android 14 / API 34 / ARM64 Docker：248 项 Rust 测试、三条 TLS 路径、15 项拒绝检查、三次存储强杀恢复和十项 Witness 实验全部通过；独立调试 APK 的五项 VPN API 检查全部通过。

此处 APK 是平台接口探针，没有 Loom Rust/JNI、加密转发或生产授权。当前结果覆盖这两个实验配置，没有完成生产 Android VPN、物理 Android 设备或 L-001 全部门禁验收。

## 证据与来源

- 重启后最终结果：[原生测试及测速](native/results.json)、[VPN API](vpn/results.json)、[独立 UDP 服务日志](udp-echo-final.log)。运行分别在 `00:17:16Z–00:17:38Z` 和 `00:17:50Z–00:18:17Z`，即上海时间 08:17–08:18。
- 重启前同样通过：[原生](before-restart-native/results.json)、[VPN](before-restart-vpn/results.json)。这两个结果与重启后的结果分别保存，没有合并采样或掩盖失败。
- [最终核验](final-checks.json)复核源文件快照、采样数与有限正数、应用 UID、独立 UDP 日志以及发布门禁；[服务器核验](server-final-checks.json)保留 Framework、PSI、PID/OOM 和原有容器状态；[清理结果](cleanup.json)记录实验进程停止、环境保留。
- [二进制清单](binary-manifest.json)记录原始与剥离调试信息后的 SHA-256，以及 Rust/Cargo 源文件摘要。Android 二进制由本机 NDK 27.2.12479018 / Rust 1.90 交叉编译，动态链接器为 Android Bionic；远端未用 Linux/glibc 冒充 Android。Linux 辅助通道单独运行于宿主机。
- 基础提交为 `498870abff9b7fede983b9ef59b0aa7132520ca4`，本轮包含尚未提交的实验及修复代码。实际来源以逐文件摘要为准；传入时、运行前后、回收证据时均核对 Rust/Cargo 摘要。传入的原生负载约 42.4 MiB，仅剥离 debug 信息，没有改动机器码。
- [脚本与 APK 源码快照](sources/)；[APK 构建及签名验证](vpn/build.json)，最终 APK SHA-256 为 `ef70aa49143a3e3270b7265a1d3150e74a3667433722868812483953370413db`。仅使用实验调试签名，私钥没有加入证据或仓库。
- [初始失败](initial-failures/)及[初始 UDP 日志](udp-echo-initial.log)保留真实失败。所有文件的摘要见 [SHA256SUMS](SHA256SUMS)，不包含摘要文件自身。

## 环境及实际变更

| 项目 | 配置 |
|---|---|
| 宿主机 | Ubuntu 24.04.4 LTS，Oracle Ampere ARM64，4 CPU / 24 GiB |
| 内核与 Docker | `6.17.0-1011-oracle`，Docker 29.7.0，cgroup v2；PSI memory 可用 |
| Android | ReDroid 14，API 34，ARM64，userdebug/test-keys；SELinux Disabled |
| 镜像摘要 | `redroid/redroid@sha256:0a611199ba2e0b5d60af39b3327a517f6407231f4352114ed3bd3cbfe2be69aa` |
| 专用资源 | `loom-l001-android-jp`，privileged，2 CPU / 3 GiB / 4096 PID；`loom-l001-android-jp-data` 独立卷 |
| 访问 | ADB 仅远端 `127.0.0.1:15555`；SSH 22 转发到本机 `127.0.0.1:15556` |
| 执行身份 | Rust 原生测试 UID 2000；最终 APK 为应用 UID 10090；未使用 appops 代替系统 VPN 授权 |
| 实验范围 | APK 只给自身 UID 和私有 Docker gateway `172.17.0.1/32` 建立测试路由 |

为当前运行内核安装了匹配的 `linux-modules-extra-6.17.0-1011-oracle`（`6.17.0-1011.11~24.04.1`）及依赖 wireless-regdb，加载 Binder、IPv6 iptables、TUN 模块。包安装更新 initramfs/GRUB；没有升级或重启宿主机。容器不挂载宿主机目录或 Docker socket。

原有 `relay-agent`、`aigc_all`、`aigc_milvus`、`nginx` 均保持运行，容器 ID、启动时间及重启计数与开始时一致。该核对证明容器没有被重建或重启，没有声称完成业务层功能验收。

## 修复后重新验收

1. **宿主内核依赖：** 初始缺少 Binder 对应模块；安装运行内核的 modules-extra 后使用独立 BinderFS。容器私有 Binder 节点权限修正为 0666。
2. **Framework 稳定性：** 初始 1024 PID 上限触发线程创建失败；专用容器改为 4096 PID。该镜像虚拟蓝牙 HAL 无有效硬件地址，本实验关闭虚拟蓝牙并保留其限制。重启后 system_server PID 234 在两轮测试及最终检查中一致，lmkd 持续 running，PID max、OOM、OOM-kill 计数均为 0。
3. **Android TUN 节点：** 仅存在 `/dev/net/tun` 时，Android JNI 的 `/dev/tun` 打开失败，APK 报 Cannot create interface。补齐容器内 `/dev/tun` 后成功；安装脚本在已有容器每次启动时恢复节点，新建容器直接映射该设备。容器重启后的 VPN 实验已再次通过。
4. **启动时序与数据判断：** 初版探针轮询 getActiveNetwork，可能在 netd 完成路由安装前得到 VPN；初始 UDP 日志确实出现未保护 canary，不能算通过。修正为等待默认网络回调中的 VPN capabilities 与 TUN LinkProperties 就绪，再发送测试流量。TUN 初始还会出现 IPv6 控制包，探针现在保留报文十六进制，在有限时间/包数内定位指定 IPv4/UDP/目的端口/canary，而非假定首包就是业务流量。
5. **自动化授权界面：** 清理专用测试 Android 内残留的授权弹窗并重建 Activity 任务，避免读取旧 Intent；保留系统 XML 和截图，不预先授予 VPN appop。另一次调试用 VPN 未停止被前置检查拒绝，也保留为失败记录。

网络回调的使用遵循 [Android 官方 NetworkCallback 文档](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback)的就绪和顺序约束。prepare/protect/连接/TUN 与撤销清理对应 [Android VPN 指南](https://developer.android.com/develop/connectivity/vpn)。这些接口实验不自动建立生产安全属性。

## 最终验收结果

| 检查 | 结果 |
|---|---|
| Android Bionic workspace / all-targets | 248 passed，0 failed，0 ignored，UID 2000 |
| TLS 与范围拒绝 | Android→Android、Android→Linux、Linux→Android，逐块核对数据；每条 5 项拒绝，共 15 项 |
| SQLite 强杀恢复 | ACK 门槛 10 / 25 / 50，SIGKILL 退出 137；恢复序列 15 / 28 / 52，Outbox 数匹配，integrity_check=ok，admission_paused=true |
| Witness 诊断 | 10 项通过，包含旧本地备份、旧 nonce、缺失/伪造/分歧 Witness、签名或镜像损坏及修复后重新检查；三份同机数据库一起回滚仍能匹配的反例继续保留 |
| 未授权拒绝 | prepare 要求授权时，直接 establish 被拒绝，未建立 TUN |
| 系统取消授权 | 点击真实系统 CANCEL，应用收到 RESULT_CANCELED，未建立 TUN |
| 授权与 TUN/protect | 点击真实系统 OK；前台服务启动；protect 在 connect 前成功；受保护 UDP 得到回包；未保护 canary 在 TUN 中出现且收不到回包；关闭后 FD/socket 与 TUN 均清除 |
| 设置断开 | 通过系统 VPN Settings 点击 DISCONNECT，实际触发 onRevoke，FD/socket 关闭，TUN 消失 |
| 应用强杀 | 应用 UID 通过 run-as 发送 SIGKILL，TUN 消失；3 秒后无应用自行重启、无 TUN |
| 容器重启 | 数据卷保留，lmkd 正常、TUN 节点恢复、APK 未自动启动；原生与 VPN 全部检查再次通过 |

最终 VPN 窗口内，宿主私有 UDP 服务独立记录 **3 个 protected 报文、0 个 unprotected canary**，与三次成功的数据路径检查一致。初始失败窗口中可见泄漏的 canary 被单独保留，不进入通过样本。该检查仅证明指定 UID、IPv4 `/32` 路由和实验报文的行为，没有验证任意流量的防泄漏。

## 测速基线

以下使用重启后单轮 release 原生通道结果。各路径都在同一 VPS 上：这些是同机 TCP/TLS 内存吞吐，**不是公网、手机网络或 VPN 端到端转发速度**。沿用本机实验的预热、50 次关联、200 次 1 KiB 回显、32 MiB bulk 与 8 通道采样口径，无预设性能 SLO。

| 客户端→服务端 | TLS 关联 P95 ms | 回显 P95 ms | 下载中位 MiB/s | 上传中位 MiB/s | 8 通道上传 MiB/s |
|---|---:|---:|---:|---:|---:|
| Android→Android | 2.146 | 0.087 | 1220.5 | 1223.8 | 1088.0 |
| Android→Linux | 1.985 | 0.134 | 1139.6 | 982.2 | 1030.3 |
| Linux→Android | 1.587 | 0.150 | 1060.6 | 1062.9 | 1002.2 |

100 条递增历史的签名 SQLite append 中位数 **42.102 ms**、P95 **75.961 ms**；100 条历史 inspect 中位数 **76.231 ms**。append 包含随历史长度增长的完整签名重放，不能当作固定历史的稳态吞吐。

## 保存与尚未覆盖的范围

实验完成后停止私有 UDP 服务与 Android 容器，保留固定镜像、独立数据卷和 `/opt/loom-l001-lab/run20261020` 负载。停止超时后 Docker 终止容器，最终退出码 137；该清理发生在全部测试通过之后，没有把它算成额外的存储断电证据。复跑步骤见 [实验说明](../../android-docker-lab.md#jp-linux-docker-复跑)。SSH 凭据未写入脚本或证据。

`PLATFORM-ANDROID-01` 仍为 blocked：生产 Rust/JNI/VpnService 转发与授权整合、DNS/IPv6 全流量泄漏、Wi-Fi/移动网络切换、厂商后台限制、物理设备重启与安全存储尚未验收。本机 OrbStack 缺 PSI 的问题也没有被远端结果覆盖掉。Windows 真机过滤器、macOS 签名扩展、独立可信防回滚与四类审查签字同样未完成；正式严格发布命令继续返回拒绝。
