# L-001 Android Docker 测试报告 — 2026-10-20

**原生运行时实验通过；Android 平台正式验收未通过。** 本机 Docker 已安装 ReDroid Android 14 / API 34 / ARM64，在真实 Android Bionic 中以 shell UID 2000 完成 248 项 Rust 测试、三条 TCP/TLS 路径、15 项拒绝检查、三次强杀恢复和十项新鲜 Witness 恢复实验。实验配置为 `L-001-android-bionic-docker-v1`，没有生产 APK、JNI 或 VpnService 集成，L-001 发布状态保持 blocked。

本机 OrbStack 内核缺少 memory pressure events，Android `lmkd` 反复退出。`sys.boot_completed=1` 和本轮 ADB shell 成功不能证明 Framework 稳定；VpnService、应用前后台及内存压力测试均未计为通过。

## 可核验的证据

- [完整结果与原始采样](results.json)：运行始于 `2026-10-19T23:48:19Z`（上海时间 10 月 20 日 07:48），130 条记录命令，源文件前后 SHA-256 一致。
- [实验脚本源码快照](runner.py)，与结果记录的 SHA-256 一致；正常复跑使用仓库的 [脚本](../../../../scripts/l001_android_docker.py)，步骤见 [说明](../../android-docker-lab.md)。
- [原始日志](logs/)：各 crate 完整测试输出、编译、Android 系统属性、ADB、lmkd、网络与存储实验；[ELF 头](logs/android-elf.log)确认为 AArch64，动态解释器 `/system/bin/linker64`，不是在普通 Linux/glibc 中运行后标注 Android。
- [初次工具失败记录](initial-tool-failure.json)：系统 sqlite3 因缺少 Android init 的 APEX 环境而在 ICU 注册时退出 134。脚本补齐 ART/I18N/TZDATA 环境后重新执行整轮验收通过；该失败未作为成功样本。
- [停止后重启验证](restart-smoke/results.json)及[最终检查](final-checks.json)：安装环境可恢复，正式验收清单有效，发布严格模式仍按预期返回拒绝。
- [SHA256SUMS](SHA256SUMS)：本目录所有证据文件的摘要，不含摘要文件自身。

## 环境与边界

| 项目 | 实际配置 |
|---|---|
| 主机 | Apple Silicon ARM64，10 CPU，16 GiB；macOS |
| Docker | 29.8.2，OrbStack，aarch64；内核 `7.2.9-orbstack-00391-g2b298d05fbd4` |
| Android | ReDroid 14，API 34，`arm64-v8a`，userdebug/test-keys，SELinux Disabled |
| 镜像 | `redroid/redroid@sha256:0a611199ba2e0b5d60af39b3327a517f6407231f4352114ed3bd3cbfe2be69aa` |
| 容器 | `loom-l001-android`，privileged，4 CPU / 4 GiB / 1024 PID；独立 `/data` 卷 |
| 编译 | Rust 1.90，NDK 27.2.12479018，Android API 26 链接目标；运行系统为 API 34 |
| 执行 | `docker exec --user 2000:2000`，非 root；ADB 绑定 `127.0.0.1:15555` |
| 网络 | 使用 Android 已有 eth0 路由，未添加绕过 VPN 的实验路由；macOS→Android 经 OrbStack 私有 IP |
| 系统限制 | `/proc/pressure/memory` 不可用，lmkd 为 restarting；镜像亦有虚拟蓝牙 HAL 崩溃，均不能当作真机环境 |

Binder 节点初始权限 0600 导致系统服务无法连接，已仅在本实验容器内修正为 0666。镜像、数据卷与 Rust Android target 已保留；不触碰现有 postgres 容器、macOS 系统代理或 VPN。临时 TLS 私钥与测试监听进程在完成后清除。由于 lmkd 仍在反复退出，后续停止容器以保留环境并释放资源，恢复使用 `python3 scripts/l001_android_docker.py start`。

## 测试结果

| 检查 | 结果 |
|---|---|
| Rust Android workspace / all-targets | 248 passed，0 failed，0 ignored；包含 182 store、35 crypto、13 core、8 wire、7 transport，以及三个各 1 项的基础 crate |
| 真实 TCP + TLS 1.3 | Android→Android、Android→macOS、macOS→Android 全部通过；逐块核对数据 |
| 负向身份与范围 | 三条路径各拒绝 5 项，共 15 项：错误服务端 pin、未信任客户端、错误 Space、错误 epoch、成员拒绝 |
| 编解码与 SQLite | release 编解码与签名验证；100 次 append + 20 次完整 inspect，原始采样有效 |
| Android 内 SIGKILL | ACK 门槛 10 / 25 / 50，设备侧写进程均退出 137；恢复序列 27 / 36 / 59，Outbox 数匹配，integrity_check 均 ok，admission_paused 始终 true |
| 新鲜 Witness 恢复 | 10 项通过：2 项健康诊断、8 项预期拒绝；本地有效旧备份由序列 8 回到 5 后，被仍保留最新历史的 Witness 检出 |
| 可信存储反例 | 三份同机数据库一起回滚仍可匹配；明确不是独立可信防回滚存储 |

强杀前读取 PID 和发送信号期间，写进程可继续提交，所以恢复序列可以高于 ACK 门槛；判定是已确认历史不丢失、镜像一致和授权继续暂停。没有执行物理断电，也没有把匹配的 Witness 诊断提升为授权。

## 测速基线

性能使用 release 构建，沿用原实验的预热与采样口径。MiB/s 为内存 TCP 实验吞吐，不能外推为手机 Wi-Fi、移动网络或 VPN 转发性能；无预设 SLO，系统后台故障与同机调度也会影响结果。

| 客户端→服务端 | TLS 关联 P95 ms | 1 KiB 回显 P95 ms | 下载中位 MiB/s | 上传中位 MiB/s | 8 通道上传 MiB/s |
|---|---:|---:|---:|---:|---:|
| Android→Android | 0.434 | 0.022 | 2156.9 | 2692.4 | 3050.1 |
| Android→macOS | 3.861 | 0.148 | 1559.6 | 2310.0 | 2205.3 |
| macOS→Android | 2.754 | 0.075 | 2009.4 | 1778.5 | 1613.3 |

SQLite append 包含完整历史签名重放，100 条递增历史的中位数 **7.227 ms**、P95 **12.377 ms**；100 条历史 inspect 的中位数 **11.084 ms**。这不是固定历史长度下的稳态 append 吞吐。

## 仍未完成的 Android 平台验收

此结果证明 Rust 核心在 Android Bionic 上可运行，实验网络和日志诊断可用。Loom 尚无生产 Android APK/JNI/VpnService 接入，本机内核还不能提供稳定的 Framework 内存管理条件。因此 prepare/protect/TUN、系统 VPN 权限与撤销、前台服务、DNS/IPv6 泄漏、切网、后台限制及重启等仍未验证，`PLATFORM-ANDROID-01` 保持 blocked；Windows、macOS 签名扩展和独立审查也未由本实验替代。

容器应用层后续测试需要具备 Binder 和 PSI/memory pressure 支持的 Linux Docker 内核。ReDroid 维护者也指出了[相关内核要求](https://github.com/remote-android/redroid-doc/issues/293)。真实 Android 设备的最终验收仍需另行完成。
