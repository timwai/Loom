# L-001 现有环境修复与集成验收 — 2026-10-20

**现有环境实验验收通过，正式 L-001 仍为 blocked。** macOS、Linux Docker 与 JP Android/Bionic 均以本轮源码重新构建，各通过 **268 项测试**。Android 实际加载 Rust JNI 动态库，五项 VPN 系统接口检查通过；专用容器重启后，268 项原生测试和 JNI/VPN 检查再次通过。没有把容器实验标记为物理设备或生产发布验收。

[汇总检查结果](final-checks.json)的配置为 `L-001-existing-environments-v1`；[核验脚本](verify.py)可以独立重放证据检查。该配置的 passed 与 [正式发布清单](release-manifest.json)的 blocked 分开记录。Windows 环境暂不可用、macOS 签名暂不可用，来自用户本轮明确说明。

## 本轮代码修复

1. **签名成员身份：** 新增 Root→MembershipWriter→成员凭证校验，严格绑定 Space、Peer 公钥、TLS key epoch、独立 membership epoch、当前 Writer epoch/精确序号及有效时间；拒绝签名、字段、类型、时效和 canonical CBOR 异常。当前 Root pin、序号和时钟仍须由外部可信状态提供，实验凭证不构成可信注册或防回滚。
2. **TLS 身份绑定：** SignedMembershipVerifier 返回凭证中的 membership epoch，修复将 TLS key epoch 直接当 membership epoch 的接口假设。握手异步 association 结束后再次核验，状态失效或主体变化即拒绝返回通道。已有通道提供显式复查；尚无强制撤销后关闭所有会话的生产协调器。
3. **Owner 授权字段：** 候选验证器将 Root 认证的 ResourceOwner 与同 Root 成员身份绑定，校验 Resource、Peer、两种 epoch、动作位、精确策略序号和时间区间。成员 Writer 不能充当 Owner，其他 Root 即使自洽签名也被拒绝。结果只是已验证字段，**不是 AdmissionPermit**，未接入生产 ServiceOpen。
4. **实际 Android JNI：** 新增 `loom-android`，APK 加载 `libloom_android.so`，复用 Rust 成员签名验证并检查实际 TUN IPv4/UDP 边界。Rust 创建 UDP socket、借用 FD 同步回调真实 VpnService.protect，成功后才 connect/send；失败立即拒绝，所有路径由 Rust 关闭 socket。Java 检查回调时尚未连接、socket inode 已释放，独立 UDP 服务核对是否发包。
5. **JNI 边界限制：** 三个入口均限制数组长度，使用 jni 安全接口，不接管 Java FD、不跨线程保留 JNI 引用；捕获 Rust panic，保留已有 Java 异常。仅该实验 crate 将 unsafe_code 设为 deny，并只对三个 JNI 导出符号的 `no_mangle` 属性作窄范围允许；没有加入原始指针解引用或 unsafe 代码块，其他 crate 的原有禁止策略保持有效。
6. **可复现负载：** 新增 Android server staging 脚本，构建全部测试与 release examples，记录来源和二进制摘要；从同批本机测试的 `--list` 生成逐 suite 预期数量，服务器核对 suite 集合、数量与摘要，避免新增测试后继续声称固定 248 项。历史 schema 1 证据保留，当前负载为 schema 2。

新增的 20 项测试由成员验证 7 项、实际 TCP/mTLS 与 Owner 集成 8 项、Android Rust 边界与 socket 工厂 5 项组成。固定 Root/Writer/Owner 私钥均为公开的可抛弃测试种子；没有完成生产密钥注册。源码仍在工作区，基础提交为 `498870abff9b7fede983b9ef59b0aa7132520ca4`；本轮改动尚未提交或合并，精确来源见 [源码快照](sources/)和各结果内的逐文件摘要。

## 实际验收结果

| 环境或检查 | 结果 |
|---|---|
| macOS workspace / all-targets | 268 passed；fmt、严格 Clippy 通过 |
| 本机 Linux Docker ARM64 | 268 passed；严格 Clippy、Rust 文档、四语言向量通过 |
| 本机 TCP / TLS 与 Relay | 四条路径、逐块数据核对、20 项拒绝；明文 canary 不可见，主动篡改被拒绝 |
| 本机存储与恢复 | 9 次进程/整容器 SIGKILL 恢复，20 项 Witness 诊断；同机全部历史一起回滚的反例继续保留 |
| JP Android 重启前 | 268 passed，UID 2000；三条 TLS 路径、15 项拒绝、3 次 SIGKILL、10 项 Witness 诊断通过 |
| JP Android 重启后 | 相同负载再次 268 passed；上述原生路径与故障检查再次通过 |
| Android JNI / VPN | 重启前后均通过未授权拒绝、系统取消、真实授权/TUN/protect、Settings onRevoke、应用 SIGKILL 五项检查 |
| JNI 凭证负向检查 | 每个成功数据路径均拒绝坏签名、错误 Space、旧序号、过期、截断、超长六类输入 |
| Rust socket 顺序及释放 | connect 前保护；protect=false 无发包；成功及拒绝 socket 均释放 |
| 独立 UDP 观测 | 两轮 VPN 窗口各 **6 个 protected 报文、0 个 unprotected canary**，与 Java+Rust 三次数据路径一致 |
| 容器与业务核对 | 重启后 system_server PID 239 持续一致，lmkd running，PID/OOM 事件为 0；原有四个业务容器身份、启动时间、重启计数不变 |
| 正式发布命令 | 清单有效；`--require-complete` 按预期退出 1，拒绝未完成的发布 |

最终 APK 为应用 UID **10093**；重启前 UID 10092。仅给探针自身 UID 安装 Docker 私有 gateway 的 IPv4 `/32` 路由；使用真实系统 VPN 授权界面，没有用 appops 预授权。Rust 成员验证、TUN 检查和受保护 UDP 已实际跨 JNI 执行，但没有将 TUN 业务报文加密后送入生产 Peer 通道。

## 测速基线

以下均为 release 实验通道。macOS↔Linux 位于本机 Docker；JP 的 Android↔Linux 位于**同一 VPS**。它们不是本机到日本的公网测速，也不是 VPN 加密转发吞吐。测速通道仍使用诊断 fixture，新增签名成员/Owner 集成由独立测试覆盖。没有预设性能 SLO，不能把完成采样写成生产性能达标。

| 客户端→服务端 | TLS 关联 P95 ms | 1 KiB 回显 P95 ms | 下载中位 MiB/s | 上传中位 MiB/s |
|---|---:|---:|---:|---:|
| macOS→macOS | 2.616 | 0.102 | 2634.7 | 2364.9 |
| macOS→本机 Linux | 9.004 | 0.646 | 1961.6 | 1459.3 |
| 本机 Linux→Linux | 1.544 | 0.018 | 2847.8 | 2843.7 |
| 本机 Linux→macOS | 6.917 | 0.275 | 1404.6 | 2616.6 |
| JP Android→Android | 1.927 | 0.081 | 1259.2 | 1242.2 |
| JP Android→Linux | 1.376 | 0.079 | 1158.2 | 1055.3 |
| JP Linux→Android | 1.930 | 0.196 | 967.9 | 1099.9 |

每条路径保留 50 次关联、200 次回显、32 MiB bulk 及 8 通道采样。原始样本、环境限额与编译命令见 [本机结果](local-docker/results.json)及 [JP 最终结果](native/results.json)。本机 builder 限制为 4 CPU / 4 GiB；Android 限制为 2 CPU / 3 GiB / 4096 PID。不同环境和采样窗口的结果未合并。

## 证据及复核

- [本机完整日志](local-docker/logs/)、[原生重启前](before-restart-native/results.json)、[原生重启后](native/results.json)。
- [JNI 重启前](before-restart-vpn/results.json)、[JNI 重启后](vpn/results.json)、[APK 构建与签名验证](vpn/build.json)、[独立 UDP 日志](udp-echo.log)。APK 使用实验调试签名，私钥没有加入证据。
- [二进制清单](binary-manifest.json)、[交叉编译日志](build-logs/)、[重启记录](container-restart.log)、[重启前健康](server-before-restart.json)、[重启后健康](server-after-restart.json)、[最终健康](server-final.json)。
- 汇总核验初版把正常清理命令的 `expected=null` 当成不匹配；保留 [初版](verify-initial.py)及 [失败记录](verification-initial-failure.json)，修正为对该命令显式要求退出 0 后重新通过。原生与 APK 测试结果未被修改。
- [清理结果](cleanup.json)：停止本轮 UDP helper 和专用 Android 容器，保留固定镜像、独立卷、负载；原有业务容器继续运行。清理停机不计为断电证据。SSH 凭据未写入文件。文件摘要见 [SHA256SUMS](SHA256SUMS)。

复跑说明见 [Android Docker 实验](../../android-docker-lab.md)；静态核验可执行：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 docs/acceptance/evidence/l001-integrated-20261020/verify.py
python3 scripts/l001_gate.py --require-complete  # 当前应退出 1
```

## 距离正式 L-001 完成仍缺什么

1. `loomd` 的可信注册、完整成员/Owner 生命周期、撤销与会话终止、策略到 ServiceOpen 的原子准入路径，以及真正的两 Peer 文件读取/撤销验收。
2. 独立可信的新鲜度与防回滚后端、跨进程协调、真实 durable Prepared/CAS 和断电恢复；本轮同机 Witness 与进程强杀不能替代这些证据，也不要求必须选 TPM。
3. 生产 Android 加密转发、DNS/IPv6 全流量防泄漏、切网/后台/物理设备重启；可管理 Windows 主机及过滤器验收；macOS 签名扩展、entitlement 与实际部署验收。
4. 协议冻结和 security、interop、platform、trusted_state 四类独立审查签字。

因此本轮只将有证据支持的实验配置置为 passed；正式九项门禁和四项审查仍未通过，不能将 `docs/acceptance/l001.json` 改成 complete。
