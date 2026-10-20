# L-001 本机 / Docker 实测验收报告

实验日期：2026-10-19（Asia/Shanghai）；运行标识：`20261019T153623Z`。

**结论：本次 PoC 实验项目全部完成；正式 L-001 发布验收仍为 BLOCKED。** 未给定性能阈值，测速仅建立基线。

## 环境与可追溯性

- macOS 27.0 / Apple Silicon ARM64，Mac16,10，10 核、16 GiB；Docker 29.8.2 / OrbStack Linux ARM64，VM 10 核、约 7.82 GiB。
- Rust 1.90.0 release 构建；Go 1.23.12、Node.js 18.20.4、OpenJDK 17、Kotlin 1.3.31 的容器版本以 [工具链日志](logs/linux-toolchains.log) 为准。
- 基线 `main@498870abff9b7fede983b9ef59b0aa7132520ca4` 加本分支实验工具与 macOS 条件编译修复；测试对象不是未经修改的 main。全部输入代码 SHA-256、原始样本、命令和返回码见 [results.json](results.json)。
- 构建容器限制 4 CPU / 4 GiB；Peer 容器 2 CPU / 512 MiB / 128 PID。编译与校验结束后，测速串行执行。主机 SQLite 位于 APFS，Linux SQLite 位于 Docker 原生卷。

## 实际 TCP + TLS 1.3 性能

所有数值来自已核对内容的内存 payload，无真实文件读写、QUIC、VPN 或 WAN。方向均以客户端为准。

| 客户端 → 服务端 | 建连中位数 / P95 (ms) | 1 KiB 回显 P95 (ms) | 上行中位数 (MiB/s) | 下行中位数 (MiB/s) |
|---|---:|---:|---:|---:|
| macOS → macOS | 2.025 / 2.874 | 0.113 | 2863.9 | 2965.9 |
| macOS → Docker Linux | 3.362 / 5.252 | 0.348 | 2035.7 | 2385.7 |
| Docker Linux → Docker Linux | 0.515 / 0.595 | 0.018 | 2627.5 | 3129.7 |
| Docker Linux → macOS | 5.228 / 6.520 | 0.216 | 2832.9 | 1868.9 |

建连预热 5 次后采样 50 次，包含 fixture 文件读取、新 TLS 配置、TCP 和关联交换；回显预热 20 次后采样 200 次。每方向 32 MiB 预热一次、实测五次，上传等候接收端确认。MiB/s 为 2²⁰ bytes/s。

| 客户端 → 服务端 | 8 通道聚合上传 (MiB/s) |
|---|---:|
| macOS → macOS | 2545.9 |
| macOS → Docker Linux | 1540.5 |
| Docker Linux → Docker Linux | 3225.0 |
| Docker Linux → macOS | 2767.6 |

8 条已建立通道各上传 8 MiB；统一起跑后计时，单次采样仅供观察。上述差异同时受 VM、调度、网络路径、文件系统和缓存影响，不能视为 Docker 加速比或实际公网容量。

## 协议与存储性能

| 操作 | macOS 中位数 / P95 (ms) | Docker Linux 中位数 / P95 (ms) |
|---|---:|---:|
| 100 条增长历史中的逐条签名 append | 5.843 / 10.589 | 7.472 / 12.397 |
| 完整重放 100 条签名历史 | 10.796 / 10.907 | 11.528 / 11.820 |

每次 append 都对已有历史完整验签并提交 SQLite FULL/WAL；100 个样本的历史长度不同，因此不能把上述中位数当成恒定成本。20 次 inspect 都重放完整 100 条历史。

- host-storage：首条 append 0.967 ms，末条 11.057 ms。
- linux-storage：首条 append 1.698 ms，末条 13.463 ms。

| 编解码 / 签名操作 | macOS (µs/操作) | Docker Linux (µs/操作) |
|---|---:|---:|
| `codec_encode_payload_256` | 0.087 | 0.031 |
| `codec_decode_payload_256` | 0.138 | 0.080 |
| `codec_encode_payload_4096` | 0.086 | 0.089 |
| `codec_decode_payload_4096` | 0.247 | 0.221 |
| `codec_encode_payload_61440` | 0.620 | 1.580 |
| `codec_decode_payload_61440` | 3.634 | 3.987 |
| `sign_encode_verify_delegated_revocation` | 213.334 | 241.606 |

编解码数据是 10 批均值的中位数，包含分配；签名操作包含实验密钥对象构造、编码、签名和双签验证。没有对等 Go 服务基准，因此不声称 Rust 相对 Go 的性能优劣。

## 实验验收结果

- macOS 与 Linux 各 **244/244** Rust 测试通过；双方严格 Clippy、格式检查、Linux API 文档成功。macOS 原有 17 项 TPM dead-code 警告通过只编译 Linux/测试需要的辅助代码消除，未放宽 lint。
- Rust/Go/JavaScript/Kotlin 候选 canonical CBOR 与签名输入校验通过；Go/JavaScript Ed25519 向量通过。
- 4 条 TCP 路径 × 5 类错误证书/客户端/Space/epoch/成员关系，共 **20/20** 拒绝。转发 Relay 观察到 3983 字节，未检出业务明文 canary；主动篡改握手后认证回显失败。这是 smoke test，非密码学证明。
- 本机进程、容器内进程均在确认 10/25/50 条记录后 SIGKILL：**6/6** 重启完整重放，Outbox 数量匹配且 `integrity_check=ok`。
- 强杀整个 Docker 写进程容器：**3/3** 新进程恢复了至少已确认的前缀，始终暂停授权。发出 Docker kill 存在延迟，恢复条数可大于最后读到的 ACK；这些额外记录不代表 ACK 丢失。

  - ACK 下界 10 → 恢复 21，容器退出码 137。
  - ACK 下界 25 → 恢复 31，容器退出码 137。
  - ACK 下界 50 → 恢复 63，容器退出码 137。

- 两个环境的篡改签名、删除 Outbox 均被拒绝。恢复有效旧备份后，诊断日志确实从 8 条退回 5 条，本地签名重放无法独立发现回退；授权仍为暂停。
- 双方 `loomd` 均输出 `BootstrapOnly / network_enabled=false`。macOS TPM 探测返回 UnsupportedPlatform，容器返回 DeviceMissing；没有可信存储自动降级。发布严格模式退出 1，正确拒绝发布。

## 正式 L-001 门禁判定

| 门禁 | 本次新增证据 | 正式状态 / 剩余缺口 |
|---|---|---|
| E2EE-01 | 真实进程与 TCP 的 mTLS、篡改拒绝、Relay canary | PARTIAL：未接入 live daemon、完整攻击矩阵和资源限额验收 |
| TLS-ID-01 | pinned 证书、Peer/Space/epoch 错配拒绝 | PARTIAL：成员关系是 fixture allowlist，缺签名注册、到期及 Owner admission |
| WIRE-01 | 四语言既有 corpus 本地复跑 | PARTIAL：协议冻结、typed payload、差分 fuzz、版本协商和独立复核未完成 |
| AUTHZ-RACE-01 | 已有模型竞态测试均通过 | PARTIAL：没有真实授权到 ServiceOpen 的原子提交、跨进程防绕过链路 |
| AUTHZ-CRASH-02 | 9 次进程/整容器强杀与恢复；镜像完整性检查 | PARTIAL：不是物理掉电，缺真实独立可信后端的 durable Prepared/CAS |
| ROLLBACK-01 | 旧备份回退实测暴露独立锚缺口；授权保持暂停 | PARTIAL：没有独立非回滚高水位和真实登记/恢复验证 |
| PLATFORM-ANDROID-01 | 无新增真实平台证据 | BLOCKED：缺 Android 设备和 VpnService |
| PLATFORM-WIN-01 | 无新增真实平台证据 | BLOCKED：缺 Windows 驱动/服务真机验收 |
| PLATFORM-MAC-01 | 本机 Rust 与 TCP 实测 | BLOCKED：缺签名 Network/System Extension、entitlement、部署及泄漏测试 |

**正式门禁仍为 0/9 passed，四项签核均未完成。** 本机 Docker 的多个进程/容器共享同一物理主机和信任域；不能冒充独立 Witness、物理断电或其他 OS 实机。

固定基础镜像的复跑 Dockerfile 已构建，并在成品镜像中通过 Go/JavaScript/Kotlin 校验及严格 Clippy；见 [镜像记录](packaging.json)、[构建日志](logs/docker-image-build.log) 和 [验证日志](logs/image-verify.log)。

复跑方法与限制见 [实验说明](../../local-docker-lab.md)。原始采样可导入 [samples.csv](samples.csv)，完整命令输出保存在 [logs/](logs/)。
