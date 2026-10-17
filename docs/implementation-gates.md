# Loom v1.1 实施前检查清单

## 固定事实

- Loom 已在未合并的 Draft PR 分支中实现 Rust Workspace、候选签名协议、安全通道 PoC、Owner 生命周期验证以及 SQLite 日志 PoC；`main` 尚未集成这些功能，`loomd` 仍不提供网络监听或实际服务。
- RelayProxy 源码对照 commit 为 `e4254c81ed678198c948272c22981fd16c19be9a`；其模块存在与调用链证据来自此前静态核对，不代表完整 AST 图谱/性能验证。
- 所有新增安全子格式、最短编码、锁顺序、证书绑定、撤销 SLO 为**设计候选**，需经过 P0 PoC 与安全审查。

## 建议首批 PR

| PR | 目标 | 必须可执行的验收 |
|---|---|---|
| L-000 | Cargo Workspace 8 crates + cargo fmt/clippy/test/deny/fuzz starter + ADR 模板 | CI 真实运行、依赖许可和漏洞扫描 |
| L-001A | SecurePeerChannel + 双端 ID + 恶意 relay PoC | E2EE-01、TLS-ID-01 |
| L-001B | CBOR/protobuf Spike、canonical validator、向量导出 | WIRE-01 across Rust/Go/Kotlin/JS |
| L-001C | SQLite admission barrier、持久 outbox、rollback anchors | AUTHZ-RACE-01、AUTHZ-CRASH-02、ROLLBACK-01 |
| L-001D | Android/Windows/macOS 真实 OS Socket/driver PoC | PLATFORM-* tests |
| L-002 | 2 Peer LAN File read, Owner ACL, revoke | without RelayProxy Server, revoked peer cannot access |

**No-Go**：直接发布 WAN Relay、启用网络全局拦截、用自报 RDP 来源 IP 自动封禁、把旧数据库恢复成无审查新权限、声称 Rust 性能已优于 Go。

## 最新 P0 安全阻塞（截至 L-001J）

- L-001I 的 `unified_policy_*` 与旧 `sqlite_revocation` 尚未有可验证单向迁移，不允许把撤销链根直接当作统一策略链根。
- L-001J 增加了 Outbox/Audit 与签名事件的本地一致性检查，仍无法防止全部 SQLite 表被一致性回滚。
- 独立可认证、抗回滚的高水位 CAS 实现、可信 Root Pin 引导、签名 Witness 时效性和跨设备收敛尚未落地。
- `pending_outbox()` 仍是内部诊断接口，不能作为网络分发授权或 ServiceOpen 的证明。
- 全部 Draft PR 需逐层审查和对最终提交执行 CI；真实两 Peer LAN 验收与跨平台网络 Spike 均未完成。
