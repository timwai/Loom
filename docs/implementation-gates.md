# Loom v1.1 实施前检查清单

## 固定事实

- 原始设计和评审来源均属于已生成的本地 Markdown 文档；Loom 当前项目尚未声明已经具备 Rust 代码或协议实现。
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