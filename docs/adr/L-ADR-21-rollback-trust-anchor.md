# L-ADR-21：跨 SQLite 备份的撤销新鲜度与防回滚锚

> 产品：Loom Rust Peer Mesh
> 版本：v1.1 设计候选 · 2026-10-17
> 状态：**PROPOSED / NOT FROZEN**（需要 Rust PoC、跨端测试与安全审查，非实施完成）
> 源自：`loom-rust-peer-mesh-architecture-review-v1.0.md`；主设计 `loom-rust-peer-mesh-architecture-v1.1.md`

## 问题与不可能性边界

同一 SQLite/磁盘备份里的 max-seq 与 revoke-root 会与授权一起回滚；签名证明只能说明过去某时合法，不保证最新状态。完全离线分区场景无法同时保证即时得知撤销和继续无限期允许访问。

## 候选决定

- `AnchorProvider` 提供 `(space_id, chain_id, writer_epoch, seq, head_hash, revocation_root, evidence_source, signed_at)` 的独立可信锚点。
- 默认安全模式优先预登记两个**独立可信见证**（具签名 key，互不以同一 Relay 为唯一路径），对风险资源按 policy 定义所需的可信见证集合；两个见证如果分歧，保留所有有效签名并切 `SYNC_CONFLICT`，不可自动取更小 seq。
- 支持平台提供的、经 PoC 证实真实防回滚的独立安全锚；不能把 Keychain/Keystore 误写成天然的 monotonic hardware counter。
- 没有可信见证时，使用已安全保存的高水位和受限 freshness_budget；过期进入 `POLICY_STALE` / `SAFE_READONLY`，不假设单一 Bootstrap 所说即为全网最新状态。
- 新 Grant 或 Root 恢复必须证明比任何已知有效撤销 epoch 更高；旧撤销 evidence 不可物理“反撤销”。合法恢复需新 key epoch 与显式重新签发。

## 启动和恢复

```
BOOTSTRAP_RECOVERY
  -> VERIFY_LOCAL_ANCHOR
  -> FETCH_TRUSTED_WITNESSES
  -> VERIFY_CHECKPOINT + REVOKE_SET
  -> READY
  otherwise -> POLICY_STALE or SAFE_READONLY
```

`POLICY_STALE` 禁止高风险新 SessionOpen（RDP 控制/文件写/跨空间 Exit/私网出口）；`SAFE_READONLY` 只允许受限本地诊断与审计导出，不自动为网络提供资源。管理员手动“仍然继续”不能在没有可验证凭证的情况下把旧 revoke 变回 allow。

## 测试

`ROLLBACK-01`：整机/SQLite 配置旧备份恢复、离线一年、两见证互相矛盾、Root 丢失、恶意 Bootstrap eclipse、恶意 Revoker mass-revoke、GC 之后的 proof 恢复。无旧权限恢复；若无法证伪回滚，应明确进入安全锁定而非继续高危操作。

## 未裁决选项

具体见证数量、离线 `freshness_budget` 上限与平台安全锚实现须由维护者结合威胁模型和可用性需求批准。没有声称两见证即可给出形式化全局最新状态证明。