# L-ADR-19：独立于 Relay 的端到端 SecurePeerChannel

> 产品：Loom Rust Peer Mesh
> 版本：v1.1 设计候选 · 2026-10-17
> 状态：**PROPOSED / NOT FROZEN**（需要 Rust PoC、跨端测试与安全审查，非实施完成）
> 源自：`loom-rust-peer-mesh-architecture-review-v1.0.md`；主设计 `loom-rust-peer-mesh-architecture-v1.1.md`

## 问题与风险

不能将 A→Relay 和 Relay→B 两条 Quinn/TLS 连接的加密等同 A↔B 端到端加密；Relay 终止外层 TLS，通常能读取流中转发的业务明文。旧设计尚缺路径统一安全协议。

## 候选决定

- V1 保守方案：为每条 Peer/Space Security Association 在可靠承载字节流上运行**内层 TLS1.3 双向 Peer 证书认证**，TLS 只在 A/B 终止。外层可选 QUIC direct stream、QUIC Relay stream、TLS/TCP direct/Relay。Relay 只能看外层元数据，不获业务明文。
- 在网络候选发现后先建立外层 bearer，再建立内层 SecurePeerChannel；验证 PeerId/expected target、SPKI Ed25519、公钥 epoch、Space proof、撤销高水位后才开放 ServiceOpen。
- `PeerId = SHA256("LOOM:PEER-ID:V1\0" || 32-byte-ed25519-public-key)`；自签 X.509 的 SPKI key 必须与 PeerId 匹配，不能简单信任任意自签名证书。
- 每次 ServiceOpen 包含 `(space_id, caller_peer, intended_owner_peer, resource_id, action, policy_epoch, request_id, capability_hash)`；目标 Owner 执行本地最终授权。路径竞速不得换实际 Exit。
- V1 默认禁用 0-RTT；切换 bearer 重新握手/重绑定，并要求完整 anti-replay。未经独立验证，不将外层 QUIC ticket 视作已完成内层身份认证。
- 多路复用候选为经过审核的成熟 mux；如 Rust mux 不能通过限额和流控 Spike，则保守使用每服务独立 TLS 会话；不自行设计未经审查的加密 mux。额外握手带来的 CPU、内存和尾延迟需实测。
- 封装 UDP 业务首版可在 E2EE 可靠 stream 中传递，明确存在 HOL；只有通过 AEAD/反重放/性能测试后才允许开启不可靠 datagram 优化。

## Bearer 安全接口（伪代码）

```rust
pub trait BearerStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

pub struct SecureChannelContext {
    pub expected_peer_id: PeerId,
    pub space_id: SpaceId,
    pub key_epoch: u64,
    pub transcript_hash: [u8;32],
}

pub trait SecureChannelFactory {
    async fn handshake(&self, bearer: Box<dyn BearerStream>, ctx: SecureChannelContext)
      -> Result<SecurePeerChannel, SecureChannelError>;
}
```

## 不变量与退出门禁

1. Relay 无法获业务明文（但可观测大小、时序、外层连接端点），不能替换目标 B、变更 Space、Replay 内层数据、降级成明文或在 path switch 后绕过授权。
2. 内层握手时拒绝错误 PeerId、证书、密钥 epoch、成员撤销；每业务 ServiceOpen 重新看 Owner ACL。
3. 恶意中继（tcp/quic）正负向 PoC 通过、真实抓包无明文、1,000 并发流与大文件下 revoke 通道满足 QoS，ADR 才可升级 `ACCEPTED`。

## 替代方案与不采纳原因

- **仅两段 TLS**：不是 E2EE，拒绝。
- **内层直接 QUIC 通过透明 UDP Relay**：理论上可行，但 TURN-like UDP 转发、Android socket protect 和 TCP fallback 成本高，留作单独性能优化。
- **自制 Noise+Mux**：审查范围更大，首版不作为默认。

关联测试：`E2EE-01`, `TLS-ID-01`, `CTRL-QOS-01`。