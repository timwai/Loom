# L-ADR-22：本地用户、Space 角色和操作系统特权分离

> 产品：Loom Rust Peer Mesh
> 版本：v1.1 设计候选 · 2026-10-17
> 状态：**PROPOSED / NOT FROZEN**（需要 Rust PoC、跨端测试与安全审查，非实施完成）
> 源自：`loom-rust-peer-mesh-architecture-review-v1.0.md`；主设计 `loom-rust-peer-mesh-architecture-v1.1.md`

## 目标

UI、Browser Bridge、CLI、daemon/service 和 privileged helper 都应遵循最小权限；本地同一个 OS 用户不能自动管理其加入的所有 Space，也不能仅凭 loopback Socket 就获系统代理/密钥导出权限。

## 主体与权限

- `LocalUserPrincipal {uid_or_sid, login_session, elevated, app_instance}` 由 OS IPC 连接凭证**生成**，不信任客户端自报字段。
- `SpacePrincipal {space_id, membership_epoch, roles, writer_delegation}` 来自经过验证的空间凭证。
- `ResourcePrincipal {owner_peer, resource_id, authorized_actions, epoch}` 来自资源 Owner 当前授权。
- 对变更操作：`LocalAllow = local_user ∧ space_role ∧ resource_owner ∧ required_os_privilege`；只读命令可按单独 ACL 精简，禁止将这一公式当作所有读操作都可放宽的默认授权。

## 进程和 IPC

- Unix domain socket 用 SO_PEERCRED/等效接口以及文件权限；Windows Named Pipe 用 ACL 与客户端 Token/SID 检查/模拟身份；Local Web UI 必须有短时本地会话 + CSRF/Origin 保护。
- Tauri 2 `capabilities` 与 `commands` 使用严格 allowlist、每 window 分开；不可将所有导出 Rust command 默认开放到任意 WebView；禁止远程内容自动继承高权 window ACL。Daemon 二次鉴权不可省略。
- 特权 helper 独立进程，仅暴露 TUN/WinDivert/firewall/route 生命周期所需精确命令。不允许任意脚本执行、任意文件路径或任意根私钥操作。
- `export_private_key`、打开公网 RDP/文件写共享、Space 管理委托、系统网络 hook 需要额外短时用户确认/OS 提权；审计但不得输出敏感原文。
- 事件源按 Space 使用独立 cursor；切换空间注销旧订阅并清理缓存；所有 mutation 有幂等键和 expected_epoch。

## 必须跑的攻击用例

`IPC-01`：其他本机账户/恶意网页/被攻击 Tauri WebView/伪造 localhost Header/浏览器扩展尝试修改 Space、导出密钥、关闭防火墙与 RDP ingress，均拒绝并有审计。Windows UAC/Service ACL、Linux systemd 账户隔离、macOS launchd 权限各自单独测。