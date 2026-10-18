# L-ADR-23：Android、Windows、macOS 网络能力 P0 前置验证

> 产品：Loom Rust Peer Mesh
> 版本：v1.1 设计候选 · 2026-10-17
> 状态：**PROPOSED / NOT FROZEN**（需要 Rust PoC、跨端测试与安全审查，非实施完成）
> 源自：`loom-rust-peer-mesh-architecture-review-v1.0.md`；主设计 `loom-rust-peer-mesh-architecture-v1.1.md`

## 设计动机

全量 Rust 内核仍必须尊重 OS 控制网络和进程生命周期的 API。Android VpnService/Socket.protect、Windows WinDivert、macOS entitlement 决定 ProtectedSocketFactory 与 daemon/privileged helper 的结构，不能放在后期才发现不可用。

## P0 平台工作包

### Android

1. Kotlin `VpnService` 建立 TUN，获得 fd 和生命周期状态。
2. Rust 建立底层 UDP socket；在 Quinn 首次 DNS/路由/连接 I/O **之前**通过 JNI `VpnService.protect(fd)`；所有创建的直连 socket 必须经过 factory 而非私下 `std::net::UdpSocket::bind`。
3. 验证 fd ownership（dup/close/transfer）、VPN 重启、网络变化、IPv4/IPv6、Android 后台限制和 TUN 数据回环。
4. `protect()` 返回 false 时失败关闭对应出口，保持 UI 显示 unsupported/error。

### Windows

1. Rust daemon/Windows Service + Tauri shell + 最小 WinDivert helper 完成端到端数据流。
2. 真机验证用户态访问、UAC、托盘退出、后台保持/完全停止、文件名任意改名、快速重启以及过滤器卸载。
3. 多网络软件共存时不得任意删除非 Loom 创建的 WinDivert 资源；测试系统代理/防火墙恢复。

### macOS

1. 无 entitlement：验证 SOCKS5/HTTP 及系统代理、launchd 生命周期、Keychain 可用范围，明确透明捕获 unavailable。
2. 有 entitlement：额外实测允许的 NetworkExtension/PacketTunnel 路径及签名部署；不假设本地个人测试无需授权即可分发。

### Linux 与 iOS

Linux 最小 TUN/nftables/systemd/无 GUI 启动路径；iOS 列为 optional target，若没有开发者资格与 entitlement，不作为首批透明 VPN 交付承诺。

## 输出和门禁

每个 Spike 交付最小编译运行代码、真机环境/版本/权限清单、失败日志（脱敏）、占用资源/功耗指标、功能降级 UX、PoC PR；任何失败只阻断该平台受限功能，不应阻断无特权 CLI/headless 核心。关联 `PLATFORM-ANDROID-01`, `PLATFORM-WIN-01`, `PLATFORM-MAC-01`。