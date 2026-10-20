# Loom v1.1 评审整改跟踪与安全门禁

> 基线：2026-10-17 原 v1.0 评审；本表的“设计已补充”**不等于任何测试通过**。
> 本表保留 2026-10-17 的历史设计评审基线，不代表当前实施进度。最新本机与 Docker 证据见 [L-001 实测报告](acceptance/evidence/l001-local-docker-20261019/REPORT.md)，正式门禁仍未通过。基线时所有行均未完成实施验证。`candidate_only` 表示重要协议选择尚待 P0 比较、验签向量和正式签字。

| 项目 | P0 | P1 | P2 | 结论 |
|---|---:|---:|---:|---|
| 已形成设计回应 | 8 | 9 | 4 | 均待复核并签字 |
| 基线时实际实施/跑测完成 | 0 | 0 | 0 | 2026-10-17 的历史统计，不是当前测试状态 |

## 21 条跟踪映射

| 编号 | 等级 | 设计位置 | 测试门禁 | 状态 |
|---|---|---|---|---|
| R01 | P0 | §12.4 / ADR19 | `E2EE-01` | design_addressed |
| R02 | P0 | §8.4 / ADR20 | `AUTHZ-RACE-01;AUTHZ-CRASH-02` | design_addressed |
| R03 | P0 | §10.5 / ADR07 | `WIRE-01` | candidate_only |
| R04 | P0 | §7.5 / ADR21 | `ROLLBACK-01` | design_addressed |
| R05 | P0 | §7.4 | `ROLE-01` | design_addressed |
| R06 | P0 | §11.4 | `TLS-ID-01` | design_addressed |
| R07 | P0 | §18.5 / ADR22 | `IPC-01` | design_addressed |
| R08 | P0 | §20.1 / ADR23 | `PLATFORM-ANDROID-01;PLATFORM-WIN-01;PLATFORM-MAC-01` | plan_only |
| R09 | P1 | §9.4 | `LEDGER-FORK-01` | design_addressed |
| R10 | P1 | §9.4 | `ACK-GC-01` | design_addressed |
| R11 | P1 | §12.4 | `CTRL-QOS-01` | design_addressed |
| R12 | P1 | §11.4 / 18.5 | `SPACE-LEAK-01` | design_addressed |
| R13 | P1 | §13.4 | `DNS-LEAK-01` | design_addressed |
| R14 | P1 | §14.4 | `FILE-RACE-01` | design_addressed |
| R15 | P1 | §15.2 | `RDP-IP-01` | design_addressed |
| R16 | P1 | §16.2 | `BROWSER-BRIDGE-01` | design_addressed |
| R17 | P1 | §22.4 | `LEGACY-01` | design_addressed |
| R18 | P2 | §4 | `WORKSPACE-01` | existing_design |
| R19 | P2 | §18.5 | `LOCAL-EVENTS-01` | design_addressed |
| R20 | P2 | §12.4 / 24.4 | `PERF-GO-01` | design_addressed |
| R21 | P2 | §25.2 | `MILESTONE-01` | design_addressed |

## 正式冻结条件

1. L-ADR-07 与 L-ADR-19～23 的相关 threat model、实现对照和测试报告已审核签字。
2. Wire bytes 至少 Rust/Go/Kotlin/JS 一致，所有负向向量同拒绝。
3. 恶意 Relay 没有业务明文读取能力；直接、Relay、TCP fallback 都绑定内层 PeerId/Space。
4. SQLite commit/cancel/outbox/anchor 的竞态、进程崩溃、全库备份回滚用例通过。
5. Android/Windows/macOS P0 实机 Spike 输出可交付范围；不满足 entitlement 的功能明确降级。
6. 旧 RelayProxy 仍保持正常运行；默认不切换系统代理/过滤驱动。

## 2026-10-17 历史 Release Gate

`DESIGN_ONLY / SECURITY_PROTOCOL_NOT_FROZEN / NO_RUST_BUILD / NO_CROSS_PLATFORM_POC / MAIN_NOT_TOUCHED`。
当前状态：L-001 PoC 工程已整合，本机与 Docker 实验已完成；生产发布门禁仍为 `BLOCKED / NO_SERVICE_OPEN`。参见 [机器可读验收清单](acceptance/l001.json)。

2026-10-20 补充：[JP Android Docker 实验](acceptance/evidence/l001-android-jp-20261020/REPORT.md)在容器重启后通过 248 项原生测试及独立 VPN API 调试 APK 五项检查。生产 Rust/JNI VPN、完整泄漏测试与物理设备仍未验收，不据此填写平台或安全审查签字。

2026-10-20 本轮：[现有环境集成验收](acceptance/evidence/l001-integrated-20261020/REPORT.md)中 macOS/Linux/Android 各 268 项通过；真实 Rust JNI 成员签名、TUN 边界及保护后连接的 socket 工厂在容器重启后复验通过。签名成员与 Owner 授权只是候选验证，生产 ServiceOpen、独立防回滚、完整 VPN 转发和真机仍缺失；Windows 暂无环境、macOS 暂无签名条件。本轮不填写四类独立审查签字。

2026-10-20 L-002：[隔离 LAN 实验验收](acceptance/evidence/l002-isolated-lab-20261020/REPORT.md)通过。macOS/Linux 各 282 项测试、每 OS 六处授权/撤销 SIGKILL、容器间 TLS 只读文件及撤销后重启拒绝通过。新增持久分叉隔离、逐块新鲜 Witness 检查和 SQLite 跨连接读取屏障。Witness 仍是同机文件且使用公开实验密钥，未实现生产准入或独立防回滚；本轮不填写独立审查签字，正式 L-002 保持 BLOCKED。
