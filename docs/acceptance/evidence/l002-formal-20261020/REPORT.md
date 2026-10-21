# L-002 正式验收：本机 / Docker

2026-10-21，Asia/Shanghai。结论：**FAILED / NO-GO，正式验收未通过，发布继续 BLOCKED。** 按用户指定，仅使用本机 macOS 与 Linux Docker。执行环境的限定不构成对正式安全要求的豁免。

验收对象为 PR [#42](https://github.com/timwai/Loom/pull/42) 的运行时代码 `36cfc55957659a451e26190a8186ddbe1a744ca7`（功能实现提交 `e5e757d0ac9e4c7d3272f94f01c4a0bb37544fd8`）。L-001 合并时将 `rustls-webpki` 从 0.103.15 升至 0.103.16，以修复依赖策略 CI 报出的安全公告；之后在合并后的 L-002 源码上重新执行全量回归与正式回滚探针。运行时功能代码未改动。完整源文件哈希见 [本轮全量回归摘要](lab/summary.json)，机器结论和归档哈希见 [正式验收摘要](summary.json)。没有填写独立审查签字。

## 执行结果

| 检查 | macOS | Linux Docker | 结论 |
|---|---|---|---|
| 工作区 / all-targets / experimental-lan | 282 项通过 | 282 项通过 | PASS |
| 格式、严格 Clippy、构建 | 通过 | 通过 | PASS |
| 授权与撤销各 3 个 SIGKILL 切点 | 6 个通过 | 6 个通过 | PASS；进程强杀，不是物理断电 |
| TLS 文件快照、越权/写入拒绝、撤销、重新授权、重启 | 通过 | 两个容器 internal LAN 通过 | PASS；单机实验 |
| 已提交撤销后普通重启 | 拒绝读取 | 拒绝读取 | PASS |
| 只恢复旧策略库 | 拒绝读取 | 拒绝读取 | PASS |
| 只恢复一个旧 Witness 库 | 拒绝读取 | 拒绝读取 | PASS |
| 同时恢复旧策略库和两个 Witness 库后重启 | **读取成功，54 字节** | **读取成功，54 字节** | **FAIL：FORMAL-ROLLBACK-ALL** |
| 生产 daemon / ServiceOpen | BootstrapOnly，network_enabled=false | 未启用生产服务 | BLOCKED |
| 独立安全 / 可信状态 / 互操作 / 平台审查 | PR 无 review；L-001 四类签字为空 | 同一候选 | BLOCKED |
| 实际平台部署 | ADB 无连接设备，macOS 有效签名身份为 0；Windows 本轮未提供 | 容器不能证明物理部署 | BLOCKED；按用户要求未等待外部设备 |

TLS 中继扫描 3389 字节未发现明文 canary。本轮撤销后下一次 read/open 拒绝采样耗时见 `lab/summary.json`；这是小文件单次观察，不是 p99 或生产会话终止时限验收。

## 阻断复现：FORMAL-ROLLBACK-ALL

操作使用新建私有实验目录和公开 fixture 身份，只监听 loopback。每一步结束进程并关闭 SQLite 连接后才复制数据库：

1. init，Owner grant；三个日志均为 sequence=1，TLS 读出原始 54 字节文件。备份三个日志。
2. Owner revoke；三个日志均为 sequence=2，普通重启拒绝。保留已撤销副本。
3. 只恢复旧 policy，读取被拒绝；恢复撤销副本后只恢复旧 witness-a，读取也被拒绝。
4. 同时恢复三个 sequence=1 日志；不改时钟、不重新授权、不注入签名、不重用旧网络响应。
5. 新进程执行真实 TLS open/read。候选内部重新生成随机 nonce，两个本地 Witness 对恢复的旧状态重新签名；两个平台都成功读出完整测试文件。

期望 `observed_allow=false`，实际 `observed_allow=true`，探针正确以 **exit 1** 结束。它不是“预期漏洞存在所以测试通过”。数据摘要为 `49093611c45456773fa3012dbb2104fe503394c7729e27135efbb2cb4ed555e3`；内容仅为测试 canary。

原始 [macOS 摘要](rollback-host/summary.json)、[TLS 事件](rollback-host/events.json)、[Linux 摘要](rollback-linux/summary.json)、[TLS 事件](rollback-linux/events.json) 和各自 `logs/` 均归档。本轮没有把私钥、证书或 SQLite 镜像加入归档，探针的运行目录和备份已清除。实验容器 / 网络已清理，原有 postgres 容器保留。

根因位于现有实验部署的信任边界：`examples/support/l002_fixture.rs` 的两个 Witness 从同目录 SQLite 读状态并在本进程使用公开测试密钥签名。`lan_read.rs::fresh_history` 验证 nonce、签名和日志一致性，能够拒绝旧响应重放，却没有安装目录之外的高水位证据；三个持久状态共同回滚后仍相互一致。本结果确认此前已声明的正式发布限制，并非绕过了已宣称具备独立信任的生产实现。

## 其他未满足项

`SignedMembershipVerifier::pause` 的成员锁与 `LanReadCandidate` 的策略 / SQLite 屏障独立，最终成员检查结束至复制 chunk 之间不持有成员撤销屏障。本轮已有测试证明“外部观察期间 pause”会拒绝，不能据此声称全局原子撤销。这里是源码核查发现的覆盖缺口，没有伪造竞态复现或关闭时限数据。

正常 `PeerCore` 仍固定 BootstrapOnly / DenyAll，没有生产 AdmissionPermit 或强制跨设备 writer；同步 SQLite / 签名仍用于实验执行器。新 append / pull 格式也未获得最终互操作或独立安全审批。本轮 [CI 快照](ci-candidate.json) 的绿色状态只支持已有工程检查，不代表上述项目通过。[前置检查日志](preflight/) 保存正式发布门禁 exit 1、L-001 九项门禁与四类签字的未完成列表，以及实际环境和 PR review 快照。

结构核查按 codebase-memory skill 尝试连接索引；CLI 30 秒后报告 daemon 无法接受客户端，无法获得图索引覆盖证明。本轮使用有界源码读取与检索核对 `loom-core`、`SignedMembershipVerifier`、实验 Witness 和 `loomd` 入口，不将图查询失败写为“没有依赖”。

## 复验

在源码目录构建并执行本机探针，使用一个不存在的输出目录：

```sh
cargo build -p loom-core --example l002_lan_lab --features experimental-lan --locked
python3 docs/acceptance/evidence/l002-formal-20261020/reproduce.py \
  --output target/l002-formal-new-host
# 当前候选：exit 1，FORMAL ROLLBACK: FAILED
```

完整本机 / Docker 回归由 `python3 scripts/l002_acceptance.py --output target/l002-new-lab` 执行。Linux 回滚探针使用相同脚本和已有 `loom-l001-target` 中的 Linux 二进制，在 `--network none`、无端口发布的资源受限临时容器内运行；实际命令见 [执行记录](execution.json)。Docker 镜像仍使用现有 `loom-l001-lab:local`；候选二进制由更新后的锁文件构建，包含 `rustls-webpki 0.103.16`。

```sh
python3 scripts/l002_gate.py --require-lab       # exit 0：实验及正式证据一致，并非正式通过
python3 scripts/l002_gate.py --require-formal    # exit 1：正式要求有失败 / 阻塞
python3 scripts/l002_gate.py --require-release   # exit 1：生产发布未批准
```

新增门禁核对正式摘要及完整归档哈希、要求集合、两个平台实际允许 / 拒绝结果与派生状态，并从 TLS 事件重新核对五组 open/read 响应、字节数与内容摘要。篡改拒绝检查见 [门禁反例](gate-negative-checks.json)，可用 `python3 docs/acceptance/evidence/l002-formal-20261020/gate_negative.py` 在临时副本复验。仅改状态、重算摘要后声称通过、将已成功读取改报为拒绝，均须被门禁拒绝。这些哈希提供一致性检查，不提供独立审查人签名。

## 进入下一轮的条件

1. 实现不与应用备份共同回滚的外部高水位来源、独立 Witness 登记 / 认证 / 密钥轮换与恢复。可以先用 Docker 独立进程及独立卷验证协议、分叉、掉线和应用备份恢复；同一宿主机整体回滚的生产保证仍需额外信任来源。无需强制 TPM。
2. 完成统一成员 / 策略 / AdmissionPermit 屏障和 writer 参与协议，移出运行时线程上的阻塞存储操作，再做并发撤销、慢 RPC、失败发布和会话关闭时限验收。正式门禁满足前继续关闭生产入口。
3. 冻结并审查新格式，补齐独立签字和实际平台部署证据，再重跑失败项及受影响回归。本轮不把更换 nonce、增加同目录日志或改清单状态作为修复。

验收任务卡：owner=`Codex / Loom workspace`；module=`loom-core::lan_read / loom-store::witness_append / loom-identity::signed_membership / apps/loomd`；test_id=`FORMAL-ROLLBACK-ALL`；rollback_strategy=`维持 experimental-lan 显式启用及生产入口关闭，保留签名历史与 fork 证据`；review_signoff=`未签署`。正式验收过程已执行并记录，L-002 通过目标尚未达成。
