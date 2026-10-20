# L-002 隔离 LAN 实验验收报告

日期：2026-10-20（Asia/Shanghai）。结论：**`L-002-isolated-lab-v1` 实验验收通过；正式 L-002 发布验收 BLOCKED。** `loomd`、生产 ServiceOpen 和默认资源准入保持关闭。

## 实现与身份

本轮将 L-002A–C 的模型推进为可执行候选：Root 绑定的 Owner 签名只读 ACL、Witness 认证追加/持久 CAS、分叉隔离，以及实际 TCP/TLS 文件快照读取和撤销。实现分支 `codex/l002-authenticated-lan-acceptance`；验收基线 `e9fe4a5` 加本轮工作树。

[summary.json](summary.json) 的 `source_sha256` 覆盖所有当前 Rust 源码、Cargo 清单/锁文件、脚本和 CI，含新增文件。验收门禁同时核对文件清单、源码哈希、摘要哈希和日志哈希。原始工作树差异在 [source-diff.log](logs/source-diff.log)。这些内容是本轮被测试代码的身份，不能把基线提交本身误当作已经包含新增实现。

| 项目 | 实测结果 | 原始证据 |
|---|---|---|
| macOS ARM64、Rust 1.90.0 | 282 项通过，0 失败；包含 14 项新增测试 | [host-tests.log](logs/host-tests.log) |
| Linux ARM64、OrbStack 7.2.9、Rust 1.90.0 | 282 项通过，0 失败 | [linux-tests.log](logs/linux-tests.log) |
| 格式与严格 Clippy | 两 OS 通过；`-D warnings` | [format](logs/format.log)、[macOS](logs/host-clippy.log)、[Linux](logs/linux-clippy.log) |
| macOS 授权/撤销 SIGKILL | 各三处切点，共六例通过 | [事件记录](events.json)、[状态与命令日志](logs/) |
| Linux 授权/撤销 SIGKILL | 同六例通过 | [独立 Linux 摘要](linux-runtime/summary.json)、[事件记录](linux-runtime/events.json) |
| 两容器不同网络命名空间、Docker internal LAN | 真实 mTLS，文件 54 字节逐块一致；错误资源、写操作、零/超限块全部拒绝 | [LAN 客户端](logs/linux-lan-full-read-client.log)、[事件记录](events.json) |
| 不可信 TCP 转发器 | 转发 3389 字节 TLS 流量，未出现文件明文 canary | `cases.host-tcp-full-read-encrypted-bearer`，见 [摘要](summary.json) |
| 撤销、重新授权与新进程 | 后续块/新打开拒绝；重新授权仍拒绝旧会话，新会话可读 | [macOS 服务端](logs/host-tcp-revocation-server.log)、[Linux 服务端](logs/linux-lan-revocation-server.log) |
| 服务端容器 SIGKILL + 重启 | 已撤销授权未复活，打开拒绝 | [kill](logs/server-container-kill.log)、[restart](logs/server-container-restart.log)、[拒绝](logs/linux-container-restart-deny-server.log) |

日志中的 `post_revoke_refusal_s` 为撤销命令完成后，下一块读取及再次打开被拒绝的合计观测：本轮 macOS **0.012 秒**、容器 LAN **0.174 秒**。这是单次小文件实验，不能推导 p99、1000 流负载或跨网分区上界。

Docker 实验复用了现有镜像 `sha256:6d2c134734e33a398b3e6b7cb5e1ac781eb8f15e268da68813bd3f905692468e`，新建带资源限制的构建/Peer 容器和 internal 网络，不发布端口。实验结束已清理本轮创建的容器/网络。运行时私钥、证书和数据库保留在忽略的 `target/` 中，未归档到本报告。

## 安全语义与故障结果

- 追加签名覆盖 Root 清单承诺、前驱、代数、Peer、TLS key epoch、member epoch、只读允许位和有效期。每次读取/追加均完整重放签名历史。签名篡改、错误清单、前驱冲突、缺失/损坏数据库拒绝。
- 一个 Owner 对同一前驱签名两个不同分支时，持久保存两份签名证据，并隔离读取、追加和 Witness 观察；重启不能自动选择分支。
- `before-insert` 和 `after-insert` 被杀恢复先前状态；`after-commit` 被杀保留已提交状态。失去应答后重试完全相同的签名字节不重复追加。所有授权与撤销切点均验证了部分 Witness 成功时拒绝，完成同一请求后得到确定结果。
- 新鲜 nonce 由 OS CSPRNG 在每次打开/每块读取内部产生，不接受调用者指定的复用 challenge。两个 Root 选定 Witness 必须对同一 nonce 和完整状态一致签名。旧回复、一个节点离线、分裂状态和本地旧库恢复拒绝。
- 文件在本地 Owner 交付打开句柄后生成有界不可变快照。网络只接收资源 ID，路径或符号链接替换不改变快照。块大小最大 4096 字节；不提供写入接口。
- 外部 Witness 回调不持有本地数据库事务。回调后重新验证成员和策略；最终复制块在 SQLite 读事务内完成，同库其他连接的撤销不能在复制期间提交。任何策略更新使旧会话失效；已经释放到 TLS/内核缓冲区的字节无法收回。
- 过期撤销仍参与历史重放；过期的新授权拒绝。成员密钥/成员 epoch 变化必须重新签名 Owner 授权；旧凭据和旧会话不能沿用。

## 复现和门禁

从仓库根目录运行：

```sh
python3 scripts/l002_acceptance.py
python3 scripts/l002_gate.py --require-lab
python3 scripts/l002_gate.py --require-release
```

完整运行需要 Docker 与 `loom-l001-lab:local` 镜像；构建方法及 `--host-only` 子集见 [L-002E](../../../spikes/l-002e-lan-file-read-acceptance.md)。最后一条命令应返回 **1**。更改受验收代码后旧证据必须失效；不能仅修改清单状态复用旧测试。

本轮另通过默认功能的 268 项回归、带实验功能的 API 文档构建、L-001 真实性门禁和默认 `loomd` 无监听检查。CI 已加入实验功能测试、跨平台运行及 L-002 证据门禁；远端 CI 结果另行记录，不能把本地结果写成远端或独立审查结果。

## 正式验收仍未通过的项目

1. **独立 Witness 与密钥信任**：当前日志与公开实验签名器位于同一主机/实验挂载中，Witness 回调访问本地 SQLite；没有独立托管的远程 Witness、真实 Root/密钥登记、受保护密钥、跨设备轮换及独立防回滚高水位。三份 SQLite 同时恢复时不能检测全体回滚。FULL/fsync 和 SIGKILL 不能证明真实掉电持久性。
2. **生产准入**：候选只读 ACL 格式与既有 L-001 生命周期日志分离，未实现生产 `AdmissionPermit`、全写者强制跨设备参与、全局成员撤销/策略屏障或生产异步调度。实验同步存储操作不能直接照搬到 Tokio 主线程。
3. **独立审查**：新追加/拉取格式未冻结，安全、互操作、可信状态等独立签字仍缺失。未因本轮测试而填写 L-001 的九项正式安全/平台门禁或四类签字。
4. **物理平台与部署**：两个容器是一个主机上的不同网络命名空间，不是两台物理设备；Android/Windows/macOS 的生产安装和 OS 能力验收仍需独立证据。现有 Server 不得据此下线。

任务卡：owner=`Codex / Loom workspace`；commit_sha=`e9fe4a5`（基线，新增实现以摘要中完整 source_sha256 为准）；module=`loom-store::witness_append / loom-core::lan_read / loom-transport::secure_channel`；test_id=`L002-OWNER-APPEND / L002-WITNESS-PARTIAL / L002-FORK-QUARANTINE / L002-TLS-FILE / L002-REVOKE-RESTART / L002-CRASH-GRANT-REVOKE`；evidence_url=`本报告及 summary.json`；rollback_strategy=`关闭 experimental-lan，保留日志和分叉证据，不删除/重建已登记日志`；blocker=`上述四组`；review_signoff=`未签署`。
