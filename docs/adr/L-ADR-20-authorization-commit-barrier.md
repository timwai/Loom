# L-ADR-20：Owner 授权事务提交与会话准入屏障

> 产品：Loom Rust Peer Mesh
> 版本：v1.1 设计候选 · 2026-10-17
> 状态：**PROPOSED / NOT FROZEN**（需要 Rust PoC、跨端测试与安全审查，非实施完成）
> 源自：`loom-rust-peer-mesh-architecture-review-v1.0.md`；主设计 `loom-rust-peer-mesh-architecture-v1.1.md`

## 问题与攻击面

前版“DB COMMIT → 更新内存 policy epoch”的两个动作并非原子；进程崩溃或提交后读回失败，会留下旧缓存和已打开会话。原 RelayProxy 已在静态审查中发现 Grant CRUD 的 DB 提交/回调分离（此事实不等于已证实线上攻击）。

## 候选决定

采用 `(space_id,resource_id)` 互斥 **AdmissionBarrier** + 一个 DB writer actor。锁次序 Space → Resource → Session，避免死锁。授权/撤销事件的持久化与内存发布由同一协调器保证：

1. 获取准入屏障，阻止新 ServiceOpen 判定；检查当前 State 是否 `READY`。
2. 在 DB actor 的 `BEGIN IMMEDIATE` 事务校验 `expected_epoch`，同时写签名 OwnerEvent、policy_epoch+1、撤销证据、critical_outbox 和 audit；提交时日志同步等级、IO failure 必须明示。
3. COMMIT 成功且屏障仍持有时更新内存 materialized ACL/epoch，将受影响 session CancellationToken 标记 cancelled；新 ServiceOpen 读取与数据库一致的 epoch 和撤销视图。
4. 解除准入屏障后异步 close socket 和发送持久 outbox；网络推送失败不影响 Owner 本地拒绝。
5. COMMIT 状态未知、DB 读失败、内存发布失败一律 `ADMISSION_PAUSED`；重查 SQLite 与独立 anti-rollback anchor 以后恢复，不从旧缓存回答允许。

## SessionOpen 的线性化语义

- Owner 的 `PolicyCommit(N)` 一旦持久成功，后续成功的新 `SessionOpen` 必须绑定 `AuthorizedEpoch>=N`；并发但先完成授权的旧流必须接收取消。
- 文件写、RDP 控制、私网出口检查每次高危操作的 token；每个流在开始/续传/重绑定时重新检查 grant epoch。
- 本机初始指标（非网络分区全网指标）：撤销提交后高危流目标 1 秒内停止新业务写入，p99 2 秒内关闭；只有真实故障注入可证明此数字。
- 重启顺序：先加载密钥/独立锚，恢复 DB/outbox/cancellations，**最后**启动网络监听。

## 数据与代码边界

`loom-policy` 负责授权决策及 permit 创建，`loom-store` 的单 actor 负责事务；任何业务不能直接更新其授权表。锁和数据库事务不得跨远程网络 RPC；不得在 Tokio 核心线程直接执行阻塞 rusqlite I/O。

## 测试及停止条件

`AUTHZ-RACE-01`、`AUTHZ-CRASH-02`：随机化任意准入和提交交错、并发打开 1000 streams、kill -9、磁盘满、SQLite BUSY、COMMIT 成功但调用者读回失败、掉电模拟、缓存发布错误及 DB 恢复。若有旧 epoch 新会话成功/重启后旧 Grant 复活，禁止继续高危 Service 实现。关联 L-ADR-21。