# L-001 本机与 Docker 修复后验收报告

**本轮约定范围：本机 macOS 与本机 Docker。验收完成，`L-001-local-docker-v1 = passed`。**

本地日期：2026-10-20（Asia/Shanghai）；UTC 运行标识：`20261019T160015Z`。正式 L-001 发布清单保持 BLOCKED，九项发布门禁及四项签核均未自动变更。未指定性能阈值，本次测速提供基线。

## 修复内容

1. 新增 `UnifiedPolicyJournal::inspect_challenge_bound_recovery`：在 journal 共享进程锁下重放完整 Root/Owner 签名历史，核对 Outbox/Audit 镜像和撤销摘要，再验证双 Witness 的 challenge 签名响应。Witness 公钥由已验签的 Root 清单取得；本地状态由 journal 计算，调用者不能用原始 high-water 值替代。清单过期、范围错误、旧响应、分歧、缺失签名及本地回退均拒绝。返回私有字段的诊断对象，授权保持暂停。
2. 新增四项 Rust 集成测试，覆盖混合历史、真实有效旧签名前缀、不一致镜像、旧 challenge、缺失/分歧 Witness、伪造签名、错误 Root、过期清单与 generation 下限。首轮测试夹具重复取消同一委托而失败，改用合法签名历史后通过；未放宽业务校验。
3. 新增本机/Linux 各 10 项进程级恢复实验。两个独立启动的 Witness 子进程各读单独的 SQLite 历史副本并验签，客户端用 Python 系统 CSPRNG 生成 32 字节新 nonce。
4. 增加独立的本地证据校验器，检查必需命令、结果和拒绝分支；不修改正式发布校验器。消除 `--skip-build` 复用旧本机二进制的风险：每次均执行两端增量 release 编译，并在运行前后核对源码及正式发布清单 SHA-256。
5. 保留此前 macOS TPM 辅助代码条件编译修复，双方严格 Clippy 不再报 dead-code；没有降低 lint 要求。

## 验收结果

| 本地检查 | 结果 |
|---|---|
| macOS / Docker Linux Rust workspace | 各 **248 passed / 0 failed** |
| 格式、双方严格 Clippy、Linux API 文档 | 通过 |
| Rust / Go / JavaScript / Kotlin 既有向量 | 通过 |
| 四条真实 TCP + mTLS 通道、完整 payload 核对 | 通过，实验客户端确认 TLS 1.3 |
| 错误 pin、客户端、Space、epoch、成员关系 | **20/20 拒绝** |
| Relay 明文 canary 与主动篡改 | canary 未检出，篡改后认证回显拒绝 |
| 本机/容器内写进程 SIGKILL 恢复 | **6/6**，已确认前缀保留、镜像匹配、SQLite 完整 |
| 整 Docker 写进程容器 SIGKILL 恢复 | **3/3**，已确认前缀保留，授权暂停 |
| 新鲜双 Witness 恢复实验 | **20/20**（每端 2 个成功诊断 + 8 个预期拒绝） |
| 本地证据校验器的负向回归 | **7/7 拒绝**缺证据、失败、伪造状态或非法样本 |
| 源码一致性、无 TPM 拒绝、daemon 网络关闭 | 通过 |
| 正式发布严格模式 | 退出 1，正确维持拒绝 |

两个环境均实际执行以下恢复场景：

| 场景 | 预期及实际结果 |
|---|---|
| Peer 与两个 Witness 均为当前签名历史 seq=8 | 诊断成功，授权暂停 |
| 仅 Peer 恢复有效旧备份 seq=5，Witness 保持 seq=8 | `LocalRollbackOrFork` |
| 将旧签名响应用于新随机 nonce | `WrongChallenge` |
| 一个 Witness 缺失 | `MissingOrDuplicateWitness` |
| 篡改 Witness 签名 | `InvalidSignature` |
| Witness 分别为 seq=8 与 seq=5 | `SplitWitnesses` |
| 损坏本地签名证据 | 完整重放拒绝 |
| 删除本地 Outbox 行 | 镜像核对拒绝 |
| 损坏 Witness 镜像 | Witness 拒绝签名 |
| 恢复正确历史后用新 nonce 复核 | 诊断成功，授权暂停 |

另运行了重要反例：**同时把 Peer 和两个同机 Witness 文件恢复到 seq=5 后，新鲜响应仍可相互一致。** 因此该实验不具备独立非回滚存储保证。基础 `inspect` 仍只诊断本地签名历史，合法旧备份可通过；要检测仅本地回退必须调用新恢复核对接口并有保持最新历史的 Witness。没有把普通文件、Docker 卷或同机进程登记成生产可信锚。

## 性能复测

采用 release 构建；协议及构建检查完成后串行测速。方向以客户端为准，MiB/s = 2²⁰ bytes/s。

| 客户端 → 服务端 | 建连中位数 / P95 (ms) | 1 KiB 回显 P95 (ms) | 上行中位数 (MiB/s) | 下行中位数 (MiB/s) |
|---|---:|---:|---:|---:|
| macOS → macOS | 1.709 / 2.590 | 0.108 | 2821.8 | 2969.8 |
| macOS → Docker Linux | 1.737 / 3.123 | 0.120 | 2085.1 | 2336.2 |
| Docker Linux → Docker Linux | 0.515 / 0.708 | 0.017 | 3512.8 | 2615.8 |
| Docker Linux → macOS | 4.567 / 5.663 | 0.220 | 2738.3 | 2222.9 |

建连预热 5 次后取 50 次，包含 fixture 文件读取和 TLS 配置；回显预热 20 次后取 200 次。每方向 32 MiB 预热一次、实测五次，上传等待接收端确认。8 通道的单次聚合样本也保存在原始数据中，不作为稳定容量上限。

| SQLite 操作 | macOS 中位数 / P95 (ms) | Docker Linux 中位数 / P95 (ms) |
|---|---:|---:|
| 增长历史逐条 append（100 条） | 6.011 / 9.930 | 7.234 / 12.150 |
| 重放完整 100 条签名历史 | 10.352 / 10.596 | 11.370 / 11.528 |

每次 append 都完整验签重放历史，100 个 append 样本的历史长度不同；inspect 为 20 次完整重放。编解码及签名操作的 10 批均值见原始样本，不能解释成逐请求尾延迟。未测 WAN、磁盘文件传输、真实服务或与 Go 服务的对比。

整容器强杀结果（Docker kill 请求到达前可能继续写入，所以恢复数可以高于最后读取的 ACK）：

| ACK 下界 | 重启恢复条数 | 容器退出码 |
|---|---:|---:|
| 10 | 19 | 137 |
| 25 | 32 | 137 |
| 50 | 53 | 137 |

## 环境、证据和复跑

- macOS ARM64，Mac16,10，10 核、16 GiB；Docker/OrbStack Linux ARM64。构建容器 4 CPU / 4 GiB，Peer 容器 2 CPU / 512 MiB / 128 PID。主机 APFS 与 Docker 原生卷并非等价存储条件。
- Rust 1.90.0；镜像、Go/Node/JDK/Kotlin 的实际版本及资源见 [环境与命令原始记录](results.json)、[工具链日志](logs/linux-toolchains.log) 与 [镜像构建日志](logs/docker-build-lab.log)。
- 代码基线为 `498870abff9b7fede983b9ef59b0aa7132520ca4` 加当前 `codex/l001-local-docker-validation` 分支的未提交修复与工具，不是原始 main。所有实验源码和正式发布清单的 SHA-256 已在运行结束逐项核对；文档报告在实验完成后归档。
- [本地验收判定](local-acceptance.json)、[完整命令与原始采样](results.json)、[CSV 样本](samples.csv)、[验收器负向回归](logs/local-gate-negative-regression.json)、[证据文件校验和](SHA256SUMS.json)。
- 本轮临时容器、网络、监听器与 TLS 私钥已清理；原有 postgres 容器保持运行，构建镜像/缓存保留。

```sh
python3 scripts/l001_local_docker.py
python3 scripts/l001_local_gate.py docs/acceptance/evidence/l001-local-docker-20261020/results.json
```

## 保留的正式发布限制

此诊断接口仍依赖调用者提供新鲜、不可预测、单次使用的 nonce；未实现生产 challenge 生命周期、认证 Witness append、可信服务登记或跨主机独立密钥保管。实验使用公开确定性测试密钥、逻辑时间、固定范围实验 envelope；Witness 文件通过夹具构建，未实现生产同步协议。

成功结果仅描述一次重放快照。进程锁不阻止其他 SQLite 进程在检查后写入，不授予后续 ServiceOpen。SIGKILL 不证明物理掉电语义。成员关系仍是 fixture allowlist，daemon 仍关闭网络；Android 真机、Windows 驱动、macOS 签名扩展、独立可信后端及四项独立签核均属于正式清单的剩余工作。本地验收通过不改变正式 `L-001 = BLOCKED`。
