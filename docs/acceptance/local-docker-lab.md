# L-001 本机与 Docker 测速、验收实验

本实验为 L-001 增加可以复跑的真实进程、TCP 和 SQLite 证据。`docs/acceptance/l001.json` 仍是正式发布验收清单；实验成功不会自动通过其中任一门禁，也不生成任何人工签核。

## 复跑

需要本机 Rust 1.90、Python 3、Go、Node.js 以及可用的 Docker。容器使用固定摘要的 Rust 1.90 与 Go 1.23 镜像，安装 Linux 构建工具、Node.js、JDK 和 Kotlin。编译期间需访问镜像及软件包源。

```sh
python3 scripts/l001_local_docker.py
```

结果位于 `target/l001-local-docker/<UTC时间>/results.json`，同目录 `logs/` 保存完整命令输出。数据包括代码基线提交、参与实验的源码 SHA-256、工具链、主机/容器资源限制、原始采样及命令返回码。该目录被 Git 忽略；经过核对的报告和数据另存入 `docs/acceptance/evidence/`。

已经准备好依赖和挂载的专用实验容器可以用 `--builder-container NAME` 复用；该容器必须将当前仓库挂载到 `/workspace`，并将专用的 `loom-l001-target` 卷挂载到 `/build`，设置 `CARGO_TARGET_DIR=/build`。每次均执行本机与 Linux 的增量 release 编译，确保二进制对应当前源码；`--skip-build` 仅保留为兼容参数，已不再跳过编译。全部源码及发布清单在运行前后核对 SHA-256，运行中发生变化即拒绝本地验收。

## 本地验收判定

用户确认的本轮范围是本机与 Docker。该范围使用独立的 `L-001-local-docker-v1` 实验配置，完成后 `results.json` 中的 `local_acceptance.state` 必须为 `passed`。可以独立复核：

```sh
python3 scripts/l001_local_gate.py target/l001-local-docker/<UTC时间>/results.json
```

该校验要求构建、测试、严格 lint、跨语言向量、四条真实通道及 20 项拒绝、Relay 探针、9 次强杀恢复、20 项新鲜 Witness 恢复实验与有效测速样本全部完成。缺少证据、出现失败、源码变化或把本地实验冒充正式发布，均返回失败。通过代表本地功能与证据完整，不是独立安全审查或性能 SLO 签核。

最近一次修复后复验见 [2026-10-20 报告](evidence/l001-local-docker-20261020/REPORT.md)。

所有网络和存储入口都在显式调用的 Cargo examples 中，正常 `loomd` 不包含实验监听器。临时证书随机生成并限制文件权限，成员关系仅用实验 allowlist；没有签名成员注册、Owner 资源授权或 ServiceOpen。主机实验监听器临时绑定通配地址以允许容器访问；容器发布端口仅绑定主机回环地址。实验结束自动移除本次的监听进程、Peer 容器、网络和私钥。只保留编译缓存卷、构建镜像及输出证据，不修改现有容器、系统代理、VPN 或驱动。

## 实验内容

- macOS 和 Linux ARM64 的完整 Rust 测试、格式、严格 Clippy；Linux API 文档生成。
- Rust/Go/JavaScript/Kotlin 的现有 canonical CBOR 与签名输入向量；Go/JavaScript 的原始 Ed25519 向量。
- `loomd` 两端均维持 `BootstrapOnly / network_enabled=false`；无可用 TPM 时探测明确拒绝；发布门禁严格模式必须返回拒绝。
- 本机→本机、本机→Linux 容器、Linux 容器→容器、Linux 容器→本机，运行实际 TCP + 现有 `SecurePeerChannel` mTLS，检查协商版本为 TLS 1.3。
- 每条路径拒绝错误服务端证书 pin、未信任客户端、错误 Space、错误 epoch 和被拒绝的成员关系；另验证转发 Relay 不包含已知业务明文、主动改写握手不能建立认证回显。
- 本机与容器内分别在确认 10/25/50 条日志后 `SIGKILL` 写进程，重启签名重放、检查 Outbox、SQLite `integrity_check` 和暂停授权状态；另在相同确认点强杀整个 Docker 写入容器，保留独立 Docker 卷后重新检查。
- 篡改签名证据、删除 Outbox 镜像均须拒绝；恢复旧的、签名仍有效的完整备份，记录本地重放无法独立识别回滚的边界，授权仍须暂停。
- 新增 `inspect_challenge_bound_recovery` 将完整签名历史、Outbox/Audit 一致性和撤销摘要与新鲜双 Witness 响应核对；Witness 公钥从 Root 签名清单取得，本地状态由 journal 自行重放计算。返回值仅为诊断，不修改可信锚或授权状态。
- 本机与 Docker 各运行 10 项恢复实验：两个 Witness 子进程各自读取单独的 SQLite 副本，客户端用系统 CSPRNG 生成新 nonce。完整当前历史和修复后复核须成功；仅回滚本地备份、重放旧响应、缺失 Witness、伪造签名、Witness 分歧、损坏本地签名或镜像、损坏 Witness 镜像均须拒绝。另运行同时回滚三个同机文件的反例，明确不具备独立可信存储保证。

## 测速口径

性能测试统一使用 release 构建，在所有编译和协议校验结束后串行执行。未指定性能阈值时，结果仅建立基线，不声称性能验收通过。

| 指标 | 采样口径 |
|---|---|
| 新连接延迟 | 先预热 5 次，记录 50 次 TCP 建连、证书 fixture 读取、新 TLS 配置和加密关联完成的总耗时；不包含启动客户端进程的时间 |
| 1 KiB 回显 | 已建立通道预热 20 次，记录 200 次往返；计入消息分配及完整内容核对 |
| 单通道吞吐 | 每方向先预热 32 MiB，再记录 5 次 32 MiB；逐块核对实际接收数据，上传等待接收端确认；单位 MiB/s，不是 Mbit/s |
| 8 通道聚合 | 8 条已建立通道同步开始，各上传 8 MiB，共 64 MiB；单次观察，不作为稳定并发容量上限 |
| 编解码 | 256 B、4 KiB、60 KiB payload，预热一个批次后记录 10 批；原始样本是每批平均每操作耗时，分位数不是逐请求尾延迟 |
| 签名证据 | 10 批，每批 100 次构造、签名、编解码、Owner/delegate 双签验证；包含实验密钥对象构造 |
| SQLite append | 连续写入 100 条签名撤销证据，每次 append 均完整重放已有签名历史并提交；记录各条耗时和历史增长，不能解释成固定长度历史的稳态吞吐 |
| SQLite inspect | 对 100 条历史重放 20 次；包含签名和镜像一致性验证 |

容器 Peer 上限为 2 CPU、512 MiB、128 PID，构建容器为 4 CPU、4 GiB。SQLite 容器数据位于 Docker 原生卷；本机数据位于仓库所在 APFS。因此差异同时包含 VM、调度、文件系统、缓存及网络路径影响，不能单独归因于容器或 Rust/Go 性能。

## 正式门禁仍缺少的证据

实际 TCP 实验尚未接入 daemon 的签名成员关系、Owner ACL 和授权提交屏障；Relay 明文探针是有界 smoke test。进程或容器 `SIGKILL` 不能证明物理断电后的落盘顺序。Docker 卷、同机 Witness、普通 SQLite 和软件 TPM 均不能成为独立防回滚可信锚。基础 `inspect` 仍是本地历史诊断；新接口需要调用者提供新鲜、不可预测的单次 challenge，并未实现生产 nonce 生命周期或认证 Witness append 服务。实验固定测试密钥、逻辑时间和仅含撤销的固定范围 envelope 都不属于正式协议。旧备份核对实验尤其不能被误报为 `ROLLBACK-01` 已通过。

本实验也不覆盖 Windows 真实驱动、Android VpnService 或 macOS Network/System Extension 的签名部署及 entitlement；不替代全协议冻结、差分 fuzz、跨设备攻击验证和独立安全审查。完成这些证据并取得四项签核以前，正式发布状态保持 `blocked`。
