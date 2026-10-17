# Loom Rust Peer Mesh v1.0 — 独立架构设计评审

> 评审日期：2026-10-17  
> 评审对象：`loom-rust-peer-mesh-architecture-v1.0.md`（953 行，§0—§30）  
> 对照：RelayProxy `main@e4254c81ed678198c948272c22981fd16c19be9a` 已核实的源码调用链、Mesh v1.2 评审结论。  
> 方法：文档逐章评审、协议/威胁场景推导、官方 Protobuf/Quinn/Tauri/Android 文档核对。**没有对 Loom 执行代码/编译/性能测试，因设计当时 Loom 为空仓库**。  
> 最终判断：**架构方向有条件通过；P0 PoC 和 ADR 允许启动；安全协议不能冻结，P1 生产实现和关闭旧 Server 不能批准。**

## 1. 总评

设计正确区分“Rust 业务核心”和必须保留的 OS/浏览器薄适配层；独立 Loom 新仓库避免将高风险重构叠加到 RelayProxy；Peer Core + 可选服务、Owner 授权、撤销优先、双栈授权交集、NAT/Relay 现实边界以及功能矩阵都有明确体现。这是一个**方向正确、覆盖范围充分的提案**，不是已可直接实施的协议规格书。

当前主要不足不是缺少功能，而是**跨边界的安全机制没有完全闭合**：Relay E2EE、授权提交屏障、反回滚信任锚、规范签名解释、Peer mTLS 会话身份与特权 IPC，以及关键平台可行性验证的先后顺序。

审核状态：`DESIGN_DIRECTION_ACCEPTED_WITH_BLOCKERS`，不等于 ADR 已签字、安全审计通过或发布可以开始。

## 2. P0 — 阻塞协议冻结 / 关键实现的 8 项问题

### LOOM-R01 / P0 / Relay E2EE 宣称与链路方案不一致（§0、§10、§12）

**文档原文要点**：Relay 不得知道业务明文，A 与 B 端到端认证，但只对每条 Quinn/TLS 连接和 RelayOpen 做了定义，未规定 Relay 前后端连接之上的**独立 A↔B 加密层**。

**失效场景**：若 A→Relay 和 Relay→B 是两条终止在 Relay 上的 QUIC/TLS 会话，Relay 在转发明文业务请求时可读/改内容。外层 TLS 完全不等于端到端 TLS。

**必须补充**：规范唯一的 `SecurePeerChannel` 安全契约：
1. 所有路径完成 **A↔B 双方身份绑定**，Relay 永远只是 OuterHop；QUIC 路径如采用 TURN 式透明 UDP packet forward，允许 A↔B 内层 QUIC/TLS 终止于真实 Peer；若 Relay 终止外层流，则在其中建立独立端到端 `TLS1.3/mTLS` 或经审查的 Noise/AEAD 记录层。
2. `SessionOpen` 的 `space_id/target_peer_id/resource_id/action/key_epoch` 与内层握手 transcript 绑定，不能通过 Relay 替换目标、重放授权或者跨 Space 复用。
3. 明确中继 datagram/TCP fallback 两种承载如何统一消息边界、可靠性、路径切换与 replay 窗口；同一业务连接换路径不能跳过重新验证。
4. 端到端业务明文绝不进入 Relay 的 tracing/logging、缓存或审计；Relay 只存带宽/源目标 ID 等受限元数据。

**验收**：受控恶意 Relay 尝试读取、修改、重放、替换目标、降级加密或跨 Space 连接，所有尝试失败；可抓包证明无明文。未实现内层端到端协议前不得使用“Relay 端到端加密”宣传语。

### LOOM-R02 / P0 / `DB.commit → 内存 epoch` 仍有准入竞态（§8.2、§9.2）

**文档原文要点**：同事务写 `policy_epoch`、安全事件、outbox、session selector，提交后“立即”改变内存 epoch。

**失效场景**：SQLite commit 完成与内存 epoch/会话取消之间存在窗口，新的 `SessionOpen` 可读取旧缓存；commit 已生效但调用者报错、线程崩溃或无法读取回执时也可能漏掉失效动作。此前 RelayProxy 旧版 Grant CRUD 已存在“提交后读回 / 回调”分离问题。

**必须补充**：
- 按 `(space_id,resource_id)` 的独占**准入屏障**，在授权变更开始前阻挡新准入；持有屏障执行 `BEGIN IMMEDIATE` 事务、签名事件/epoch/outbox 原子写入、commit 结果核实、内存 epoch 发布和现有会话取消标记；屏障释放后异步关闭 socket/传播事件。
- `commit` 结果不确定时，保持拒绝新准入，重查持久化 epoch，直至一致才恢复；禁止 `DB` 读失败时默认接受旧缓存。
- 每个会话/流保存 `AuthorizedEpoch` 和 CancellationToken；至少对文件写入、RDP 控制、代理出口高危操作校验中途撤销。**已开始的字节传输何时终止**需定义 SLO。
- 进程启动时先恢复 DB/outbox、安全 high-water mark，**后**开放外部监听器。

**验收**：多线程同时打开会话与撤销、commit 后读回失败、kill -9、磁盘满、持久化回滚、流内大量数据等故障注入；无旧 epoch 的新准入漏检。

### LOOM-R03 / P0 / 签名字节一致不等于协议语义唯一（§10.2—10.4）

**文档原文要点**：`prost` raw payload 哈希 + 独立 `signing_frame_v1`；拒绝关键字段重复/未知，业务 ID 规范化。

**问题**：原始字节签名可证明完整性，但 `prost` 等解码后的数据结构**不必保留重复/未知字段的原始痕迹**；不同语言可对重复标量、unknown field、map 顺序等有差异。Proto 官方特别说明 deterministic 不等于 canonical。

**必须补充**：
- 形成 **RawWireValidator → 签名帧验签 → 严格业务解码 → 语义一致性验证** 的完整处理流程。验签前只解析有限长度、顶层安全 Envelope，不把未经认证内容作为分配资源的依据。
- 安全关键消息不能仅依赖默认 protobuf 生成解码器；对重复单值字段、未知安全字段、非法 UTF-8、字段数/递归深度和等价表示做严格前置拒绝或选用完整规范编码的安全专用子格式。
- `frame` 中的 `space_id/message_type/signing_key_id/message_id/seq/expiry/payload_sha256` 必须与 payload 内字段一一对照；`event_id` 的定义、domain separator、字段大小端/长度上限、签名算法、未知版本处理要以**规范和 golden vectors** 精确冻结。
- 若安全事件不需要 protobuf 复杂兼容，可以使用 protobuf 作控制面、将**签名事件本体**独立定义为受限确定性 CBOR：两种方案要做限时 Spike，再批准一项。

**验收**：Rust/Go/Kotlin/JS 同输入同签名输入字节；异构 parser 差异、重复字段、未知字段、重排、过长帧、二义性 EventID 必须被一致拒绝。

### LOOM-R04 / P0 / 反回滚记录与 SQLite 位于同一信任域（§7.3、§9.2—9.3）

**文档原文要点**：保存最大 `writer_epoch/chain_head/revocation_root` 并在备份回滚后不恢复旧权限。

**问题**：若这些 high-water mark 也仅存在同一个 SQLite/备份中，恢复旧 DB 就会一起回退，无法证明旧事件被撤销；签名快照只能证明“某个历史时刻有效”，无法证明“它是所见最新状态”。

**必须补充**：定义可验证的**独立防回滚锚点**：受限的 OS 安全区元数据（须确认真实抗回滚语义）、本地受信的独立保护存储、预先可信的其他 Peer 签名见证点/最小 checkpoint quorum；取不到足够证据时 `POLICY_STALE/SAFE_READONLY`，尤其禁止 RDP、文件写、私网出口的新会话。不能把 Keychain/Keystore 简单等同于硬件单调计数器。明确定义孤立离线两端如何在已有信任下工作及何时牺牲可用性。

**验收**：回滚整个数据库和应用配置、恢复 OS 备份、撤销后长期离线、两观察者互相矛盾、攻击者控制 Bootstrap 等情况均不能借历史凭证扩权。

### LOOM-R05 / P0 / Root/Writer/EmergencyRevoker 权限边界未可执行（§7.2—7.3、§9.1）

**文档原文要点**：成员单写者哈希链、Root 可离线、EmergencyRevoker 可以独立签发只减权事件。

**不足**：没有定量规定 writer epoch 轮换与撤销证明有效条件、revoker 可撤销的对象范围、恶意 revoker 拒绝服务时如何恢复、新签与旧 Grant 的代际隔离、邀请码多次兑换冲突处理。

**必须补充**：Root/Writer/Revoker 三类凭证的 schema、权限动作矩阵、委托最大有效期、scope 上限与 key rotation 规则；revocation 单调针对**特定凭证/密钥 epoch**，合法重入必须用新凭证和新 key epoch，并证明不会恢复旧授权。明确多方同时紧急撤销是集合并集，成员扩权仍由 writer 单写；确定系统中的最终恢复权威和无可用 Root 时的失败模式。

**验收**：恶意/被盗 revoke-only key、离线管理员重复签发、writer equivocation、旧邀请高并发兑换、Root 恢复后历史撤销不能复活。

### LOOM-R06 / P0 / QUIC mTLS 身份绑定和传输选择尚缺可实现规格（§6—§7、§10.1、§11）

**文档原文要点**：Ed25519 PeerId、mTLS、Space membership proof、PathManager 检验相同目标。

**不足**：未指定自签证书 PKI 方案、X.509 公钥与 PeerId 的精确绑定、TLS 握手何时验成员、是否按 Space 单独握手、ALPN/cert rotation/0-RTT/resumption 的拒绝规则。§11 状态机甚至写为 `DISCOVERED→VERIFYING→AUTHORIZED→RACING`；但通常必须先建立某条认证承载才能验证远端公钥。

**必须补充**：分离 `DISCOVERED/CONNECTING/TLS_AUTHENTICATED/SPACE_VERIFIED/SERVICE_AUTHORIZED`；第一次网络候选收集可经授权观察点完成，但资源 admission 必须在目标公钥与 Space proof 验证后。首版禁止所有应用 0-RTT；重连/路径迁移不得沿用错误 Space 的授权上下文。

**验收**：TLS 证书替换、签名证书与 PeerId 不一致、错误 Space 的合法 Peer、过期成员、跨 Space 重用连接、旧票据及重连/session resumption 等负向向量。

### LOOM-R07 / P0 / 本地特权 Daemon 与无特权 GUI 的授权边界不够细（§18、§20）

**文档原文要点**：Unix socket / Windows Named Pipe 用 OS 身份检查，Tauri GUI 为无特权客户端。

**不足**：OS 同一账户 ≠ 该用户自动有资格修改任意 Space/RDP 公网 ingress/系统代理/删除共享/导出密钥。管理员与普通本机用户、服务用户、GUI/WebView、远端成员的授权模型不同。Tauri Command/capability 管理失误可能扩大 XSS 后的权限。

**必须补充**：
- 定义本地会话身份 `LocalUserPrincipal{uid/sid, session_id, elevation_state, app_instance}`；每个 API 按操作要求 `LocalUserAuthorized ∧ SpaceRoleAuthorized ∧ ResourceOwnerAuthorized ∧ OSPrivilege`。
- 使用本机 socket peer credentials/named pipe impersonation+ACL，避免仅凭来源是 loopback 就信任；高危操作可要求 OS 提权/再认证/用户确认。
- Tauri command 最小 allowlist、per-window capabilities、严控插件/remote WebView/CSP，关闭不必需的任意文件和远程 URL 访问；本机 Web UI 不能重用 Peer 密钥作为前端 bearer token。
- 特权 helper 提供狭窄 ABI，仅处理 TUN、驱动、路由、防火墙和安装生命周期，不开放通用管理员命令执行 RPC。

**验收**：普通本机账户不能修改其他用户 Space，受恶意 HTML/JS 的窗口不能发起 RDP 公网开口/导出私钥，跨进程 IPC 不能伪造身份，Web CSRF/Origin 欺骗失败。

### LOOM-R08 / P0 / 平台可行性验证排期过晚（§20、§25）

**文档原文要点**：Android VpnService/WinDivert/Apple NetworkExtension 在 P5 才集中落地。

**问题**：这些是决定底层 Peer socket/事件循环/FFI/权限模型的设计输入，不宜等 Mesh、文件、Proxy 核心成型后才发现无法用同样方式保护 UDP socket、在驱动层提取进程信息或持有前台服务。

**必须补充**：在 P0 设置三项独立技术 Spike：
1. Android：从 Rust Quinn 自建 UDP fd，经 JNI/Kotlin `VpnService.protect(fd)` 后再进行任何网络 I/O，测试 VPN 开关、切网、TUN fd 关闭、生命周期、无代理回环；UniFFI 仅负责业务 API，fd 生命周期/保护时序允许 JNI/C ABI 精细适配。
2. Windows：Tauri GUI + daemon/Windows Service + WinDivert helper 最小路径，测试服务权限/托盘退出/任意 exe 重命名/启动和驱动卸载。
3. macOS：至少在有/无 NetworkExtension entitlement 两个场景验证可实际交付的系统代理和透明流量能力；不假装 iOS 可无资格部署。

**验收**：各 Spike 独立样例在真机通过、写出受限 API 和用户可见降级行为；不必等完整 Peer Core 再验证。

## 3. P1 — 必须在对应模块开发前落实的 9 项

| ID | 章节 | 问题与可执行修订 | 验收 |
| --- | --- | --- | --- |
| LOOM-R09 | §9.2/9.3 | `signed_events` 的 `(space,chain,epoch,seq)` 唯一约束会拒绝存储第二个相同 seq 的恶意分叉，需单独 `equivocation_evidence` 表保存两份有效签名事件与来源、证据状态；快照恢复要跨 event GC 后仍可验证 | 双签冲突不会被数据库约束悄然吞掉；恢复后可出具证据 |
| LOOM-R10 | §9.2 | `outbox.sent_ack_mask BLOB` 缺乏动态 Peer 映射及持续离线处理。应定义 `delivery_receipts(event_id, peer_id, checkpoint_seq, acked_at)`、范围/过期/新成员 snapshot 规则；`revocations` 记录含签名原文/证据指针、不可只存目标 ID | 50 Peer、离线 1 年、慢节点/恶意 ACK 与 GC 并发压力 |
| LOOM-R11 | §11—12 | 同一个 QUIC connection 的各 stream 共享 congestion window 和连接级资源，所谓 P0 revoke 专用 stream 不保证端到端优先级；定义控制流保底预算和 p95/p99，实测不够时改独立控制连接。Quinn stream 优先级 API/版本以 PoC 结果为准 | 1,000 streams、大文件占满上传时撤销不饥饿 |
| LOOM-R12 | §7/11/19 | 多 Space 的 `PeerRecord`、候选、观测源、路由缓存和 GUI 都要求隔离，但同一个 `PeerId/证书` 在公网可被相关性分析；定义按空间可见的 discovery nonce/地址保护及不泄露拒绝原因 | A/B 两空间侧信道、多租户 Discovery 负向测试 |
| LOOM-R13 | §13 | DNS 防泄漏提出目标，但缺 fail-open/fail-closed 模式、IPv6/DoH/QUIC 接管覆盖矩阵、FakeIP TTL 与进程归属置信度；自动模式不能暗中更换解析出口或绕过 REJECT | 首次域名访问、DNS 缓存清理、kill-switch/断网、回环 DNS、QUIC/DoH 真实测试 |
| LOOM-R14 | §14 | Unix `openat/O_NOFOLLOW` 是构件不是完整保证，Windows reparse/junction 同理；需逐步句柄相对路径解析、打开文件后校验根、特殊设备/ADS/hardlink/rename 竞态方案，并明确下载/上传流内撤销、磁盘满、重启的清理 | 路径逃逸、软/硬链接竞态、上传回滚、大文件写中撤销 |
| LOOM-R15 | §15/17 | RDP 与 Relay 场景下目标看到的 socket IP 往往是 Relay，不是控制端原始公网 IP；日志需区分 `observed_peer_socket_ip`、`relay_observed_source_ip`、`claimed_original_ip`（不能信任），GeoIP 封禁须明确执行入口 | Relay 路径无法通过自报 IP 绕过黑名单，来源被准确标注 |
| LOOM-R16 | §16/18 | Browser MV3 本地 Bridge 的信任关系还不够明确。优先 Native Messaging 或明确挑战配对的 loopback，不依赖 Origin 作为唯一鉴权；每个扩展实例/站点/设备发最小范围短时能力 | 恶意网页 CSRF/loopback 端口访问、窃取 session storage、账号登出冲突 |
| LOOM-R17 | §22/25 | “旧系统继续运行”和“新 Loom 全新协议”兼容可行，但并行期间本机系统代理/TUN/端口、配置路径和密钥用途可能冲突。应设计互斥资源仲裁、双栈试运行与零权限扩张迁移 diff，以及失败回滚策略 | Go 与 Rust 两套 daemon 共存，互斥端口/驱动处理和旧设备在线均可解释 |

## 4. P2 — 可在开发过程中完善的 4 项

| ID | 章节 | 建议 |
| --- | --- | --- |
| LOOM-R18 | §4 | 30+ crate 是目标分层，不要第一天拆完；先 8 个并按明确依赖方向拆，必要时将 `loom-identity/loom-policy/loom-ledger` 的事务所有权放进一致的服务模块，避免循环依赖与共享 SQLite 表。 |
| LOOM-R19 | §18—19 | 明确 GUI 实时状态的 event cursor 重放、跨 Space 切换清空敏感缓存、设备详情错误状态的术语规范，以及本地 API idempotency/version。 |
| LOOM-R20 | §12/24 | Quinn 当前提供 CUBIC、NewReno 和实验性 BBR 等接口，但不能把 BBR/Brutal 性能推定为生产能力；增加旧 Go/Hysteria2 真实网络同条件基线，明确性能倒退时回退。 |
| LOOM-R21 | §25—26 | 将 P0–P8 的“完成”拆成 `设计/实现/自动化/实网/发布` 五种状态；每个里程碑设明确 owner、证据路径、失败回退、不可继续条件，避免 GUI 与平台风险全堆到 P5。 |

## 5. 具体 ADR 修改建议

| ADR | 建议审查决策 | 状态 |
| --- | --- | --- |
| L-ADR-01/02/03 | 独立 Rust workspace、单 Peer Core、Tokio 结构化并发：**批准方向** | `ACCEPT_DRAFT` |
| L-ADR-04 | Quinn + rustls：选型通过；控制流 QoS、跨路径 E2EE、fallback 未冻结 | `SPIKE_REQUIRED` |
| L-ADR-05/06/15 | 把身份/撤销/反回滚、授权准入屏障和恢复凭证合成安全协议专题 | `BLOCKED` |
| L-ADR-07/14 | Wire/签名字节规范、原始 payload 严格解析与多语言向量 | `BLOCKED` |
| L-ADR-08 | rusqlite + 单写者 DB actor 可用；事务 outbox/外部 rollback anchor 未批准 | `BLOCKED` |
| L-ADR-09 | LAN/静态/Bootstrap 发现且不用全球 DHT：**批准方向** | `ACCEPT_DRAFT` |
| L-ADR-10 | Relay 可选并限额可用；**E2EE 机制待设计** | `BLOCKED` |
| L-ADR-11/12 | Tauri + Android 原生 + 最小 privileged helper：方向通过；P0 跨平台 Spike | `SPIKE_REQUIRED` |
| L-ADR-13 | 默认新协议，旧配置显式审核迁移：**批准方向**；实现见 P7 | `ACCEPT_DRAFT` |
| L-ADR-16 | 和 Go 真实对照，Rust 不预设更快：**批准** | `ACCEPT_DRAFT` |

**建议补充的 ADR**：
- L-ADR-19：`SecurePeerChannel`、端到端加密及经 Relay/TCP fallback 承载。
- L-ADR-20：`AuthorizationCommitBarrier` 与流内撤销语义。
- L-ADR-21：独立 anti-rollback high-water anchor 与离线恢复策略。
- L-ADR-22：本机用户、Space Owner 与 OS 特权三类 principal 的权限模型。
- L-ADR-23：Rust 传输层的跨平台 socket protect/driver 生命周期与 P0 技术 Spike。

## 6. 重新安排首批任务与安全门禁

> 将工程内容视为**可并行但不可乱序批准**的两条流：A. Wire/安全基础；B. 系统平台可行性。

1. **L-000：冻结证据基线**。固定 RelayProxy commit、功能/失败行为矩阵；Loom 初始化 Cargo workspace 和安全/测试 CI；建立 ADR 模板及状态。
2. **L-001A：协议安全 Spike**。`SecurePeerChannel` A↔B，经恶意 Relay 数据中转仍保密；最小 PeerId/mTLS/Space proof；拒绝无授权 ServiceOpen。没有 E2EE 不进入 WAN/Relay 实现。
3. **L-001B：编码 Spike**。protobuf signing frame vs canonical CBOR 小样；正式限定安全 wire、业务事件 ID 和 Rust/Go/Kotlin/JS 交叉测试向量。
4. **L-001C：事务/撤销 Spike**。SQLite writer actor、resource gate、revoke outbox、crash recovery、高水位反回滚与持久 ack。
5. **L-001D：平台 Spike（可并行）**。Android TUN→Rust protected UDP；Windows WinDivert→daemon/service；macOS system proxy/NE entitlement 探测。
6. **L-002：LAN 无中心闭环**。已有信任/邀请完成、两 Peer mTLS、Owner 授权文件读取/代理 TCP、旧 Server 全离线、撤销后新流立即拒绝并停止旧流。
7. **L-003：公网直连/NAT/单跳 E2EE Relay**。先复用同一 `SecurePeerChannel` 验证目标/Scope，之后做候选竞速、QUIC CC、公平控制流量。
8. **L-004 以后：分业务复建**。代理/DNS、文件、RDP、Android/桌面、浏览器/消息/审计、迁移、实网发布矩阵；每项 feature 以用户可见的端到端测试关闭。

### 6.1 第一批必须补充的测试

| 用例 ID | 断言 |
| --- | --- |
| `TEST-E2E-RELAY-01` | 恶意 Relay 无法读/改业务明文、不能替换目标或跨 Space 转发；同一业务目的地不变 |
| `TEST-AUTHZ-RACE-01` | 授权变更 commit 与新 `SessionOpen` 任意交错，绝无 commit 后沿用旧权限准入 |
| `TEST-AUTHZ-CRASH-02` | commit 成功后崩溃，outbox/epoch 恢复完整，高风险新流失败关闭 |
| `TEST-ROLLBACK-01` | 整个 SQLite、配置和服务快照回滚后，旧 Grant 不复活，或 Peer 进入明确安全锁定 |
| `TEST-WIRE-01` | 重复、未知安全字段、非规范编码在 Rust/Go/Kotlin/JS 的接受/拒绝结果一致 |
| `TEST-ID-01` | TLS 公钥与 PeerId 不一致、合法 Peer 在错误 Space、key epoch 过期均被拒绝 |
| `TEST-LOCAL-IPC-01` | 非管理本机用户或受限 WebView 不能执行改变系统服务/授权/私钥相关 RPC |
| `TEST-PLATFORM-ANDROID-01` | Kotlin VpnService 启动后 Rust UDP socket 已 protect，VPN 断线/切网没有回环或 fd 生命周期错乱 |
| `TEST-LEGACY-01` | 旧新系统并行下相同出口的 `LegacyAllow ∧ LoomAllow` 正确收敛、不抢系统代理端口 |

## 7. 文档改稿优先级

按以下顺序改主设计，不应先全面调整用词、页面样式或拆 crate 名称：

- **先修改 §12 + §10**：增加 `SecurePeerChannel` 分层图、端到端握手/重连/Relay 传输约束；加 wire strict parser 完整规范与测试向量。
- **再修改 §8 + §9 + §7**：定义准入屏障、已建立流终止、revoke-only 恢复权限模型、反回滚锚点/快照恢复；修正发现/网络连接/认证状态机。
- **再修改 §18 + §20 + §25**：明确本机操作系统用户与 Space Owner 独立授权、特权 helper command allowlist、将平台 P0 Spike 提前。
- **最后修改 §14—17 + §22**：详细化文件句柄安全、RDP 原始 IP 语义、Browser Bridge、防泄漏、迁移两套系统共存。

## 8. 最终裁决

- **可以开始**：初始化 Loom、架构 ADR 审批、安全/平台/协议 Spike、测试基线、文档修订和不默认启用的 PoC。
- **暂缓开始**：把当前的 Relay/QUIC 方案当成具备 E2EE 的生产协议；将凭证验证当作授权新鲜度；基于已列出的 SQL 表直接实现全量 GC；未经 OS IPC 与平台 Spike 就发布系统透明代理。
- **不允许**：提前关闭 RelayProxy、对外宣称完成去中心化撤销、承诺 Rust 比 Go/Hysteria 更快、在没有安全测试之前默认启用新 Mesh。

**最终评级**：`CONDITIONAL_PASS / 8 P0 + 9 P1 + 4 P2`。安全设计原则可以作为工程北极星，但 8 项 P0 未补齐之前，Wire/Secure Transport/Storage/Privileges 不应宣布冻结。

## 9. 核对资料

设计本身：`loom-rust-peer-mesh-architecture-v1.0.md`。代码证据：RelayProxy `main@e4254c81ed678198c948272c22981fd16c19be9a` 和 `design/decentralized-peer-mesh` 分支的 P0 审查文档（本文中旧代码风险已在此前审核，不等于本轮执行动态测试）。

外部官方技术说明：
- Protobuf 非规范序列化：<https://protobuf.dev/programming-guides/serialization-not-canonical/>；<https://github.com/protocolbuffers/protobuf/blob/main/SECURITY.md>。
- Quinn 当前拥塞控制接口：<https://docs.rs/quinn/latest/quinn/congestion/trait.ControllerFactory.html>。
- Tauri capabilities：<https://v2.tauri.app/security/capabilities/>。
- Android VpnService protect：<https://developer.android.com/reference/android/net/VpnService>。