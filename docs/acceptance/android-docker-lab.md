# Android Docker 实验

最新 [集成验收报告](evidence/l001-integrated-20261020/REPORT.md)：macOS/Linux/Android 各 268 项通过，实际 Rust JNI 的成员签名、TUN 边界和受保护 UDP socket 工厂通过容器重启复验。历史独立 Java 探针结果保留在下文，生产 VPN 与真机门禁继续 blocked。

**JP 远端补充已通过：** [2026-10-20 远端报告](evidence/l001-android-jp-20261020/REPORT.md)。在 `jp.tingjusting.fun` 的 ARM64 Linux Docker 中，PSI 与 lmkd 正常；完整原生回归和独立 VPN API 调试 APK 均通过，容器重启后再次通过。本机 OrbStack 的内核限制仍保留在下文，不能把远端结果写成本机已修复。

## JP Linux Docker 复跑

远端为 Ubuntu 24.04 ARM64、4 CPU / 24 GiB。专用容器 `loom-l001-android-jp` 使用 2 CPU / 3 GiB / 4096 PID、独立数据卷、同一固定摘要镜像；没有挂载宿主机目录或 Docker socket。ADB 仅绑定远端 `127.0.0.1:15555`，通过 SSH 22 端口转发到本机 `127.0.0.1:15556`。不在脚本或仓库保存 SSH 密码。

本轮为当前运行内核 `6.17.0-1011-oracle` 安装匹配的 `linux-modules-extra-6.17.0-1011-oracle`（及依赖 wireless-regdb），加载 Binder、IPv6 iptables 和 TUN 模块；包安装更新了 initramfs/GRUB，没有升级或重启宿主机。现有四个业务容器的 ID、启动时间和重启计数均保持不变。

服务器已保留 `/opt/loom-l001-lab/run20261020` 中经过摘要验证的测试负载。复跑现有原生负载：

```sh
# 在远端专用目录运行；不要对其他业务容器操作
python3 /opt/loom-l001-lab/run20261020/scripts/l001_android_server_setup.py start
python3 /opt/loom-l001-lab/run20261020/scripts/l001_android_server.py
```

仓库中的 [安装/重启脚本](../../scripts/l001_android_server_setup.py)只操作带 `loom.task=l001-android-remote` 标签、镜像匹配且端口绑定到 loopback 的容器。它要求宿主机已提供 PSI 与匹配的 Binder/TUN 模块，不会自行升级内核。新容器挂载 `/dev/net/tun` 为 Android 需要的 `/dev/tun`；已有容器每次启动后会重新创建该节点，并修正私有 Binder 节点权限。镜像的虚拟蓝牙无有效硬件地址，本实验关闭该虚拟蓝牙功能，没有验证蓝牙。

VPN API 独立实验采用 [调试 APK 源码](../../tools/android-vpn-lab/ProbeActivity.java)，使用真实系统授权界面，不使用 appops 预先授权。APK 只给自身 UID 和 Docker 私有 UDP 地址安装 `/32` 路由；`protect()` 的连接收到独立服务回包，未保护 canary 必须在 TUN 中出现且不能收到回包。测试等待网络回调就绪，保留 IPv6 控制包与实际 IPv4 canary 的十六进制证据。当前探针已通过 JNI 加载 Loom Rust 动态库：校验 Root→MembershipWriter→成员签名、六类无效凭证、TUN IPv4/UDP 边界，并由 Rust 创建 UDP socket、借用 FD 调用真实 VpnService.protect 后再连接，验证拒绝时不发包及两条路径释放 socket。JNI 仅三个有界实验入口；没有加密报文转发、DNS 或生产准入功能。

```sh
# 本机：构建独立调试 APK，需要 SDK platform/build-tools 35 与 JDK
python3 scripts/l001_build_android_vpn_lab.py

# 本机：使用 SSH 密钥、agent 或交互认证建立转发
ssh -p 22 -N -L 127.0.0.1:15556:127.0.0.1:15555 root@jp.tingjusting.fun
# 另一个本机终端
~/Library/Android/sdk/platform-tools/adb connect 127.0.0.1:15556

# 远端：仅在实验期间运行已保留的私有 UDP 服务
python3 -u /opt/loom-l001-lab/udp_echo.py --bind 172.17.0.1
# 本机：使用实际 Docker Gateway；新网络需先通过 docker inspect 核对
python3 scripts/l001_android_vpn_test.py --echo-host 172.17.0.1
```

原生负载包含测试二进制、release examples、Rust 源文件摘要和编译时来源记录；它由本机 NDK 交叉编译后传入，远端无需安装 SDK。源码或二进制摘要不符会拒绝执行。更改 Rust 代码后应重新交叉编译并生成新负载，不能直接沿用本轮证据。VPN 每轮核对 APK、构建源码和脚本摘要，并输出 `target/android-vpn-lab/<UTC时间>/results.json`、系统 UI XML/PNG 和 ADB 日志。

更新源码后的负载可用 [构建脚本](../../scripts/l001_stage_android_server.py)生成，不再手工复用旧二进制：

```sh
# 本机；先按 local-docker-lab.md 构建 loom-l001-lab:local
# 该专用 builder 用于本机 Linux 编译，远端 Android 不挂载这些目录

docker run -d --name loom-l001-integrated-builder --label loom.task=l001-local-docker \
  --cpus=4 --memory=4g --pids-limit=512 -v "$PWD:/workspace" \
  -v loom-l001-cargo:/usr/local/cargo/registry -v loom-l001-target:/build \
  loom-l001-lab:local sleep infinity
python3 scripts/l001_stage_android_server.py \
  --output target/l001-remote/fresh-payload --builder-container loom-l001-integrated-builder
# 使用 tar --no-xattrs 打包后传入远端专用目录，再运行 scripts/l001_android_server.py
# 完成后删除自己创建的 builder

docker rm -f loom-l001-integrated-builder
```

构建脚本从本机同一批测试二进制的 `--list` 生成每个 suite 的预期数量，检查 Android suite 集合完整，再打包并记录剥离 debug 后的摘要。服务器逐项核对实际数量和摘要，新增测试不会继续沿用固定的 248 项断言。当前 schema 2 负载与旧历史 schema 1 分开保存；旧报告保留其原始脚本。


完成后停止私有 UDP 服务与专用 Android 容器，保留镜像、数据卷和测试负载：

```sh
python3 /opt/loom-l001-lab/run20261020/scripts/l001_android_server_setup.py stop
```

独立 APK 实验通过不代表生产 Android 平台验收完成。仍需生产 VPN 加密转发与授权集成、完整 DNS/IPv6 防泄漏、切网、后台限制、设备重启和物理目标设备测试。

## 本机 OrbStack 原生实验

本实验在本机 OrbStack 的 ARM64 Docker 中安装 ReDroid Android 14 / API 34，并在 Android Bionic 中实际执行 Loom 测试程序。实验配置为 `L-001-android-bionic-docker-v1`；通过只表示原生库、实验 TCP 通道及 SQLite 测试完成。`PLATFORM-ANDROID-01` 与 L-001 正式发布仍为 blocked。

最近一次结果：[2026-10-20 报告](evidence/l001-android-docker-20261020/REPORT.md)。

## 启动与复跑

本机已有 Android SDK、NDK `27.2.12479018` 和 Rust 1.90。脚本使用固定摘要的 `redroid/redroid:14.0.0_64only-latest` ARM64 镜像，首次下载约 1 GiB。Android 使用独立的 `loom-l001-android-data` 卷、4 CPU、4 GiB、1024 PID；容器不挂载 macOS 目录或 Docker socket。ReDroid 需要 privileged 和 Binder，使用 memfd 与软件绘图，不需要 KVM。

```sh
# 安装或启动；启动时修正容器内 Binder 节点权限
python3 scripts/l001_android_docker.py start

# 交叉编译后，在 Android 内运行全部测试、测速和故障实验
python3 scripts/l001_android_docker.py test

# 停止 Android，保留已安装镜像与数据卷
docker stop loom-l001-android
```

脚本仅复用带 `loom.task=l001-android-docker` 标签、且镜像摘要匹配的专用容器。默认 SDK 路径为 `~/Library/Android/sdk`，可用 `--sdk`、`--ndk` 指定。默认通过已有 `loom-l001-lab:local` 镜像解析 `host.docker.internal`；也可直接传 `--host-ip <Docker可访问的本机IP>`，本机此次使用 `0.250.250.254`。该解析镜像可用 `docker build -f scripts/l001-lab.Dockerfile -t loom-l001-lab:local .` 构建。

ADB 发布到 `127.0.0.1:15555`。新建容器另把实验 TLS 端口发布到 `127.0.0.1:18443`；此次早期创建的容器使用 OrbStack 可路由的私有容器 IP 进行 macOS→Android 测试。macOS 实验监听器仅在测速期间绑定通配地址，以允许 Android 访问，结束即关闭。

```sh
~/Library/Android/sdk/platform-tools/adb connect 127.0.0.1:15555
~/Library/Android/sdk/platform-tools/adb -s 127.0.0.1:15555 shell
```

每轮输出到 `target/l001-android-docker/<UTC时间>/results.json` 和 `logs/`。保留原始采样、完整命令、返回码、镜像摘要、源文件与二进制 SHA-256；前后核对源文件，运行中变化即拒绝通过。实验私钥在本机与 Android 端均清除。

## 覆盖范围

- 全 workspace、all-targets 的 Android ARM64 测试二进制，由 NDK 交叉编译，在 Android 中以 shell UID 2000 执行；无需 root 运行 Loom。SELinux 为该 ReDroid 镜像的 Disabled，不能推导普通应用沙箱行为。
- Android→Android、Android→macOS、macOS→Android 三条实际 TCP / TLS 1.3 路径；每条验证回显与收发内容，并拒绝错误服务端 pin、未信任客户端、错误 Space、错误 epoch 和拒绝成员关系五种 fixture。
- release 编解码、签名验证、100 条 SQLite 签名日志 append 与 20 次完整 replay。网络预热与采样口径沿用[本机实验](local-docker-lab.md#测速口径)，保留原始样本，没有预设性能 SLO。
- 三次在收到 10/25/50 条 ACK 后强杀 Android 内写进程，明确执行设备侧 PID 的 SIGKILL；检查进程退出码 137、确认历史未丢失、Outbox 一致、授权暂停与 SQLite integrity_check。
- 十项新鲜 Witness 恢复实验：当前完整历史、旧本地备份、旧 nonce 响应、缺失 Witness、伪造签名、Witness 分歧、损坏本地签名、缺失本地镜像、损坏 Witness 镜像、修复后重新核验；另保留三个同机文件一起回滚仍可通过诊断的反例。

`docker exec` 不会继承 Android init 的环境。脚本显式提供 ANDROID_ROOT、ANDROID_DATA、ANDROID_ART_ROOT、ANDROID_I18N_ROOT、ANDROID_TZDATA_ROOT，避免系统 sqlite3 的 ICU 初始化崩溃。Loom 使用自身 bundled SQLite；系统 sqlite3 仅用于实验备份、篡改与完整性复核。

## 当前容器系统限制

本机 OrbStack `7.2.9-orbstack-00391-g2b298d05fbd4` 内核没有可用的 `/proc/pressure/memory`。Android `lmkd` 日志报告内核不支持 memory pressure events，进程反复退出；初次启动期间 ADB shell 也曾超时。复验中 `sys.boot_completed=1`、ADB shell UID 查询成功，但不能据此认定 Android Framework 稳定。

本轮保留这些真实故障，没有替换 lmkd 或伪造健康状态。测试允许通过 Docker exec 执行独立原生进程，明确不把 Activity、VpnService、内存压力、前后台生命周期等应用层验收计为通过。生产 APK/JNI、VpnService.prepare/protect/TUN、系统 VPN 授权与撤销、DNS/IPv6 防泄漏、切网、重启和厂商后台限制均需后续集成与目标设备验证。

要继续容器内应用层测试，需要另一个具备 Binder 与 PSI/memory pressure 支持的 Linux Docker 内核；不能仅靠 Android 容器参数补上当前缺失的内核功能。ReDroid 的[官方启动说明](https://github.com/remote-android/redroid-doc)与维护者对 [lmkd 所需内核功能的说明](https://github.com/remote-android/redroid-doc/issues/293)可供对照。容器测试仍不能替代真实 Android 设备的正式验收。
