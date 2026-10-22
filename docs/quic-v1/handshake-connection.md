# 可复用的握手连接引擎

`quic/handshake_connection.hh/.cc` 将先前测试驱动中的握手编排移入库代码。`HandshakeConnection` 独占 TLS、三类包号空间、双方 CID、单一路径反放大预算及有上限的待解密包。它是握手阶段的连接基础，尚不提供可靠应用传输。

## 与 UDP 接线

构造参数是 `ConnectionConfig` 与固定的对端 `UdpEndpoint`。本端 CID 和客户端 original DCID 都要求 8..20 字节，调用者应使用安全随机值；服务端不预先填写 original DCID。TLS 的角色、证书、CA、主机名、ALPN 由 `config.tls` 提供。连接根据实际包头设置用于 TLS 的 CID 参数，不能用配置中的猜测替代。

客户端构造后即可 `poll_transmit()` 取得 Initial（最终 UDP payload 恰为 1200 字节，包含包头和 AEAD 标签）；服务端在通过认证、数据报大小及帧检查的首个 Initial 中取得实际 SCID/DCID，随后创建 TLS。外部 UDP 接收器将完整 `UdpDatagram` 交给 `receive()`；类会检查来源地址和 DCID，再逐个处理合并包。不同对端地址的数据报直接丢弃，本轮不处理迁移。

`poll_transmit()` 在精确线上大小通过拥塞及反放大检查后才分配包号，每次交付一个含目标地址、payload 和 ECN 的数据报，并记入发送额度和物理在途字节、推进新 CRYPTO offset。阻塞时不消费 TLS/恢复队列；纯 ACK 可回退，PTO 探测可越过拥塞窗口但受反放大约束。**这一步是发送交接**：若随后 `UdpSocket::send()` 返回 EAGAIN，外部事件循环必须保存并重试同一个数据报，不能把再次 poll 的输出当作其替代品。网络发送错误由外部循环处置。

## 认证、参数绑定与缓冲

客户端创建 TLS 时显式延后绑定服务端 Initial SCID。收到认证的 Initial 后，调用新增的 `bind_peer_initial_source_connection_id()` 一次性绑定；TLS 参数回调必须检查实际 CID，未绑定或参数不一致均失败为 `0x08`。原有直接使用 `TlsHandshake` 的默认行为保持不变。

只有通过 AEAD 的包才会记录包号和处理帧。新增 `open_initial_packet_detailed()` 区分认证失败的静默丢弃与认证后保留位错误（`0x0a`）；旧 optional 接口保留兼容。整个包先完成帧格式、包类型放置、HANDSHAKE_DONE 角色及 ACK 对实际交付包号的检查，再交付 CRYPTO，避免包后部的非法帧让前部 CRYPTO 提前改变握手。重复包只计入新收到的数据报字节，不重复交付；认证重复包仍可重新触发 ACK。

缺少密钥或 TLS 尚未完成时，密文最多缓存 64 个包、合计 65536 字节；溢出丢弃新包，不根据未认证流量判定对端协议错误。新密钥可用时重试缓存，不重复增加反放大额度。每个包号空间仅保留最近 4096 个包号的去重范围；更旧包丢弃，ACK 记录另有同样大小的窗口；这不是丢包恢复策略。

## 状态与密钥

服务端从 WaitingInitial 进入 Handshaking，TLS 完成后进入 Confirmed，并发送 1-RTT HANDSHAKE_DONE。客户端从 Handshaking 进入 Established，仅在认证并处理 HANDSHAKE_DONE 后进入 Confirmed。TLS 完成不能直接等同于客户端 QUIC 确认。

客户端在首次交付 Handshake 包时、服务端在认证收到 Handshake 包时丢弃 Initial 密钥和相应 CRYPTO。两端在确认握手时清除 Handshake 读写 secret 与 CRYPTO，保留应用密钥。退役同时清理该空间的 ACK 与恢复状态，且是幂等的，不会因重复事件再次重置 PTO 退避。TLS 新增的 `discard_keys()` 只供达到上述里程碑且 TLS 已释放旧级别输入的连接调用，不允许以此接口丢弃 OneRtt。

合法的对端关闭进入 Draining，停止输出；本轮没有 draining 定时器。认证帧错误或 TLS 失败进入 Failed，首个错误保持不变，清理 TLS、输出和待解密队列。尚未实现向对端调度错误 CONNECTION_CLOSE。

## 当前支持范围

支持握手 CRYPTO、PADDING、PING、HANDSHAKE_DONE 和对端关闭。ACK 已接入生成与发送记录更新，详见 [acknowledgments.md](acknowledgments.md)；RTT、握手帧重传和 PTO 现已接入，见 [loss-recovery.md](loss-recovery.md)；单路径 NewReno 物理字节/窗口见 [congestion-control.md](congestion-control.md)，持续拥塞、pacing 和 ECN 验证仍缺失。`send_ping()` 最多保留一个待发 PING。

STREAM、流量控制、连接 ID 生命周期、路径控制及其它未实现语义不会被交给应用，认证后遇到它们以本地 INTERNAL_ERROR (`0x01`) 结束；这不表示它们本身都是对端协议违规。后握手 CRYPTO 和密钥更新也尚不支持。该类不接受 Retry、0-RTT、版本协商或 TLS 会话恢复，不提供监听器、动态多连接分发、空闲超时及外部互通保证。

## 测试

`tests/quic_handshake_connection.cc` 使用库中的连接类覆盖正常/乱序/合并包、实际 CID 参数绑定、密文队列压力、包损坏和重复、非法来源/CID、完整帧预检、关闭与终止、大握手反放大暂停恢复；另在 IPv4/IPv6 的真实回环 UDP 上完成双端确认和 PING。原 `quic_udp_handshake` 保留为较低层 TLS/包/UDP 组合测试。

```sh
cmake --build build --target quic_handshake_connection_sanitized -j2
ctest --test-dir build -R 'quic_' --output-on-failure -j2
ctest --test-dir build --output-on-failure --timeout 30 -j2
```

独立审查发现两项重要接线问题：Initial 认证后保留位错误被旧 optional 接口隐去、Initial 将明文而非最终数据报填充到 1200 字节。两项均先新增回归复现，再修复；边界测试包括损坏认证标签、错误状态保持，以及仅接受 <=1200 字节数据报的 8/20 字节 CID 双端握手。该连接初始里程碑修复后 QUIC 专项 19/19 通过（含编译 fixture，20.21 秒）；修复后全量 50/57 通过（100.79 秒），与上一轮相同的五个超时为 `wrapping_integers_roundtrip`、`wrapping_integers_extra`、`recv_transmit`、`recv_reorder_more`、`send_transmit`；`net_interface` 和 `router` 因缺少可执行文件未运行。日志在忽略的 `build/quic-connection-full-ctest.log`。普通 `quic_debug` 构建、格式及空白检查通过；不宣称全量套件通过。

当前代码基准 `7abc5c7` 已加入超时 API 和十种握手丢包场景；最近 QUIC 21/21、全量 52/59 的记录与事件循环约定见 [loss-recovery.md](loss-recovery.md)。上述 19/19、50/57 为历史结果。
