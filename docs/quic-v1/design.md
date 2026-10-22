# 完整 QUIC v1 设计草案

基线：Minnow `my-work`，提交 `7d30f0b7b1545ef997005440fb5be3b1e90f7e6e`。新增独立 `quic/` 库；扩展现有 UDP/地址接口后提供 IPv4/IPv6 I/O，`EventLoop` 负责事件；`ByteStream`/`Reassembler` 仅提供每流字节缓存与重组。

## 模块与状态

UDP I/O → 包解析/保护 → 连接/TLS → 帧调度与恢复 → 流/API。认证和合法性检查先于状态更新及应用交付。连接拥有角色、连接 ID、路径、握手/关闭状态、传输参数、三类包号空间、流表及定时器。0-RTT 和 1-RTT 共享 Application Data 包号空间。

每流记录方向、offset、final size、额度、收发状态、待确认/恢复区间与独立 `Reassembler`。STREAM 数据进入 Reassembler 前先检查流状态、权限、最终长度和流/连接额度。连接额度按各流最高接收偏移变化计量。每流发布的 `MAX_STREAM_DATA` 上限始终不大于 `bytes_popped + Reassembler capacity`；应用消费后再增加额度。接收层必须确认额度内的全部字节已保存，才可 ACK 该包；若 Reassembler 仍会裁剪，须改为无损存储或修正窗口实现。现有 Reassembler 的冲突重叠和提前 FIN 行为须先测试，再决定适配或修正。并发流上限与缓冲预算共同约束总内存。

发送调度器从 CRYPTO、流、ACK、额度与路径控制队列组帧，再按密钥级别、PMTU、反放大与拥塞窗口组包。每包记录包号、时间、大小及可恢复信息；ACK/丢包更新包状态，仍需可靠送达的信息重新入队。Recovery 分空间管理包和丢包状态，共享 RTT/拥塞估计。

路径状态包含地址、验证、PMTU、ECN 与适用的 RTT/拥塞信息。迁移执行挑战/响应，更新连接 ID；按照 RFC 9000 §9.4 对新路径重置或保留拥塞/恢复状态，不能机械沿用旧路径估计。旧路径数据不能误验证新路径。连接状态机覆盖版本协商、Retry、握手确认、密钥丢弃、空闲、关闭、draining、stateless reset。

TLS 使用 OpenSSL 3.5 external QUIC TLS 回调接口，当前固定 3.5.9；证书验证与握手已接入，会话恢复和密钥更新后续实现。QUIC 侧实现包保护、CRYPTO 重组和传输参数集成；不手写 TLS 或密码原语。0-RTT API 默认禁止应用数据，只有应用协议配置了可重放操作并明确请求才放行；互通适配层的 profile 只允许只读 HTTP/0.9 GET。拒绝时服务端不处理早期包，客户端重置所有流及关联应用状态并通知应用，仅由应用按重放安全策略发起新的 1-RTT 操作。服务端检查恢复配置并执行重放防护。

当前 `UDPSocket` 和 `Address` 仅面向 IPv4，且 `recvfrom`/`sendto` 不携带 ECN 元数据。新增可表达 IPv4/IPv6 的地址和数据报类型，通过 `recvmsg`/`sendmsg` 及 IP_TOS/IPV6_TCLASS 等控制消息收发 ECN；先写回环探针，再接入 QUIC 路径/ECN 状态。

验证采用编解码/状态单元测试、确定性虚拟网络、IPv4/IPv6 端到端、解析器模糊测试及 RFC 覆盖审计。独立实现互通采用 QUIC Interop Runner 约定的 HTTP/0.9 测试适配层、ALPN `hq-interop`、证书和文件传输格式；该适配层只服务测试。主要风险是 TLS/0-RTT、迁移路径状态、流量额度和跨包号空间恢复，每项独立设失败测试。

参考：[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)、[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)、[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html)、[OpenSSL external QUIC TLS API](https://docs.openssl.org/3.5/man3/SSL_set_quic_tls_cbs/)。

2026-10-21 TLS 选型更新：采用 OpenSSL 3.5 的 external QUIC TLS 回调接口，固定 3.5.9 工作树内静态构建，替代早期 BoringSSL 探针候选。先启用 TLS_AES_128_GCM_SHA256，证书/主机名/ALPN 与传输参数均验证；恢复及 0-RTT 后续实现，当前明确关闭。见 `tls-handshake.md`。
