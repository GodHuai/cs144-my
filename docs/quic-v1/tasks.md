# 完整 QUIC v1 实施计划

每项保存代码、测试与 RFC 覆盖证据；中间里程碑不宣称完整。

1. [ ] 构建 `quic/`、确定性网络测试、模糊测试入口；探针验证并固定 QUIC TLS 库及会话恢复。扩展 Address/UDP 到 IPv4/IPv6 和数据报 ECN 元数据，验证收发控制消息。
2. [ ] 变长整数、全部基础帧、包头、包号恢复、合并包、Version Negotiation、Retry、token 和错误解析测试。
3. [ ] Initial/Handshake/1-RTT 密钥、CRYPTO、TLS 1.3、证书/ALPN、传输参数、包保护、握手与密钥丢弃。
4. [ ] 连接生命周期、单向/双向流、STREAM offset、FIN、RESET_STREAM、STOP_SENDING、关闭及超时；保证已 ACK 的额度内数据无损保存，测试乱序帧靠近接收上限。
5. [ ] 流级/连接级/并发额度、MAX_* 与 BLOCKED 帧，乱序/重复/RESET 记账。
6. [ ] ACK/ACK_ECN、RTT、丢包阈值、PTO、迟到 ACK、跨空间和重新组包。
7. [ ] 慢启动、拥塞避免、恢复期、持续拥塞、bytes-in-flight、ECN 验证和发送节奏。
8. [ ] 0-RTT 票据、应用 API、接受/拒绝、重放防护和参数约束；为测试适配层定义只读 GET 的 0-RTT profile，通用 API 默认禁止早期应用数据。服务端不处理拒绝的早期包；客户端拒绝时重置所有流及应用状态，应用按显式重放安全策略重新发起 1-RTT 操作。
9. [ ] 地址验证、反放大、迁移、NAT 重绑定、连接 ID 生命周期和新路径恢复状态。
10. [ ] PMTU 探测/黑洞恢复、密钥更新、stateless reset、draining 和异常边界。
11. [ ] 本项目双端及 QUIC Interop Runner 双向角色互通；实现其 `hq-interop`/HTTP/0.9 测试适配层并记录对端版本、测试用例和日志。逐条展开并填满 `coverage.md`，新旧测试、故障注入与模糊测试通过。
12. [ ] 依据最终代码写 `docs/quic-v1/implementation.md`，逐项解释 RFC、源码、状态机、关键路径、测试与互通证据。

2026-10-21 阶段进展：任务 3 已增加 `CryptoStreams` 分级别收发缓冲，并通过受保护 Initial 的内存网络测试；随后新增 `TlsHandshake`，以固定 OpenSSL 3.5.9 完成真实双端 TLS 1.3 握手、证书/ALPN/参数校验及 secret 回调；本轮再补上 AES-128-GCM Handshake/1-RTT 整包保护，内存测试贯通受保护 TLS 握手及双向 1-RTT STREAM 字节；生产连接、握手确认和密钥丢弃仍缺失，因此任务 3 保持未完成。

完成条件：RFC 9000/9001/9002 适用的规范性要求均有实现与验证处置，双向互通及回归通过，详细讲解文档与最终提交一致。

2026-10-21 UDP 阶段：任务 1 新增 Linux 专用双栈非阻塞数据报接口和逐包 ECN 元数据，真实 IPv4/IPv6 回环测试贯通受保护 TLS、反放大检查与 1-RTT 控制帧。驱动仅为测试工具，生产连接状态机、ACK/恢复与流量控制仍待实现；任务 1、3 保持未完成。见 `udp.md`。

2026-10-21 连接阶段：新增 `HandshakeConnection` 库类管理单一固定对端的 TLS、实际 CID、包号、密文队列、反放大、握手确认和握手密钥丢弃，真实双栈 UDP 回归改用该类。尚无 ACK/恢复、流、监听分发与完整关闭计时，相关总任务保持未完成。详见 `handshake-connection.md`。


ACK 里程碑：即时确认、分空间的有界发送记录与认证重复包重新确认已接入连接，见 [acknowledgments.md](acknowledgments.md)。前文关于 ACK 完全缺失的历史描述已由此替代；RTT 接线、丢包恢复、PTO 和拥塞控制仍待实现。


2026-10-22 恢复阶段：新增 `PacketRecovery` 和连接超时 API，接入发送时间、RTT、包号/时间阈值与 PTO，用新包号重发握手 CRYPTO/HANDSHAKE_DONE/PING。确定性丢包测试覆盖六种握手包/ACK 丢失，详见 [loss-recovery.md](loss-recovery.md)。相关旧文中的恢复缺失描述由本段更新；任务 6 仍因应用流恢复及完整 RFC 边界尚缺而未完成，任务 7 拥塞控制也未完成。
