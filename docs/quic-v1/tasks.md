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

2026-10-21 阶段进展：任务 3 已增加 `CryptoStreams` 分级别收发缓冲，并通过受保护 Initial 的内存网络测试；TLS 库及回调、握手状态尚未接入，因此任务 3 保持未完成。

完成条件：RFC 9000/9001/9002 适用的规范性要求均有实现与验证处置，双向互通及回归通过，详细讲解文档与最终提交一致。
