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

## 当前里程碑（2026-10-22，含应用流阶段）

上面的复选框对应完整总任务，部分实现不勾选；尤其不能把“握手可靠”视为“所有应用流可靠”。当前证据汇总如下：

| 总任务 | 已完成的子范围 | 仍未完成的关键范围 |
| --- | --- | --- |
| 1–2 | 双栈 UDP/ECN 元数据、基础编码与核心帧格式、包号/包边界、VN/Retry 原语 | 会话恢复、模糊测试、VN/Retry 接受状态机与 token |
| 3 | CRYPTO、真实 TLS 1.3、证书/ALPN/实际 CID 参数绑定、AES 包保护、单路径握手确认及密钥丢弃 | 其它套件、后握手处理与完整 RFC 安全边界 |
| 4–5 | 可复用连接、可靠双向/单向应用流、FIN/RESET/STOP、流/连接额度和 MAX/BLOCKED | 完整生命周期与关闭计时 |
| 6 | 即时 ACK、有界发送历史、RTT、包号/时间阈值、PTO/退避、迟到 ACK、新包号重发握手帧 | ACK_ECN、CRYPTO 发送缓冲按 ACK 回收及完整 RFC 边界 |
| 7 | 已接入物理在途字节、固定路径 NewReno、慢启动/拥塞避免及恢复期降窗、ACK/PTO 发送例外及有界 pacing | 持续拥塞、ECN 验证和完整 RFC 边界 |
| 8 | 显式禁用 0-RTT/会话恢复 | 0-RTT 策略、会话恢复和应用 API |
| 9–10 | 单路径反放大接线，路径验证/CID 管理等独立基础模块 | 迁移、动态 CID 路由、PMTU、密钥更新、stateless reset 和计时器 |
| 11–12 | 内存故障注入、真实双栈回环与逐模块文档 | 第三方双向互通、完整覆盖审计和最终文档 |

恢复测试共十种握手丢包场景，含连续丢失三份关键包；具体范围和 QUIC 21/21、全量 52/59 的验证记录见 [loss-recovery.md](loss-recovery.md)。该组数字仅对应握手恢复里程碑。NewReno 的范围与该阶段验证记录见 [congestion-control.md](congestion-control.md)。

完成条件：RFC 9000/9001/9002 适用的规范性要求均有实现与验证处置，双向互通及回归通过，详细讲解文档与最终提交一致。

后续已接入有界令牌桶 pacing：速率随窗口与 RTT 调整，发送唤醒与恢复期限合并，纯 ACK/PTO 探测保留例外。当前实现与验证见 [pacing.md](pacing.md)。

后续已接入有界可靠应用流、FIN/RESET/STOP 与流量控制，当前能力、API、资源限制和验证见 [application-streams.md](application-streams.md)。

后续已实现流终态回收、紧凑关闭 ID 区间与可靠 MAX_STREAMS 补额，最新语义和验证见 [stream-retirement.md](stream-retirement.md)。
