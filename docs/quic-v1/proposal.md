# Minnow 完整实现 QUIC v1：提案

状态：待评审的普通项目提案。没有任务号与已发布的 explore，故不冒充正式 `specjc:refine-propose` 产物。

## 目标

在 Minnow 基础上实现独立的 QUIC v1 客户端和服务端，最终逐项满足 RFC 9000、RFC 9001、RFC 9002 中适用于双方的规范性要求，并与独立 QUIC v1 实现双向互通。中间里程碑可以有缺项；只有覆盖矩阵全部核验后才称“完整实现”。

复用 `ByteStream`、`Reassembler`、`UDPSocket` 和事件循环；新建 QUIC 协议模块。TCP 的序号、累计 ACK 和报文段重传状态机不作为 QUIC 实现。现有 TCP 实验和测试保留。

## 完成范围

1. **RFC 9000 传输**：版本协商、Initial/Handshake/0-RTT/1-RTT/Retry、包与全部基础帧、三类包号空间、连接 ID、传输参数、单向与双向流、流状态、流/连接级流量与并发控制、ACK、重置、地址验证、反放大、路径验证、主动迁移、PMTU、ECN、关闭与 stateless reset。
2. **RFC 9001 安全**：TLS 1.3、CRYPTO 帧、证书与 ALPN、Initial secret、包加密和包头保护、0-RTT 票据及接受/拒绝、密钥更新与丢弃、错误映射。采用成熟 TLS/密码库；本项目负责 QUIC 集成。0-RTT 应用数据仅用于显式定义了重放安全规则的应用协议；互通适配层限定为只读 GET。
3. **RFC 9002 恢复**：ACK 范围、RTT、包/时间阈值丢包判定、PTO、慢启动、拥塞避免、恢复期、持续拥塞、bytes-in-flight、ECN 与发送节奏。丢失信息用新包号重新发送。
4. **互通与解释**：本项目客户端和服务端都与独立实现验证；完成后根据最终源码逐项对照 RFC 写详细实现讲解。

“完整”包括上述规范的强制要求，以及实现并宣称支持的条件/可选机制的相关要求。`coverage.md` 跟踪条款、实现位置和证据。HTTP/3、QUIC v2、RFC 9221 DATAGRAM、WebTransport 等另属应用协议或扩展，不在 QUIC v1 核心范围内。IPv4 与 IPv6 均纳入验证。

## 验收

- 双端与独立实现分别完成握手、1-RTT/0-RTT、Retry、多流、流量控制、恢复、迁移和关闭的适用测试；对端不支持的功能由可复现协议测试补足。互通采用 QUIC Interop Runner 的 HTTP/0.9 测试适配层及其约定的 ALPN、证书和文件传输格式；HTTP/0.9 只用于验证传输，不扩大 QUIC 核心范围。
- 可控注入丢包、乱序、重复、延迟、路径及 MTU 变化、ECN、非法包与错误证书，验证数据一致性、安全边界、反放大和拥塞上限。
- RFC 9000/9001/9002 规范性条款的覆盖矩阵全部有代码与测试处置；互通成功不能替代异常路径测试。
- 新测试集成 CMake，现有 Minnow TCP 测试继续通过；解析器接受模糊测试。
- 完成 `implementation.md`，用实际源码和测试证据解释数据结构、状态机、UDP→流交付、TLS/0-RTT、ACK/PTO→重发、迁移及每项 RFC 对应关系。

## 交付与风险

按 `tasks.md` 分阶段实施，最终全量审计。首个阻点是 TLS 库的 QUIC API、会话恢复和构建方式：虚拟机目前仅确认有 OpenSSL 3.0.13 命令；BoringSSL QUIC API 是技术探针候选。现有 UDP/地址封装还需扩展 IPv6 与 ECN，现有 Reassembler 需建立“公布额度内绝不裁掉已 ACK 数据”的接收缓冲约束。完整协议显著超出当前三个 Minnow 实验，单次握手或单流演示不算完成。

来源：[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)、[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)、[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html)、[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner/blob/master/quic.md)。
