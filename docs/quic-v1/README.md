# Minnow QUIC v1 学习笔记

这组笔记记录 `quic-v1-proposal` 分支当前的代码及其依据。目标是先理解规范，再能亲手推导线上字节和代码里的边界判断。**这里记录的是进行中的实现，不表示已经有可互通的 QUIC 连接。**

## 建议阅读顺序

1. [requirements.md](requirements.md)：最终希望满足的 RFC 9000、9001、9002 行为。
2. [implementation.md](implementation.md)：按“规范 → 为什么 → 代码 → 例子 → 未完成工作”学习已经写出的模块。第一次阅读从这里开始。
   [transport-parameters.md](transport-parameters.md) 专门手算 TLS 扩展中的传输参数和 CID 校验。
   [path-validation.md](path-validation.md) 讲解连接迁移之前的路径验证状态。
   [anti-amplification.md](anti-amplification.md) 解释未验证地址的三倍发送额度。
   [connection-ids.md](connection-ids.md) 解释迁移时使用、退休和替换连接 ID。
   [local-connection-ids.md](local-connection-ids.md) 解释本端签发连接 ID、处理对端退休帧和路由入口。
   [initial-packet-protection.md](initial-packet-protection.md) 手算 Initial 密钥、AES-GCM 载荷和报头掩码。
   [retry-integrity.md](retry-integrity.md) 解释 Retry 伪包和接收前的完整性验证。
3. [coverage.md](coverage.md)：查某条规范现在有代码、有测试，还是尚未开始。
4. [design.md](design.md) 与 [tasks.md](tasks.md)：完整连接的目标架构和后续工作顺序；它们是计划，不是当前实现证据。
5. `docs/superpowers/specs/`、`docs/superpowers/plans/`：每一轮小功能的设计与测试记录。

## 已有代码从哪里看

| 学习问题 | 规范 | 源码 | 测试 |
| --- | --- | --- | --- |
| 一个整数如何占 1、2、4、8 字节？ | RFC 9000 §16 | [varint.hh](../../quic/varint.hh)、[varint.cc](../../quic/varint.cc) | [quic_varint.cc](../../tests/quic_varint.cc) |
| 为什么只发包号的低 1–4 字节还能恢复完整包号？ | RFC 9000 §17.1 | [packet_number.hh](../../quic/packet_number.hh)、[packet_number.cc](../../quic/packet_number.cc) | [quic_packet_primitives.cc](../../tests/quic_packet_primitives.cc) |
| 拼接的包如何定位边界与包号字段？ | RFC 9000 §17.2–17.3 | [packet_header.hh](../../quic/packet_header.hh)、[packet_header.cc](../../quic/packet_header.cc) | [quic_packet_header.cc](../../tests/quic_packet_header.cc) |
| ACK、STREAM、连接 ID、路径、关闭等核心帧在载荷里是什么样子？ | RFC 9000 §19 | [frame.hh](../../quic/frame.hh)、[frame.cc](../../quic/frame.cc) | [quic_frames.cc](../../tests/quic_frames.cc) |
| TLS 握手里如何声明和检查传输参数？ | RFC 9000 §7.3–7.4、§18 | [transport_parameters.hh](../../quic/transport_parameters.hh)、[transport_parameters.cc](../../quic/transport_parameters.cc) | [quic_transport_parameters.cc](../../tests/quic_transport_parameters.cc) |
| 迁移前怎样确认新路径可达且支持 1200 字节数据报？ | RFC 9000 §8.2 | [path_validation.hh](../../quic/path_validation.hh)、[path_validation.cc](../../quic/path_validation.cc) | [quic_path_validation.cc](../../tests/quic_path_validation.cc) |
| 未验证地址最多能发送多少字节？ | RFC 9000 §8、§9.3.1 | [anti_amplification.hh](../../quic/anti_amplification.hh)、[anti_amplification.cc](../../quic/anti_amplification.cc) | [quic_anti_amplification.cc](../../tests/quic_anti_amplification.cc) |
| 换路径时怎样使用对端提供的新连接 ID？ | RFC 9000 §5.1、§9.5 | [peer_connection_ids.hh](../../quic/peer_connection_ids.hh)、[peer_connection_ids.cc](../../quic/peer_connection_ids.cc) | [quic_peer_connection_ids.cc](../../tests/quic_peer_connection_ids.cc) |
| 怎样签发供对端使用的连接 ID，并处理其退休请求？ | RFC 9000 §5.1.1、§19.16 | [local_connection_ids.hh](../../quic/local_connection_ids.hh)、[local_connection_ids.cc](../../quic/local_connection_ids.cc) | [quic_local_connection_ids.cc](../../tests/quic_local_connection_ids.cc) |
| 报头保护为什么先取样、再恢复包号长度？ | RFC 9001 §5.4 | [header_protection.hh](../../quic/header_protection.hh)、[header_protection.cc](../../quic/header_protection.cc) | [quic_packet_primitives.cc](../../tests/quic_packet_primitives.cc) |
| Initial 包怎样派生密钥并保护载荷？ | RFC 9001 §5.1–5.4 | [initial_keys.hh](../../quic/initial_keys.hh)、[initial_keys.cc](../../quic/initial_keys.cc) | [quic_initial_keys.cc](../../tests/quic_initial_keys.cc) |
| 怎样验证 Retry 确实对应最初的 Initial？ | RFC 9001 §5.8 | [retry_integrity.hh](../../quic/retry_integrity.hh)、[retry_integrity.cc](../../quic/retry_integrity.cc) | [quic_retry_integrity.cc](../../tests/quic_retry_integrity.cc) |
| 收到 ACK 后如何更新 RTT 和 PTO？ | RFC 9002 §5–6 | [rtt_estimator.hh](../../quic/rtt_estimator.hh)、[rtt_estimator.cc](../../quic/rtt_estimator.cc) | [quic_packet_primitives.cc](../../tests/quic_packet_primitives.cc) |

## 一句话检查当前边界

可以编码和解析部分 QUIC v1 字段；**还不能发送或接收一个经过 TLS 与 AEAD 认证的完整 QUIC 连接**。缺失内容和逐项状态以 [coverage.md](coverage.md) 为准。

构建 QUIC 加密模块需要 OpenSSL 3 的开发头文件与 `libcrypto`；CMake 会检查此依赖。
