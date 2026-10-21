# Minnow QUIC v1 学习笔记

这组笔记记录 `quic-v1-proposal` 分支当前的代码及其依据。目标是先理解规范，再能亲手推导线上字节和代码里的边界判断。**这里记录的是进行中的实现，不表示已经有可互通的 QUIC 连接。**

## 建议阅读顺序

1. [requirements.md](requirements.md)：最终希望满足的 RFC 9000、9001、9002 行为。
2. [implementation.md](implementation.md)：按“规范 → 为什么 → 代码 → 例子 → 未完成工作”学习已经写出的模块。第一次阅读从这里开始。
   [transport-parameters.md](transport-parameters.md) 专门手算 TLS 扩展中的传输参数和 CID 校验。
   [path-validation.md](path-validation.md) 讲解连接迁移之前的路径验证状态。
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
| 报头保护为什么先取样、再恢复包号长度？ | RFC 9001 §5.4 | [header_protection.hh](../../quic/header_protection.hh)、[header_protection.cc](../../quic/header_protection.cc) | [quic_packet_primitives.cc](../../tests/quic_packet_primitives.cc) |
| 收到 ACK 后如何更新 RTT 和 PTO？ | RFC 9002 §5–6 | [rtt_estimator.hh](../../quic/rtt_estimator.hh)、[rtt_estimator.cc](../../quic/rtt_estimator.cc) | [quic_packet_primitives.cc](../../tests/quic_packet_primitives.cc) |

## 一句话检查当前边界

可以编码和解析部分 QUIC v1 字段；**还不能发送或接收一个经过 TLS 与 AEAD 认证的完整 QUIC 连接**。缺失内容和逐项状态以 [coverage.md](coverage.md) 为准。
