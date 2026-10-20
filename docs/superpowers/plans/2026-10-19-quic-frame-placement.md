# QUIC v1 帧与包类型校验实施计划

## 依据与接口

对照 RFC 9000 §12.4 表 3 与 §12.5。给 `quic/frame.hh/.cc` 增加纯函数 `frame_allowed_in_packet(Frame, PacketKind)` 和 `frames_allowed_in_packet(vector<Frame>, PacketKind)`；解析字节与包上下文校验仍由独立步骤承担，调用方可区分字段编码错误与 PROTOCOL_VIOLATION。

## 测试先行

1. 在 `tests/quic_frames.cc` 为全部现有 Frame 变体指定 Initial、Handshake、0-RTT、1-RTT 允许矩阵。特别测 ACK/CRYPTO 不得出现在 0-RTT，应用 CONNECTION_CLOSE 不得出现在 Initial/Handshake，PADDING/PING 可以在四种包中出现，空帧集合拒绝。
2. 构建 `quic_frames_sanitized`，确认缺少接口导致失败。
3. 实现表 3 规则并运行定向与 QUIC 测试。审查代码和文档中的已实现范围。
4. 更新 `docs/quic-v1/implementation.md`、`coverage.md`，记录连接层必须在 AEAD 验证后使用这些规则。

## 后续

连接处理器负责把 `decode_frames` 失败映射到适用错误，把帧与包类型不符按 RFC 9000 §12.4–12.5 处理；对于 §12.5 单独列出的六种 0-RTT 帧，服务端可以选择 PROTOCOL_VIOLATION。ACK 包号空间、方向/角色限制和帧语义校验另行实现。
