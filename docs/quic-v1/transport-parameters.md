# QUIC 传输参数：把 TLS 握手里的承诺变成可检查的字节

对应 [RFC 9000 §7.3–7.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3) 和 [§18](https://www.rfc-editor.org/rfc/rfc9000.html#section-18)。本页先解释协议要求，再按接收流程对照 `quic/transport_parameters.hh/.cc` 和 `tests/quic_transport_parameters.cc`。这里实现的是**参数扩展的编解码与静态校验**；TLS 握手、认证、与实际包头/连接状态的接线仍未完成。

## 1. 参数在连接里起什么作用

握手时，客户端和服务器各自通过 TLS 的 `quic_transport_parameters` 扩展声明自己的限制。例如“我最多接收 1200 字节的 UDP 载荷”“你最多能同时使用两个我发给你的连接 ID”。它们不是对方替你选择的数值；一端发出的参数约束另一端之后怎样向它发送数据。QUIC 需要 TLS 的认证结果来相信这些声明。只把这串字节解析成功，不能证明发送方是谁。[RFC 9000 §7.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4)

**费曼式复述：**把握手参数想成两人交换的“收件规则”。纸条上写清接收方能收多大的包、准许多少条流；签名（TLS 认证）使纸条可信。解析器只负责读纸条并检查规则有没有写错。

## 2. 线上格式怎样读

扩展内容是连续的三元组：`参数 ID (varint) | 值的字节数 (varint) | 值 (指定长度的原始字节)`。同一扩展中一个 ID 只能出现一次。未知 ID 需要忽略其语义，不能因不认识就拒绝握手；RFC 为此还专门预留了 `31 × N + 27` 的 ID。已知的整数值本身也用 QUIC varint 编码，可以使用非最短表示。[RFC 9000 §18](https://www.rfc-editor.org/rfc/rfc9000.html#section-18)

例如 `03 02 44 b0 0f 01 c1` 可手算成两项：

| 字节 | 读法 | 结果 |
| --- | --- | --- |
| `03` | ID | `max_udp_payload_size` |
| `02` | 长度 | 后面读 2 字节 |
| `44 b0` | QUIC varint，前两位 `01` | 1200 字节 |
| `0f` | ID | `initial_source_connection_id` |
| `01` | 长度 | 后面读 1 字节 |
| `c1` | 原始连接 ID | 单字节 CID `c1`，**不**按 varint 再解码 |

`decode_transport_parameters()` 从 offset 0 循环调用 `decode_varint()` 读取 ID 和长度，先确认 `length <= input.size() - offset`，再取 value。任何截断、已知值非法或重复 ID，返回 `std::nullopt`。`std::map` 保存原始值，未知 ID 因此仍可存储并重新编码；发送时 `encode_transport_parameters()` 按 ID 顺序输出，但接收时并不要求网络上的顺序固定。

## 3. 为什么已知值还要检查

外层长度只回答“读几个字节”，不能保证这些字节符合参数含义。`valid_value()` 在解完外层后逐项检查：

| 参数 | 规则及省略时的值 | 代码中的判断 |
| --- | --- | --- |
| `max_udp_payload_size` `0x03` | 至少 1200；省略为 65527 | 整数解码后 `>= 1200` |
| `initial_max_streams_bidi/uni` `0x08/09` | 最多 `2^60`；省略为 0 | 超界会使流 ID 超过 varint 范围 |
| `ack_delay_exponent` `0x0a` | 最多 20；省略为 3 | 避免错误解释 ACK Delay |
| `max_ack_delay` `0x0b` | 小于 `2^14` 毫秒；省略为 25 | 边界 `2^14` 无效 |
| `active_connection_id_limit` `0x0e` | 至少 2；省略为 2 | 需要留出连接 ID 更换空间 |
| `disable_active_migration` `0x0c` | 只能是零长度 | 出现即表示启用该限制 |
| `stateless_reset_token` `0x02` | 恰好 16 字节 | 固定长度随机标记 |
| `initial/original/retry` CID | 最多 20 字节，零长度也合法 | 原样保存，随后和包头对照 |
| `preferred_address` `0x0d` | IPv4/端口、IPv6/端口、1 字节 CID 长度、1–20 字节 CID、16 字节 token | CID 长度字段在第 24 字节，整项长度必须等于 `41 + CID长度` |

`initial_max_data` 和三种 `initial_max_stream_data_*` 等其他整数也必须**恰好**是一枚 varint：空值、截断值，或者一个整数后面再附加字节，都无效。`transport_parameter_integer()` 负责把合法的原始值转成数字，并对省略的整数返回 RFC 默认值；它假设调用者已先完成解码与校验。比如 `0x0a 0x02 0x40 0x03` 的值 `40 03` 是非最短编码的 3，仍应接受。[RFC 9000 §18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2)

## 4. 为什么还得带握手上下文验证

单看参数字节，无法判断 `initial_source_connection_id=c1` 是否真实，因为攻击者可能在早期包中影响连接 ID。RFC 要求把参数里的 CID 与**实际发送或收到的 Initial/Retry 包头**比对，保证 TLS 认证的握手也认证了这些 ID。实现把这一层放在 `validate_transport_parameters(parameters, context)`：`context` 由未来的连接层从握手包头填入，不能从未认证的参数自身复制。双方必须有 `initial_source_connection_id`；服务器还必须有 `original_destination_connection_id`。若收到 Retry，服务器参数还必须带对应的 `retry_source_connection_id`；没有收到 Retry 时则不能带它。[RFC 9000 §7.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3)

角色也决定合法性。客户端不可发送 `original_destination_connection_id`、`stateless_reset_token`、`preferred_address`、`retry_source_connection_id`。服务器可发送它们，但如果自己选了零长度 Source CID，就不能提供 `preferred_address`。因此验证函数先核对参数值与初始 CID，再检查角色、原始 DCID、Retry CID 和 preferred address 的前提。它返回 `false` 时，未来连接层应触发 `TRANSPORT_PARAMETER_ERROR`（Retry 关联问题 RFC 也允许 `PROTOCOL_VIOLATION`）；当前模块不持有连接，不能自行发送 CONNECTION_CLOSE。

## 5. 从测试回到实现

`tests/quic_transport_parameters.cc` 用固定字节验证 1200 的编码、默认值、非最短整数、未知 ID、重复 ID 和各数值边界；另用模拟握手上下文验证客户端/服务器角色、原始 DCID、Retry CID、零长度 CID 与 preferred address 的组合。这里的字节期望由规范手算，不调用被测编码器来生成“预期值”。

下一步仍需把本模块接入 RFC 9001 的 TLS QUIC 扩展处理，再用**已认证的**握手包头填充上下文；之后连接层才能消费这些参数去限制流、数据报、ACK 和连接 ID。0-RTT 恢复参数不得降低等约束，也属于后续连接状态实现，不是这个 codec 已经完成的功能。
