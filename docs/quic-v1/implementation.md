# QUIC v1 实现讲解（进行中）

当前完成 RFC 9000 §16 的变长整数、§17.1 的包号编解码、RFC 9001 §5.4 的报头掩码基础操作，以及 RFC 9002 §5 的 RTT 估计和 §6.2.1 的 PTO 时长计算。它们还没有组成 QUIC 连接；TLS、AEAD、完整包/帧解析、ACK 与丢包状态机、UDP 互通仍未完成。最终以完整协议代码、测试和 `coverage.md` 为准。

## RFC 9000 §16：变长整数

QUIC 的变长整数使用首字节最高两位表示总长度：`00` 为 1 字节，`01` 为 2 字节，`10` 为 4 字节，`11` 为 8 字节。剩余位以网络字节序表示非负整数，最大值为 `2^62 − 1`。[RFC 9000 §16](https://www.rfc-editor.org/rfc/rfc9000.html#section-16)

`quic/varint.hh` 暴露 `encode_varint`、`decode_varint` 和上限常量。`quic/varint.cc` 的编码函数根据 6/14/30/62 位边界选最短长度，先按大端顺序写入数值，再在首字节写入长度前缀；超过 62 位直接抛出 `std::out_of_range`。这一接口供后续包头、传输参数和帧字段使用。

解码函数先读最高两位确定需要的总长度，确认输入足够后再累积数值并推进 offset。若输入截断，返回 `std::nullopt`，offset 保持原值，调用者可以在数据报解析层统一处理该错误。一般整数字段允许非最短编码，因此 `0x4025` 与 `0x25` 都解为 37。**帧类型**还有额外的最短编码规则；后续帧解析器必须单独校验，不能仅依赖此通用解码器。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

`tests/quic_varint.cc` 检查长度边界、62 位最大值、越界拒绝、非最短编码、截断时 offset 不变，以及 [RFC 9000 附录 A.1](https://www.rfc-editor.org/rfc/rfc9000.html#appendix-A.1) 的四组示例字节。测试使用会在 Debug 和 Release 都执行的异常检查。

验证记录：Debug 配置下构建 `quic_varint_sanitized`，`ctest -R '^quic_varint$'` 通过；Release 配置下同一目标编译并直接运行通过。Release CTest 的公共编译夹具在现有 `webget` 链接阶段失败，错误为 `FileDescriptor::CheckSystemCall<int>` 未定义；该夹具失败与新变长整数目标分开记录，尚未作为 QUIC 测试失败处理。

## RFC 9000 §17.1：包号编码与解码

`quic/packet_number.hh/.cc` 选择 1–4 字节的包号字段，只发送完整包号的低位字节。发送端依据当前包号与该包号空间的最大已确认包号选择足够宽的字段；未收到 ACK 时，字段必须装下完整包号，例如包号 128 仍只需一字节，超过四字节可表示的范围则拒绝编码。接收端在报头保护移除后，以“最大已成功认证包号 + 1”为期望值，恢复最接近期望值的完整包号。测试包括 RFC 9000 附录 A.2 的 `0xac5c02` / `0xabe8b3` 长度示例与附录 A.3 的 `0xa82f9b32` 解码示例。

这个模块只做数字编解码。调用方仍必须为 Initial、Handshake、Application Data 维护独立包号空间，并保证每个空间的发送包号单调且不复用。接收方仍须在认证后处理重复包；这些状态机尚未实现。输入超出 62 位范围、字段长度不是 1–4 字节或长度不足以安全表达当前未确认范围时，函数拒绝操作。

## RFC 9001 §5.4：报头保护的掩码操作

`quic/header_protection.hh/.cc` 的 `header_protection_sample` 从包号字段起点往后跳四字节，取得 16 字节密文样本；长度不够返回空值。`apply_header_mask` 先从未保护的首字节读出包号长度，再只异或长报头最低四位或短报头最低五位及对应的 1–4 字节包号。`remove_header_mask` 顺序相反：先恢复首字节，再确定包号长度，最后恢复包号。任何字段不足都在写入前返回失败，因此不会留下半修改的报头。RFC 9001 附录 A.2 的客户端 Initial 报头与掩码是测试向量。

这两个函数接收**已经生成的五字节掩码**。从 TLS 派生 HP 密钥、AES/ChaCha 生成掩码、AEAD 加解密与认证都尚未实现；不能把这些函数当成安全的 QUIC 包保护。后续收到受保护包时，还必须在认证通过后才更新包号空间状态。

## RFC 9002 §5、§6.2.1：RTT 估计和 PTO 时长

`quic/rtt_estimator.hh/.cc` 默认用 333 ms 初始化 `smoothed_rtt`，用其一半初始化 `rttvar`。第一份 RTT 样本会重置这两个估计值；`min_rtt` 保留未扣除 ACK delay 的最小原始样本。之后只有在扣除 ACK delay 不低于 `min_rtt` 时才调整样本；握手确认后还会把对端的 ACK delay 限在其 `max_ack_delay` 之内。按 RFC 给出的 7/8 与 3/4 权重更新平滑值和变动值。`pto_ms()` 计算 `smoothed_rtt + max(4*rttvar, 1 ms) + max_ack_delay`；Initial/Handshake 取 0 ACK delay，应用数据在握手未确认前不给出 PTO 值。`reset()` 用于新路径重新初始化估计器。

调用者必须确保 ACK 帧中的 Largest Acknowledged 包是新确认的，且这次 ACK 至少新确认了一个会引发 ACK 的包，才调用 `observe()`。RTT 样本取自 Largest Acknowledged 包的发送时间；这个包本身可以不引发 ACK。该 ACK 处理器尚未实现。这里也没有实现 PTO 定时器、指数退避、包号空间选择或丢包判定。测试覆盖首次样本、ACK delay 上下限、未确认握手的应用 PTO、路径重置和非法输入。

验证：`quic_packet_primitives_sanitized` 与原有 `quic_varint_sanitized` 在 Debug CTest 中通过；每个新模块的测试先观察到缺失实现的失败，再补充实现。独立代码审查指出 ACK 取样契约的注释错误和 ACK delay 上限测试没有真正区分分支，均已修正。全量 `ctest --timeout 12` 共 41 项，34 项通过；五项原有 TCP/整数压力测试超时，`net_interface` 和 `router` 因本分支尚未含相应测试程序而未运行。因此全量测试**未通过**，不能把新增 QUIC 两项的通过外推为整个项目通过。详细任务见 `docs/superpowers/plans/2026-10-19-quic-packet-primitives.md`。
