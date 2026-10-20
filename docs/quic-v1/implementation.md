# QUIC v1 实现讲解（进行中）

当前完成 RFC 9000 §16 的变长整数、§17.1 的包号编解码、§17.2–17.3 的部分受保护包头布局、§19 的部分基础帧编解码、RFC 9001 §5.4 的报头掩码基础操作，以及 RFC 9002 §5 的 RTT 估计和 §6.2.1 的 PTO 时长计算。它们还没有组成 QUIC 连接；TLS、AEAD、版本协商与 Retry、其余帧、ACK 与丢包状态机、UDP 互通仍未完成。最终以完整协议代码、测试和 `coverage.md` 为准。

## RFC 9000 §16：变长整数

QUIC 的变长整数使用首字节最高两位表示总长度：`00` 为 1 字节，`01` 为 2 字节，`10` 为 4 字节，`11` 为 8 字节。剩余位以网络字节序表示非负整数，最大值为 `2^62 − 1`。[RFC 9000 §16](https://www.rfc-editor.org/rfc/rfc9000.html#section-16)

`quic/varint.hh` 暴露 `encode_varint`、`decode_varint` 和上限常量。`quic/varint.cc` 的编码函数根据 6/14/30/62 位边界选最短长度，先按大端顺序写入数值，再在首字节写入长度前缀；超过 62 位直接抛出 `std::out_of_range`。这一接口供后续包头、传输参数和帧字段使用。

解码函数先读最高两位确定需要的总长度，确认输入足够后再累积数值并推进 offset。若输入截断，返回 `std::nullopt`，offset 保持原值，调用者可以在数据报解析层统一处理该错误。一般整数字段允许非最短编码，因此 `0x4025` 与 `0x25` 都解为 37。**帧类型**还有额外的最短编码规则；后续帧解析器必须单独校验，不能仅依赖此通用解码器。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

`tests/quic_varint.cc` 检查长度边界、62 位最大值、越界拒绝、非最短编码、截断时 offset 不变，以及 [RFC 9000 附录 A.1](https://www.rfc-editor.org/rfc/rfc9000.html#appendix-A.1) 的四组示例字节。测试使用会在 Debug 和 Release 都执行的异常检查。

验证记录：Debug 配置下构建 `quic_varint_sanitized`，`ctest -R '^quic_varint$'` 通过；Release 配置下同一目标编译并直接运行通过。Release CTest 的公共编译夹具在现有 `webget` 链接阶段失败，错误为 `FileDescriptor::CheckSystemCall<int>` 未定义；该夹具失败与新变长整数目标分开记录，尚未作为 QUIC 测试失败处理。

## RFC 9000 §17.1：包号编码与解码

`quic/packet_number.hh/.cc` 选择 1–4 字节的包号字段，只发送完整包号的低位字节。发送端依据当前包号与该包号空间的最大已确认包号选择足够宽的字段；未收到 ACK 时，字段必须装下完整包号，例如包号 128 仍只需一字节，超过四字节可表示的范围则拒绝编码。接收端在报头保护移除后，以“最大已成功认证包号 + 1”为期望值，恢复最接近期望值的完整包号。测试包括 RFC 9000 附录 A.2 的 `0xac5c02` / `0xabe8b3` 长度示例与附录 A.3 的 `0xa82f9b32` 解码示例。

这个模块只做数字编解码。调用方仍必须为 Initial、Handshake、Application Data 维护独立包号空间，并保证每个空间的发送包号单调且不复用。接收方仍须在认证后处理重复包；这些状态机尚未实现。输入超出 62 位范围、字段长度不是 1–4 字节或长度不足以安全表达当前未确认范围时，函数拒绝操作。

## RFC 9000 §17.2–17.3：受保护包头的布局

QUIC 可以把多个长包头包放进同一个 UDP 数据报。要解密其中一个包，接收端先要知道它从哪里开始、在哪里结束、包号字段从哪个字节开始。长包头的 `Length` 字段解决包边界问题：它表示**包号字段加密文载荷**的总字节数，不包括 `Length` 字段本身。短包头没有这个长度字段，所以从其起点一直占用数据报剩余部分。[RFC 9000 §17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2)、[§17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1)

`quic/packet_header.hh/.cc` 的 `parse_protected_packet()` 从未加密字段读出版本、目的/源连接 ID、Initial Token 和长包头 Length，返回包类型、包号字段起点 `pn_offset` 与包结束位置 `packet_end`。再次以 `packet_end` 为起点调用即可定位下一个拼接的长包头包。短包头的目的连接 ID **没有长度字节**，因此调用者必须从连接状态传入 `short_dcid_length`。两个连接 ID 的 v1 长度均限制为 20 字节；超过界限、字段截断或 Length 超出数据报都拒绝解析。当前接口只接受 v1 Initial、0-RTT、Handshake 和 1-RTT；版本协商包与 Retry 包格式不同，交由后续模块处理。

为什么这里不直接读包号？包号长度写在首字节低两位，但这两位已经被 RFC 9001 的报头保护掩盖。解析器只读首字节的长/短格式、固定位和长包头类型，**不使用低位计算包号长度，也不提前检查保留位**。后续应在 `pn_offset + 4` 取 16 字节样本，生成报头掩码，恢复首字节与包号，再用完整包号解开 AEAD，认证成功后才验证保留位和更新接收状态。为保证样本存在，布局解析器要求从 `pn_offset` 到包末尾至少 20 字节。[RFC 9001 §5.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4)

发送端用 `build_long_header()` 或 `build_short_header()` 构造**尚未保护的**包头和 1–4 字节截断包号。两者都要求调用者提供将来的密文及 AEAD tag 长度 `protected_payload_length`，用它检查样本长度；长包头还会计算 `Length = 包号字节数 + protected_payload_length`。这段未保护包头将来要作为 AEAD 的 associated data；密文生成后才应用报头保护。RFC 9001 附录 A.2 的 Initial 包头 `c3 00 00 00 01 ... 44 9e 00 00 00 02` 是测试向量：包号起点为字节 18，`44 9e` 编出的 Length 为 1182，整个包长为 1200 字节。[RFC 9001 附录 A.2](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2)

`tests/quic_packet_header.cc` 还验证拼接的 Handshake 包、0-RTT 包、带 Token 的 Initial、1-RTT 短包头，以及损坏的连接 ID、Token、Length、版本和固定位。构造函数不会分配包号、不会加密或认证，也不会生成 Retry 完整性标签；本模块的“布局正确”不能当作真实网络包已经有效。

## RFC 9000 §19：基础帧编解码

QUIC 包通过帧传递控制信息和数据。可以把一个包的明文载荷想成若干张接在一起的“小纸条”：每张先写帧类型，再写该类型约定的字段。接收方必须知道一张纸条在哪里结束，才能找到下一张。`quic/frame.hh/.cc` 的 `decode_frames()` 接收**已经完成 AEAD 认证**的整段载荷，依次解码并返回 `Frame` 列表；空载荷或任何一处格式错误都返回空值，不把已经读出的前缀交给连接层。`encode_frame()` 把单个结构化帧还原成线上字节。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

目前支持五类帧：PADDING 是一个 `0x00` 字节，可连续出现，解码后合并为长度；PING 是 `0x01`，没有后续字段；CRYPTO 是 `0x06`，依次写握手数据的 Offset、Length、Data；STREAM 类型为 `0x08` 至 `0x0f`，最低三位分别决定是否有 Offset、Length 和 FIN；ACK 是 `0x02`，ACK_ECN 是 `0x03`。除类型外，各整数均调用已有的 QUIC 变长整数编解码器。帧类型必须用最短长度，本轮支持的类型都只占一字节；未知类型和非最短类型会使整段解析失败。[RFC 9000 §19](https://www.rfc-editor.org/rfc/rfc9000.html#section-19)

例如 `06 02 03 61 62 63` 是一个 CRYPTO 帧：类型 `06`、偏移 2、长度 3、数据 `abc`。`0f 04 01 02 78 79` 是一个 STREAM 帧：`0f` 的 OFF/LEN/FIN 三个位全为 1，因此随后是流 ID 4、偏移 1、长度 2、数据 `xy`，且流在偏移 3 处结束。若 LEN 位为 0，数据就延伸到**当前包载荷的末尾**，因此打包器只能把这种 STREAM 放在最后；本模块的单帧编码函数无法替调用者决定排包顺序。[RFC 9000 §19.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6)、[§19.8](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8)

ACK 的 `First ACK Range` 表示从最大包号往前连续确认了多少个包。例如 `02 0a 03 01 02 01 01` 表示最大确认包号 10、原始 ACK Delay 3、后续区间数 1；第一个区间是 `[8,10]`，再经过一个缺口和一个区间得到 `[4,5]`。代码保存降序闭区间，检查每次减法不会变成负包号；ACK_ECN 另外读入 ECT(0)、ECT(1)、CE 三个累计值。这里只保留 ACK Delay 的线上整数，尚未按对端 `ack_delay_exponent` 换算，也未根据 ACK 更新已发送包、RTT、丢包与拥塞状态。[RFC 9000 §19.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3)

CRYPTO 和 STREAM 的“偏移 + 数据长度”不能超过 `2^62−1`。代码先比较剩余字节和长度，再复制数据；ACK Range Count 先受载荷剩余长度约束，以免畸形计数导致无意义的长循环。`tests/quic_frames.cc` 检查组合帧往返、无 LEN 的 STREAM、空 FIN、ACK/ACK_ECN、空载荷、截断、未知类型、区间下溢、畸形大计数与 62 位偏移边界。帧所在的包类型、流方向与流量控制、CRYPTO 加密级别等语义规则仍需连接层实现，不能把“能解析”理解为“可以接受”。

## RFC 9001 §5.4：报头保护的掩码操作

`quic/header_protection.hh/.cc` 的 `header_protection_sample` 从包号字段起点往后跳四字节，取得 16 字节密文样本；长度不够返回空值。`apply_header_mask` 先从未保护的首字节读出包号长度，再只异或长报头最低四位或短报头最低五位及对应的 1–4 字节包号。`remove_header_mask` 顺序相反：先恢复首字节，再确定包号长度，最后恢复包号。任何字段不足都在写入前返回失败，因此不会留下半修改的报头。RFC 9001 附录 A.2 的客户端 Initial 报头与掩码是测试向量。

这两个函数接收**已经生成的五字节掩码**。从 TLS 派生 HP 密钥、AES/ChaCha 生成掩码、AEAD 加解密与认证都尚未实现；不能把这些函数当成安全的 QUIC 包保护。后续收到受保护包时，还必须在认证通过后才更新包号空间状态。

## RFC 9002 §5、§6.2.1：RTT 估计和 PTO 时长

`quic/rtt_estimator.hh/.cc` 默认用 333 ms 初始化 `smoothed_rtt`，用其一半初始化 `rttvar`。第一份 RTT 样本会重置这两个估计值；`min_rtt` 保留未扣除 ACK delay 的最小原始样本。之后只有在扣除 ACK delay 不低于 `min_rtt` 时才调整样本；握手确认后还会把对端的 ACK delay 限在其 `max_ack_delay` 之内。按 RFC 给出的 7/8 与 3/4 权重更新平滑值和变动值。`pto_ms()` 计算 `smoothed_rtt + max(4*rttvar, 1 ms) + max_ack_delay`；Initial/Handshake 取 0 ACK delay，应用数据在握手未确认前不给出 PTO 值。`reset()` 用于新路径重新初始化估计器。

调用者必须确保 ACK 帧中的 Largest Acknowledged 包是新确认的，且这次 ACK 至少新确认了一个会引发 ACK 的包，才调用 `observe()`。RTT 样本取自 Largest Acknowledged 包的发送时间；这个包本身可以不引发 ACK。该 ACK 处理器尚未实现。这里也没有实现 PTO 定时器、指数退避、包号空间选择或丢包判定。测试覆盖首次样本、ACK delay 上下限、未确认握手的应用 PTO、路径重置和非法输入。

验证：包号、报头掩码、RTT、基础帧和包头布局模块的 Debug QUIC 定向测试通过；新增模块均先观察到缺失实现的测试失败，再补充实现。独立审查指出 ACK 取样契约、ACK delay 上限测试、空载荷处理、62 位边界测试以及短包头样本长度检查的问题，均已修正。全量 `ctest --timeout 12` 共 43 项，36 项通过；五项原有 TCP/整数压力测试超时，`net_interface` 和 `router` 因本分支尚未含相应测试程序而未运行。因此全量测试仍未通过，不能把新增 QUIC 测试的通过外推为整个项目通过。详细任务见 `docs/superpowers/plans/2026-10-19-quic-packet-primitives.md`、`2026-10-19-quic-basic-frames.md` 与 `2026-10-19-quic-packet-header.md`。
