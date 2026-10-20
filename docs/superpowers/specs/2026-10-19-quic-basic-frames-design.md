# QUIC v1 基础帧编解码设计

在现有变长整数和包号模块上，增加 RFC 9000 §19 的基础帧编解码，供后续解密后的包载荷处理使用。本轮覆盖 PADDING、PING、ACK（含 ECN）、CRYPTO、STREAM。输入是已经完成 AEAD 认证的帧字节串；输出是有类型的帧序列。编码器从同一帧模型生成字节串。

解码器一次处理完整帧序列。空载荷、任何截断、未知类型、无效 ACK 区间、流偏移溢出都拒绝整个序列，避免把前半段当作有效包。PADDING 合并为连续字节数；没有 LEN 位的 STREAM 吃掉包载荷剩余全部字节。ACK 区间按包号从大到小保存为闭区间，保留原始 ACK Delay 和 ECN 计数，供包号空间与恢复模块使用。

本模块只负责帧语法。合法包类型、ACK 所属包号空间、流状态和流量控制、加密级别、ACK Delay 指数、错误码映射由后续连接层检查。当前分支尚无 AEAD，所以不能把任意网络字节直接交给连接状态机。

规范依据：[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)、[§19.1–19.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1)、[§19.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6)、[§19.8](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8)。
