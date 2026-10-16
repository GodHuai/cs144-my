# QUIC v1 实现讲解（进行中）

当前只完成 RFC 9000 §16 的变长整数编解码。本文随代码里程碑扩展；不能据此认为已经实现 QUIC 连接、TLS、帧或拥塞控制。最终以完整协议代码、测试和 `coverage.md` 为准。

## RFC 9000 §16：变长整数

QUIC 的变长整数使用首字节最高两位表示总长度：`00` 为 1 字节，`01` 为 2 字节，`10` 为 4 字节，`11` 为 8 字节。剩余位以网络字节序表示非负整数，最大值为 `2^62 − 1`。[RFC 9000 §16](https://www.rfc-editor.org/rfc/rfc9000.html#section-16)

`quic/varint.hh` 暴露 `encode_varint`、`decode_varint` 和上限常量。`quic/varint.cc` 的编码函数根据 6/14/30/62 位边界选最短长度，先按大端顺序写入数值，再在首字节写入长度前缀；超过 62 位直接抛出 `std::out_of_range`。这一接口供后续包头、传输参数和帧字段使用。

解码函数先读最高两位确定需要的总长度，确认输入足够后再累积数值并推进 offset。若输入截断，返回 `std::nullopt`，offset 保持原值，调用者可以在数据报解析层统一处理该错误。一般整数字段允许非最短编码，因此 `0x4025` 与 `0x25` 都解为 37。**帧类型**还有额外的最短编码规则；后续帧解析器必须单独校验，不能仅依赖此通用解码器。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

`tests/quic_varint.cc` 检查长度边界、62 位最大值、越界拒绝、非最短编码、截断时 offset 不变，以及 [RFC 9000 附录 A.1](https://www.rfc-editor.org/rfc/rfc9000.html#appendix-A.1) 的四组示例字节。测试使用会在 Debug 和 Release 都执行的异常检查。

验证记录：Debug 配置下构建 `quic_varint_sanitized`，`ctest -R '^quic_varint$'` 通过；Release 配置下同一目标编译并直接运行通过。Release CTest 的公共编译夹具在现有 `webget` 链接阶段失败，错误为 `FileDescriptor::CheckSystemCall<int>` 未定义；该夹具失败与新变长整数目标分开记录，尚未作为 QUIC 测试失败处理。
