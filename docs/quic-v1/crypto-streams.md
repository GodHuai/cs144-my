# CRYPTO 数据流：把乱序帧还原为 TLS 字节

依据 [RFC 9000 §7.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.5)、[§19.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6) 和 [RFC 9001 §4.1.3](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.1.3)。源码为 `quic/crypto_streams.hh/.cc`，测试为 `tests/quic_crypto_streams.cc`。

## 为什么有这个模块

TLS 需要按顺序接收握手字节，但 UDP 包可能丢失、重复或乱序。CRYPTO 帧的 offset 标记握手数据在本加密级别中的位置。Initial、Handshake、1-RTT 各自从 offset 0 开始，不能拼成同一个字节流；0-RTT 不能携带 CRYPTO。

`CryptoStreams` 为一条连接维护三个相互独立的收发状态。它不解析 TLS 消息，也不决定何时推进 TLS 加密级别。连接层必须先认证包、解析和检查帧，再调用 `receive(kind, frame)`；调用 `take_contiguous(kind)` 取走从当前游标开始的连续字节，交给 TLS。一次取走的数据不会再次交付。

例如先收到 `{offset=3, data="def"}` 时存在缺口，不能给 TLS 任何字节；再收到 `{offset=0, data="abc"}` 后，取出的是 `"abcdef"`，游标移动到 6。此后 `{offset=4, data="efgh"}` 只交付 `"gh"`。这个游标表示**已经交给 TLS 的字节位置**，与包号和应用 STREAM offset 无关。

## 有界、无损的接收

接收用有序的稀疏区间保存尚未交付的数据，合并相邻及一致的重叠部分。offset 即使接近 `2^62-1`，也只为实际数据分配空间，不为缺口分配空间。所有 offset 和长度先验证和不超过 `2^62-1`；空数据不占区间。

每个级别默认可保存 65536 个数据字节，构造时可调整，但接收上限不能小于 4096。区间索引还有与区间数成正比的开销；区间不为空且互不重叠，因此条目数也受数据字节上限约束。容量按**唯一、尚未交付的数据字节**计算，包含已连续但尚未被取走的数据；重复数据不重复计费。取走字节会释放接收容量。

`receive()` 成功返回 `nullopt`；以下错误返回对应的 `CryptoReceiveError`，不修改已保存的数据或游标：

| 输入/条件 | 返回值 | 未来连接层的责任 |
| --- | --- | --- |
| offset 或 offset+length 超出 62 位范围 | `FrameEncodingError` (`0x07`) | 关闭连接 |
| 0-RTT CRYPTO，或与尚未交付数据内容冲突的重叠 | `ProtocolViolation` (`0x0a`) | 关闭连接 |
| 新增数据超过接收容量 | `BufferExceeded` (`0x0d`) | 关闭连接，不能把截断后保存当成功 |

重叠冲突检查是本实现的选择：检查仍在缓存中的字节；已经交付的旧字节不保留历史，重复部分直接忽略。模块不会自己发送 CONNECTION_CLOSE，也不生成 ACK。TLS 必须能接收当前级别数据后，调用方才能取走数据；取走后将其交给 TLS 的责任属于调用方。

## 发帧和重传

TLS 将生成的字节交给 `append(kind, bytes)`，它们按追加顺序拥有稳定 offset。`frame(kind, offset, max_data)` 返回至多 `max_data` 字节的 CRYPTO 帧，支持任意重分片，不消耗原始数据。`max_data` 只限制数据，不包含帧类型、offset、长度的线上开销；组包器还要计算这些开销、AEAD tag 和包头。

重传的是同一段 CRYPTO 字节及其 offset，封装时必须分配**新的包号**。发送数据按级别默认最多保留 65536 字节，`append` 超限时返回 false 且不部分追加；调用者必须处理失败，不能丢掉 TLS 输出。当前没有 ACK 驱动的发送数据回收，所有数据保留到该级别被丢弃；因此这还是握手传输基础模块，尚不适用于无限持续的握手后 TLS 输出。

`discard(kind)` 在密钥被丢弃时释放该级别的收发数据，并永久禁止其再次发送或接收；迟到帧被忽略，其他级别不受影响。它不判断协议上何时可丢弃密钥，这由未来的握手状态机负责。

## 测试证明的边界

测试覆盖乱序、缺口、桥接重叠、冲突原子性、旧/部分重复、NUL/高位字节、4096 字节边界、容量释放、巨大稀疏 offset、62 位溢出、空帧、三个级别隔离、0-RTT 拒绝、发送保留与重分片，以及密钥级别丢弃。另用 2048 个不相邻单字节区间及反向填洞检查合并过程。内存释放回归通过 ASan 的实时分配字节统计，确认丢弃包含 1 MiB 发送数据的级别会立即释放其堆空间；该测试先复现了空字符串移动赋值保留 capacity 的问题，再验证临时空字符串交换的修复。

集成测试实际经过“发送缓冲 → CRYPTO 编码 → Initial 加密和报头保护 → 乱序/重复/丢失/篡改 → Initial 认证解封 → 帧解析 → 接收重组”。缺失的片段用新包号重发后，接收端恢复精确的二进制输入；认证失败的包不能推进 CRYPTO 或包号状态。

这个集成测试使用的是测试握手字节和确定性的内存网络操作，**还没有 TLS 1.3 协商、证书/ALPN 校验或真实 UDP 连接**。后续仍需选定并固定支持 QUIC 回调的 TLS 库、接入密钥回调和 CRYPTO 数据，以及实现 ACK、恢复、连接状态与互通。

验证命令：

```sh
cd /home/huai/minnow-quic-proposal
ctest --test-dir build -R '^quic_' --output-on-failure -j2
```

2026-10-21 验证记录：QUIC 专项 14/14（包含编译夹具）通过，ASan/UBSan 启用；独立审查发现的 discard 堆内存保留问题已按 RED→GREEN 修复并复核。全量回归在审查期间运行，49/52 通过；`net_interface`、`router` 因原有测试可执行文件缺失而未运行；原有 `wrapping_integers_roundtrip` 在约 495 秒仍未完成后被手动停止，不能称全量回归通过。修复后另行完成了全部 QUIC 专项。全量日志保留于 `build/quic-crypto-full-ctest.log`。
