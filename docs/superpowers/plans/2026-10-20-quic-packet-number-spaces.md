# QUIC v1 包号空间状态实施计划

## 规范和接口

依据 RFC 9000 §12.3：Initial、Handshake、Application Data 三个空间；0-RTT 和 1-RTT 共用 Application Data 空间；每个空间的发送包号从 0 起且不可复用；包号达到 `2^62−1` 时停止发包。接收端在去除包保护后，必须识别同空间重复包，并能设置一个过旧包号的丢弃下限。

新增 `quic/packet_number_space.hh/.cc`：

- `packet_number_space(PacketKind)` 将四种受保护包映射到三个空间。
- `PacketNumberSpaces::allocate(PacketKind)` 为发送分配递增且不复用的包号；耗尽时返回空值，由连接层执行关闭规则。
- `record_authenticated(PacketKind, number)` 仅供 AEAD 验证后的接收路径调用；返回 false 表示重复、过旧或超界。
- `largest_received(PacketKind)` 供包号恢复使用。
- `retire_received_below(PacketKind, minimum)` 单调地推进丢弃下限并裁剪已接收区间；连接层根据 RTT/ACK 情况选择 minimum。

## 测试与实现顺序

1. 先写独立空间、0-RTT/1-RTT 共享、乱序去重、裁剪下限和超界测试，确认构建失败。
2. 用有序闭区间存储已接收包号，合并相邻区间，避免为连续包号逐个保留节点。
3. 编译、运行 QUIC 定向测试，复核边界与文档。
4. 更新初学者笔记与覆盖矩阵。此里程碑不实现 AEAD、ACK 生成、RTT 驱动的自动保留窗口或连接关闭。
