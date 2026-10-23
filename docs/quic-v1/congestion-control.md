# 单路径 NewReno 与物理在途字节

本阶段在握手恢复上接入 `quic/congestion_control.*`。当前固定路径最大数据报大小为 1200 字节，初始窗口 12000、最小窗口 2400。它是 NewReno 基础实现，该阶段尚无持续拥塞检测、ECN 验证、应用流和迁移；不表示完整 RFC 9002。

## 字节额度如何使用

拥塞控制按整个受保护包的线上字节记账，包含包头和 AEAD 标签。引发 ACK 的包或带 PADDING 的包计入在途；纯 ACK 不计入。因此填充到 1200 字节的 Initial ACK 也消耗窗口，未填充的 1-RTT ACK 不消耗窗口。

`HandshakeConnection::congestion_stats()` 返回窗口、在途字节和慢启动阈值的快照。`packets_awaiting_ack()` 仍是逻辑恢复使用的活动包计数，两者不能互相替代。

```text
剩余拥塞额度 = max(0, window − bytes_in_flight)
普通在途包的完整线上大小必须不超过剩余额度
PTO 探测可以超过窗口，但仍增加 bytes_in_flight
纯 ACK 可以绕过窗口；所有输出仍受反放大与元数据容量约束
```

恢复和 RTT 的包号空间独立；拥塞窗口由单一路径的三个空间共享。实际 `poll_transmit()` 交付才记录时间和字节；UDP EAGAIN 时仍须保存并重试原数据报。

## 逻辑帧交付与物理包在途分开

假设 PN=10 携带某段 CRYPTO，PTO 后 PN=14 重发同一字节。确认 PN=10 说明逻辑数据已交付，可以取消再次重发；PN=14 仍在网络中，其字节不能因此立即从在途中扣除。只有 PN=14 自己获 ACK、被声明丢失或所属密钥空间退役，才扣掉它的物理在途字节。

`PacketRecovery::Space::flight` 独立保存每个在途包的发送时间、线上大小和是否引发 ACK。每空间最多 4096 个物理记录；不会为了释放历史容量而淘汰仍在途的包。旧的逻辑重发队列和近期历史保持各自边界。迟到 ACK 若指向已经声明丢失的包，只更新仍可关联的逻辑交付信息，不重复扣字节或增长窗口。

丢失期限同时检查物理记录，因此逻辑上已被其他副本交付的包、填充 ACK 包仍能按阈值退出在途。仅有不引发 ACK 的填充包时不会为它单独启动 PTO；已有更大包的 ACK 时仍可建立丢失期限。密钥丢弃清除该空间在途，不触发拥塞事件。

## 窗口如何变化

慢启动每确认一个在途包，将其新确认字节加到窗口；拥塞避免按 `1200 × acked_bytes / window` 增长，保留不足一字节的累计信用，避免小包 ACK 被整数除法永久截断。发送受应用或流量限制时不增长：当前没有应用流，采用保守的 ACK 批次前窗口利用率判断，剩余空间至少 1200 字节视为未充分利用。

例如窗口 12000 且已用满，确认 1200 字节可使慢启动窗口变为 13200。第一次确认丢包时窗口减半到 6000；同一恢复期内更早发出的包继续丢失，不会再次减半。恢复开始时及之前发送的包，其 ACK 也不增长窗口。后来发送包的 ACK 才能按拥塞避免增长，比如 `6000 + 1200×1200/6000 = 6240`。

时间戳 0 是合法注入时钟值，用 optional 表达“尚无恢复期”，不能拿 0 兼任哨兵。PTO 超时本身不减窗；必须有实际丢失证据。持续拥塞减到最小窗口的检测仍待实现，不能把连续 PTO 当作它的替代品。

## 发送选择与测试

发送器先非消费地查看待恢复帧、TLS 输出和 ACK，按固定 4 字节包号计算精确线上大小；通过拥塞及反放大检查后才分配包号、保护并交付。阻塞轮询不会消耗包号、CRYPTO offset、重发项或 ACK generation。相比之前持有 Prepared 密文的方式，当前每次根据最新状态重建候选，避免旧的普通包挡住后来的 ACK/PTO。

普通数据被窗口阻塞时尝试 ACK-only 回退；PTO 探测在恢复队列中优先。反放大阻塞暂时隐藏恢复期限，拥塞阻塞继续保留 PTO。大握手回归必须及时交付客户端 ACK，不能只靠重复 Initial 增加反放大额度来无限发送。

`tests/quic_congestion_control.cc` 验证窗口边界、PTO 例外、慢启动、应用受限、恢复期、最小窗口、零时刻及小 ACK 信用；`quic_packet_recovery.cc` 验证物理副本、填充 ACK、迟到确认及空间退役；`quic_handshake_connection.cc` 填满窗口后验证纯 ACK、PTO、实际 ACK 重开窗口和无包号空洞，并保留十种握手丢包及双栈 UDP 回归。

规范依据：[RFC 9002 §2](https://www.rfc-editor.org/rfc/rfc9002.html#section-2)、[§7](https://www.rfc-editor.org/rfc/rfc9002.html#section-7)、[Appendix B](https://www.rfc-editor.org/rfc/rfc9002.html#appendix-B)。

## 验证记录

本阶段验证：QUIC CTest **22/22**（75.70 秒），全量 **53/60**（115.23 秒）。五项既有 30 秒超时为 `wrapping_integers_roundtrip`、`wrapping_integers_extra`、`recv_transmit`、`recv_reorder_more`、`send_transmit`；`net_interface`、`router` 缺少可执行文件。额外的冗余副本丢失/物理容量边界与阈值断言加入后，恢复及 NewReno sanitizer 程序再次通过。独立审查最终无待处理发现；一条阈值建议经 RFC §7.3.2 / Appendix B.6 核对后撤回，保留“先减半 ssthresh、再对 cwnd 施加最小值”的顺序。

后续已接入有界令牌桶 pacing：速率随窗口与 RTT 调整，发送唤醒与恢复期限合并，纯 ACK/PTO 探测保留例外。当前实现与验证见 [pacing.md](pacing.md)。

后续有界应用流及其恢复/流量控制已接入，最新范围和验证见 [application-streams.md](application-streams.md)。
