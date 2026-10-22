# 握手丢包恢复与 RTT 接线

`quic/packet_recovery.*` 在已有 ACK 连接上增加发送时间、RTT 样本、包号/时间阈值、重发队列和 PTO。当前覆盖握手 CRYPTO、HANDSHAKE_DONE 和 PING；没有实现拥塞控制、bytes-in-flight、pacing、持续拥塞、ECN 验证或可靠应用流，因此仍不是完整 RFC 9002 传输。

## 事件循环接口

`ConnectionConfig::clock_us` 可注入单调微秒时钟，默认 steady_clock。`next_timeout_us()` 返回同一时钟的绝对期限，事件循环在到期时调用 `on_timeout()`，再排空 `poll_transmit()`。每次接收、发送或计时器回调之后重新读取期限，不能沿用旧期限。没有内部线程或 sleep。示意：

```cpp
while (auto output = connection.poll_transmit()) {
  // Send via UDP; EAGAIN requires retaining this exact datagram.
}
auto deadline = connection.next_timeout_us();
// Wait for UDP input or this deadline using the same monotonic clock.
// On input: connection.receive(datagram); on expiry: connection.on_timeout();
```

实际交付 `poll_transmit()` 才记录发送时间；UDP EAGAIN 时仍须保留并重试同一数据报，调用者排队等待时间会算入 RTT。时钟逆行使连接以本地 INTERNAL_ERROR 终止。首发之前没有 PTO；反放大导致 Prepared 包暂停时，期限暂时为空，新的有效路由数据报增加额度后恢复调度，避免轮询同一过期时间。

## RTT 与确认

只在 ACK 的 Largest Acknowledged 是新确认包、且本次至少新确认一个会触发 ACK 的包时采样。样本取最大包号的实际发送时间，即使该包是 ACK-only；同一微秒的样本取 1 微秒。Initial/Handshake 忽略 ACK Delay；Application 按对端 ack_delay_exponent 把整数恢复为微秒，再换算毫秒传入已有 `RttEstimator`。握手确认后由估计器按对端 max_ack_delay 限制扣除值。`rtt_estimate()` 返回快照。

密钥退役可以先于实际收到该空间的 ACK；这种情况下不强求每端已在握手期间取得 RTT 样本，后续 PING 的 ACK 可以建立样本。发送元数据只在最近有界历史内可用，已淘汰的旧记录不再提供 RTT 样本。

## 阈值、PTO 与重发

三个空间独立记录最大已确认包号。较小的未确认包满足包号差至少 3，或发送后超过 `max(1ms, 9/8 × max(latest_rtt, smoothed_rtt))`，才声明丢失；时间阈值期限优先于 PTO。ACK 的稀疏范围只遍历已存记录，不逐个遍历 62 位包号。

PTO 基于已有估计器，初始为 999ms，Initial/Handshake 不加 max_ack_delay；Application 必须握手确认后才启用。连接共享指数退避，PTO 到期排队一个探测帧，**不会把未确认包直接标成丢失**。没有新数据时重发最早未交付信息；客户端仍不确定服务端已完成地址验证且没有在途包时，用当前可用的 Handshake 或填充 Initial PING 防止死锁。客户端收到 Initial ACK 不重置退避。

重发的是帧，重新使用包保护与新包号，不重放旧密文或旧 ACK。CRYPTO offset/data 保持原值，TLS 新数据游标不重复推进。不同发送副本共享逻辑交付身份，任一原包或副本被确认都会取消冗余排队任务；迟到 ACK 在最近历史可保留期间仍能找到这个身份。Prepared 已构建时若交付状态变化，可能仍发送一次冗余帧，协议允许对端去重。空间退役、关闭或失败清除该空间的计时器、记录与队列。

## 资源边界和剩余工作

每空间最多 4096 个活动发送记录、4096 个最近的丢失/被替代/ACK-only 记录，最多 4096 个等待重新发送的逻辑帧；同一身份只排队一次。活动容量满时保留原有发送背压，包括探测包，直至 ACK 或声明丢失释放容量；无限丢包/永久不确认不保证进展。退避和期限使用饱和算术。CRYPTO 发送缓冲的按 ACK 回收、流数据恢复、拥塞约束和外部互通仍待完成。

测试使用注入时钟验证初始/退避期限、时间与包号阈值、ACK-only 最大包 RTT、ACK Delay 单位、零间隔样本、迟到 ACK、重复超时回调、反放大暂停和密钥退役；连接故障注入分别丢弃客户端 Initial、服务端 Initial、服务端 Handshake 分片、客户端 Finished、HANDSHAKE_DONE 及其 ACK；另连续丢失三份 Initial/Handshake/Finished/HANDSHAKE_DONE，共十种场景，要求双方最终确认。真实双栈 UDP 回归继续保留。

规范依据：[RFC 9002 §5–6](https://www.rfc-editor.org/rfc/rfc9002.html#section-5)、[RFC 9000 §13.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3)。逐项符合性仍见覆盖表，不以这些测试代替完整互通证据。


计时器回调会先核对当前选定期限，过期登记或提前到达的回调不会越过尚未到期的丢失计时器触发 PTO。Initial/Handshake 退役幂等，重复收发握手包不会重复重置全连接退避。恢复中“对端已完成地址验证”在服务端角色恒成立；它与服务端是否验证了客户端地址的反放大状态分开，故服务端 Initial ACK 会重置退避，客户端 Initial ACK 仍不会。

代码基准 `7abc5c7` 的验证记录（本次文档整理未重跑）：QUIC CTest **21/21**（21.00 秒）；全量 **52/59**（107.85 秒）。既有超时：wrapping_integers_roundtrip、wrapping_integers_extra、recv_transmit、recv_reorder_more、send_transmit；net_interface、router 缺少可执行文件。独立审查的三项计时器问题均通过失败复现与修复后验证，未留下 Minor。当前只保留隔离分支的本地提交。
