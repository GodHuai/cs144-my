# ACK 与有界发送记录

`quic/acknowledgments.*` 提供三包号空间隔离的即时确认策略，`HandshakeConnection` 在 AEAD 验证和完整帧预检后接入。PING、CRYPTO、HANDSHAKE_DONE 触发确认，ACK/PADDING/关闭不触发。认证重复包可以重新触发 ACK，但不重复交付；窗口外旧包与认证失败包不触发 ACK。

每空间保留最近 4096 个包号的接收区间，一帧最多编码最新的 32 个区间。较旧区间可能从 ACK 中省略，后续恢复实现须能处理这种情况。ACK 尽量与同级 CRYPTO 或控制帧一起发送，否则独立发包；所有 Initial 数据报仍为 1200 字节。携带 ACK 时 CRYPTO 片段最多 400 字节，其他时候最多 600，避免稀疏 ACK 挤掉 CRYPTO。Application 的 ACK Delay 来自最大已收包首次到达至构建 ACK 的 steady_clock 微秒差，并按本地 ack_delay_exponent 编码；Initial/Handshake 为零。未实现 delayed ACK 定时策略。

发送记录只在 `poll_transmit()` 真正交付数据报时更新。反放大暂停的 Prepared 包不算已发送。各空间实际交付的包号连续，故最高已交付包号足以检查整个 ACK 是否确认未发送包；空间退役后不再发送。完整包内所有 ACK 先预检，才删除被确认记录，重复 ACK 幂等。

每空间最多记录 4096 个尚未确认、会触发 ACK 的包号。达到上限时暂停该空间的新 CRYPTO/PING/HANDSHAKE_DONE，仍允许 ACK-only 输出。ACK-only 包没有逐包保存，只推进已发送上界。`packets_awaiting_ack(kind)` 提供当前数量；该接口不表示字节在途或拥塞窗口。密钥退役和终止清除相应记录。Prepared ACK 用接收 generation 防止在暂停期间收到的新包被旧 ACK 快照误标为已确认。

测试包含区间合并、稀疏范围上限、独立空间、ACK Delay、重复/旧包、发送容量与释放、ACK 幂等、未发送包拒绝；连接测试解密检查实际 Initial ACK，并验证受保护握手、双向 PING、重复包重新确认、坏标签静默丢弃、ACK-only 静止和 IPv4/IPv6 UDP 回环。

尚未实现 RTT 样本接线、发送时间记录、CRYPTO 发送缓冲回收、丢包阈值/PTO/重传、拥塞控制、ACK_ECN 验证、ACK 频率协商。丢失关键握手包仍会停滞，因此这仍不是可靠的完整 QUIC 传输。


本轮验证：QUIC CTest 20/20；全量 51/58。既有超时为 wrapping_integers_roundtrip、wrapping_integers_extra、recv_transmit、recv_reorder_more、send_transmit；net_interface 与 router 缺少可执行文件。独立审查未发现 Critical/Important/Minor 问题，并独立运行两个 sanitizer 测试通过。因既有全量失败，本轮仅保留分支内本地提交。
