# ACK 与有界发送记录

`quic/acknowledgments.*` 提供三包号空间隔离的即时确认策略，`HandshakeConnection` 在 AEAD 验证和完整帧预检后接入。PING、CRYPTO、HANDSHAKE_DONE 触发确认，ACK/PADDING/关闭不触发。认证重复包可以重新触发 ACK，但不重复交付；窗口外旧包与认证失败包不触发 ACK。

## 接收范围与 ACK Delay

每空间保留最近 4096 个包号位置的接收窗口，一帧最多编码最新的 32 个区间；不是保存 4096 个任意跨度的区间。较旧区间可能省略。比如收到 `{0,2,3}`，降序范围为 `[2,3]`、`[0,0]`；Largest=3、First ACK Range=1、ACK Range Count=1、Gap=0、下一范围长度字段=0。Gap=0 表示跳过一个包号。

ACK 尽量与同级 CRYPTO 或控制帧一起发送，否则独立发包；当前连接的 Initial 数据报均为 1200 字节。新 CRYPTO 携带 ACK 时片段最多 400 字节，其他时候最多 600；恢复帧保留原 offset/data，可能沿用原来的较大片段。Application ACK Delay 来自最大已收包首次到达至构建 ACK 的单调微秒差，按本地 ack_delay_exponent 编码；时钟可注入，默认 steady_clock。Initial/Handshake 为零。尚无 delayed ACK 定时策略。

## 已发送上界与活动记录

发送记录只在 `poll_transmit()` 真正交付数据报时更新。反放大或拥塞暂停的候选包不算已发送；当前只在通过门控后分配包号。各空间实际交付的包号连续，故最高已交付包号足以检查 ACK 是否确认未发送包。整个包内所有 ACK 先预检，再更新记录，重复 ACK 幂等。ACK 使用接收 generation 标记已交付快照；阻塞后重新选择最新 ACK，不保留旧 Prepared 密文。

每空间最多记录 4096 个活动、会触发 ACK 的包号。达到上限时暂停新 CRYPTO/PING/HANDSHAKE_DONE，包括恢复探测，仍允许 ACK-only 输出。ACK 模块不逐包保存 ACK-only；恢复模块另行保存近期发送时间，因此最大新确认包即使为 ACK-only，也可能用于 RTT 采样。详见 [loss-recovery.md](loss-recovery.md)。

`packets_awaiting_ack(kind)` 返回活动包数量；记录会因 ACK、声明丢失或同一逻辑帧的其他副本交付而释放，所以它不是字节在途或拥塞窗口。物理字节与窗口由 `congestion_stats()` 单独提供，见 [congestion-control.md](congestion-control.md)。密钥退役和连接终止也会清理记录。

## 测试和剩余边界

`tests/quic_acknowledgments.cc` 覆盖区间合并、稀疏范围上限、独立空间、ACK Delay、重复/旧包、发送容量与释放、ACK 幂等及未发送包拒绝。连接测试解密检查 Initial ACK，验证受保护握手、双向 PING、重复包重新确认、坏标签丢弃、ACK-only 静止和 IPv4/IPv6 UDP 回环。

RTT、发送时间、阈值丢包和握手 PTO 已实现；NewReno 基础窗口已接入；仍缺 CRYPTO 发送缓冲按 ACK 回收、可靠应用流、持续拥塞/pacing/ECN 验证与 ACK 频率协商。恢复只保证现有有界测试场景，不能据此宣称完整可靠传输。

握手恢复基准 `7abc5c7` 的验证记录为 QUIC CTest 21/21、全量 52/59；失败项目及恢复测试范围见 [loss-recovery.md](loss-recovery.md)。后续 NewReno 阶段验证为 QUIC 22/22、全量 53/60，见 [congestion-control.md](congestion-control.md)。
