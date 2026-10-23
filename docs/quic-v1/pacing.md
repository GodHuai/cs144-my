# 单路径发送节奏（pacing）

在 NewReno 窗口之外，`quic/pacer.*` 用字节令牌桶限制发送突发。窗口限制尚在途的字节，pacing 限制当前能交付多少字节；ACK 释放前者，不保证后者立即恢复。该阶段仅覆盖既有固定 1200 字节路径和握手/控制帧，仍缺可靠应用流、持续拥塞检测、ECN 验证和迁移。

## 计算与边界

- 容量为 `min(cwnd, 12000)` 字节，初始信用 12000；空闲补充最多到容量。
- 速率为 `1.25 × cwnd / max(smoothed_rtt_us, 1000)` 字节/微秒。
- 不足时返回绝对期限 `now + ceil((packet_bytes − tokens) / rate)`；期限饱和到 uint64 上限，时钟 0 合法，逆行或非法参数显式报错。
- 参数变化时，先用旧速率、旧容量结算过去的时间，再安装新参数并夹紧信用；窗口扩大不会追溯放大旧信用。

例如窗口 12000、RTT 333000 微秒，速率约 0.045045 字节/微秒。耗尽初始信用后，1200 字节需要等待 **26640 微秒**。速率和有界突发的选择依据 [RFC 9002 §7.7](https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7)。这里只是当前实现策略，不能据此声称完整 RFC 9002。

## 交付、例外与计时器

`poll_transmit()` 在分配包号和消费 TLS/恢复队列之前，检查完整受保护线上大小（含填充和 AEAD 标签）。阻塞候选不推进 CRYPTO offset 或 ACK generation。普通候选被 pacing 阻塞后，尝试纯 ACK 回退。

未填充的纯 ACK 绕过 pacing 且不扣令牌；填充 Initial ACK 仍被 pacing。PTO 探测绕过 pacing，交付时消耗剩余信用至零，不产生负债；仍受反放大和恢复记录容量限制。普通重发仍受 pacing。

只有待发、通过窗口检查而被 pacing 阻塞的候选才建立唤醒。`next_timeout_us()` 取它与恢复期限的较早值；`on_timeout()` 清除已到期的 pacing 唤醒，并独立调用带到期判断的恢复逻辑，不能把 pacing 唤醒当 PTO。每次输入及 poll 重新计算候选；无待发数据时不保留 pacing 空转计时器，反放大阻塞仍暂停发送唤醒。

外部循环使用同一单调微秒时钟：输入或 timeout → poll 到无输出 → 读取下一绝对期限。引擎不创建线程或 sleep。poll 是发送交接点；UDP EAGAIN 后须保存并重试原数据报。

## 测试与审查

`tests/quic_pacer.cc` 覆盖初始突发、分数信用、空闲上限、窗口收缩/扩大、速率变更、PTO 扣除语义、时间零/逆行/溢出。连接测试覆盖令牌先于窗口耗尽、阻塞轮询期限稳定、立即纯 ACK、到期发包、包号连续及空闲计时器清除；既有满窗口 PTO 与大握手反放大回归继续通过。大握手驱动改用注入时钟推进真实 pacing 唤醒。

审查发现窗口扩大时若先按新容量补充，会把旧空闲时间变成额外突发。回归先复现再修复：旧窗口 2400、RTT 100000，耗尽后空闲到 1000000 微秒并扩大窗口到 12000，只能拥有 2400 信用；12000 字节请求应等到 **1064000**。复核后无待处理发现。

QUIC CTest **23/23** 通过（含编译夹具，对应 22 个测试程序）。全量 **54/61**（117.11 秒），未通过项仍是既有五个 30 秒超时：`wrapping_integers_roundtrip`、`wrapping_integers_extra`、`recv_transmit`、`recv_reorder_more`、`send_transmit`；`net_interface`、`router` 缺少可执行文件。日志为 `build/quic-pacing-ctest.log` 和 `build/quic-pacing-full-ctest.log`（忽略目录）。不将专项通过视为全量通过。

后续有界应用流及其恢复/流量控制已接入，最新范围和验证见 [application-streams.md](application-streams.md)。
