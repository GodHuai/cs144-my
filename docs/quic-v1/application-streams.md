# 可靠应用流与流量控制（有界里程碑）

`quic/application_streams.*` 现在接入 `HandshakeConnection` 的受保护 1-RTT 路径。支持客户端/服务端发起的双向、单向流，可靠字节读写、乱序与重复处理、FIN、RESET_STREAM、STOP_SENDING，以及协商后的流级/连接级/流数量额度。仍是固定单路径、有限生命周期流数的实现，不宣称完整 QUIC。

## 应用如何使用

握手完成前 `open_stream()` 返回空、写入返回 false。默认传输参数中的流和字节额度为零；应用必须在双方 `config.tls.local_parameters` 配置希望授予对端的额度（编码为 QUIC 变长整数）：

| 参数 | ID | 授予对端什么 |
| --- | --- | --- |
| initial_max_data | 0x04 | 所有接收流最高偏移之和的连接级上限 |
| initial_max_stream_data_bidi_local | 0x05 | 本端发起的双向流，对端向本端发送的字节上限 |
| initial_max_stream_data_bidi_remote | 0x06 | 对端发起的双向流，对端向本端发送的字节上限 |
| initial_max_stream_data_uni | 0x07 | 对端发起的单向流接收上限 |
| initial_max_streams_bidi / uni | 0x08 / 0x09 | 对端累计可开的双向/单向流数量 |

发送侧参数是**对端**授予的值。因此本端发起双向流的发送上限用对端 0x06；应答对端发起的双向流用对端 0x05。这两项不能因测试中数值相同就混为一项。

```cpp
// 已完成 TLS，且双方显式配置了足够的传输参数。
if (auto id = connection.open_stream(false)) {
  bool accepted = connection.write_stream(*id, "hello", true);
  // accepted 表示接纳到有界发送缓冲，不表示数据已到达对端。
  (void)accepted;
}
for (auto id : connection.stream_ids()) {
  auto result = connection.read_stream(id, 4096);
  // result.data 是本次连续字节；eof 表示最终大小之前的字节均已读取。
  // reset_error 表示对端 RESET 的应用错误码，与正常 EOF 分开。
}
```

`write_stream` 全部接纳或返回 false，不进行部分写入；FIN 后不再允许追加。`reset_stream(id,error)` 取消本端发送，`stop_sending(id,error)` 请求对端取消发送；双向流两半互不连带终止。`stream_send_buffered()` 包含排队及未确认的应用数据。

流 ID 低位区分发起方与方向：客户端双向/单向从 0/2 开始，服务端从 1/3 开始，同类递增 4。对端较高编号隐式打开较低同类流；STREAM、RESET、STREAM_DATA_BLOCKED，以及双向流的 MAX_STREAM_DATA/STOP_SENDING 都能建立状态。`stream_ids()` 枚举已实体化状态，隐式较低流可按 ID 读写，不为所有占位流立即分配内存。

## 接收与额度的手算

接收端保存触及或重叠区间，只交付从当前读取偏移开始的连续字节。先收到 `[3,6)` 且 FIN，再收到 `[0,3)`，不会提前返回 EOF；读取到偏移 6 后才返回 EOF。重复或重叠字节不重复交付，已接受重叠内容优先保留。

流量控制按每条流的**最高已接收偏移**计算。若流 0 只收到 offset=11 的一个字节，连接额度仍消耗 12，而不是 1；另一个流也这样接收，总计消耗 24。乱序缺口占额度，可防止稀疏数据绕过限制。重复与重传不会再次消耗这些额度。

应用读出 N 字节后，连接 MAX_DATA 增加 N；最终大小未定的流 MAX_STREAM_DATA 也增加 N。更新使用绝对单调上限，较旧较小值被忽略。未发送更新按类型/流 ID 合并，已发送更新交给恢复层可靠重传。额度阻塞报告 DATA_BLOCKED、STREAM_DATA_BLOCKED、STREAMS_BLOCKED，同一上限不反复产生新报告。

FIN 或 RESET 的最终大小不能小于已见最高偏移，也不能与已有最终大小冲突。RESET 即使没有实际交付缺口字节，也先按 final_size 计入连接额度，再释放未消费部分，避免取消流绕开记账。重复 RESET 幂等并保留第一个应用错误码；活跃流随后数据仍检查最终大小但不再交付。完整关闭后丢弃最终大小细节，迟到帧策略见 [stream-retirement.md](stream-retirement.md)。

每个受保护包的所有应用帧在临时状态中验证，全部成功才提交；非法方向、越限或最终大小冲突不会留下部分已接纳数据并继续 ACK。错误分别为 STREAM_STATE_ERROR (0x05)、STREAM_LIMIT_ERROR (0x04)、FLOW_CONTROL_ERROR (0x03)、FINAL_SIZE_ERROR (0x06)、偏移编码错误 (0x07)。

## 发送、确认与取消

发送器轮询不消费候选；新 STREAM 最多携带 600 字节，按流轮转。通过准确线上大小、拥塞、反放大及 pacing 检查并交接数据报后，才推进 STREAM offset 和新发送字节额度。普通重传复用逻辑帧身份，以新包号重新保护，不推进流量额度。

恢复层 `acknowledged` 新增可选逻辑交付回调：同一帧任意副本首次被确认时调用一次，释放对应发送缓冲范围；乱序 ACK 可以先释放后部范围。物理在途字节独立保留到每个副本自己的 ACK、丢失或退役。

RESET final_size 采用最高**已交接**偏移。未交接的后缀及未发出的 FIN 可以取消；已交接 FIN 后不能改变最终大小。仅 FIN 尾部被 ACK 而前缀尚未确认时，流仍不能视为交付完成。已交接 STREAM 即使遇到 RESET，恢复层仍可能重发；这些字节的缓冲额度保留到数据 ACK 或 RESET 交付并取消旧恢复任务，不能靠反复 RESET 绕过接纳上限。

## 资源边界与未完成项

- 连接发送缓冲：最多 1 MiB 应用字节，包含跨流排队和未确认的数据；RESET 仅立即释放未交接后缀，RESET 被确认后释放剩余缓冲并取消旧 STREAM 恢复。
- 本端配置的连接接收窗口及各流初始窗口：各不超过 1 MiB。接收字节负载受连接窗口约束；区间和流状态另有元数据开销，不能把它解释成整个进程只用 1 MiB。
- 本端初始授予的流数量及本地同时占用资源上限：每方向每发起方 128。现已按终态回收并可靠补额，可持续递增创建新流；应用需保存已观察的终态结果。详见 [stream-retirement.md](stream-retirement.md)。
- 可靠性沿用有界恢复记录容量；仍缺第三方互通、全面模糊测试和完整 RFC 状态审计。监听/关闭计时、会话恢复/0-RTT、迁移、持续拥塞/ECN、密钥更新等仍未实现。

设计与协议依据见 [RFC 9000 §2–4](https://www.rfc-editor.org/rfc/rfc9000.html#section-2)；这里只说明当前工程实现的子范围。

## 验证记录

`quic_application_streams` 覆盖方向/隐式打开、非对称额度、乱序/重叠/FIN、原子拒绝、稀疏偏移/RESET 额度、跨流缓冲上限与 ACK 回收、累计流数量上限。`quic_stream_connection` 以实际 TLS/包保护连接传输 9 KB 数据并注入乱序、重复、数据和 ACK 丢失；4 字节窗口验证读取补额及 MAX 帧丢失恢复；同时覆盖双向应答、单向空 FIN、STOP/RESET。恢复测试明确验证重复副本与迟到 ACK 的逻辑回调只发生一次，物理记账仍独立。

两项状态/资源回归均先复现失败再修复：FIN 尾部先确认时仍允许重置未完成发送；RESET 不能提前释放恢复层仍保留的数据额度。最终全量 CTest **56/63**（151.12 秒），其中 QUIC **25/25**（含编译夹具，对应 24 个测试程序）通过。未通过的仍是既有五个 30 秒超时：`wrapping_integers_roundtrip`、`wrapping_integers_extra`、`recv_transmit`、`recv_reorder_more`、`send_transmit`；`net_interface`、`router` 缺少可执行文件。日志 `build/quic-stream-full-ctest.log`（忽略目录）；初轮专项 25/25 日志为 `build/quic-stream-ctest.log`。审查补充测试后全量再次覆盖所有 QUIC 用例，独立复核无待处理阻塞项。

后续已实现流终态回收、紧凑关闭 ID 区间与可靠 MAX_STREAMS 补额，最新语义和验证见 [stream-retirement.md](stream-retirement.md)。
