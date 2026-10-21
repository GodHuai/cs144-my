# QUIC 本端连接 ID：签发、路由与退休

对应 [RFC 9000 §5.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1) 和 [§19.16](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16)。代码在 `quic/local_connection_ids.hh/.cc`，测试在 `tests/quic_local_connection_ids.cc`。这里管理**本端发给对端、让对端放在 Destination Connection ID 字段**的 ID，与 `PeerConnectionIds` 所管的方向相反。

## 1. 为什么本端要签发多张 ID

对端向我们发送 UDP 数据报时，地址可能因迁移或 NAT 重绑定而改变。收包端可用目标 CID 找到同一连接。为了避免不同路径上的数据报被同一个非零 CID 关联，对端需要可轮换的 CID，而这些 CID 由我们提供。握手包的第一个 Source CID 是序号 0；之后通过 `NEW_CONNECTION_ID` 帧依次签发。若服务器提供 `preferred_address` 传输参数，其 CID 占用序号 1，下一帧从序号 2 开始。[RFC 9000 §5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1)

**自己复述：**对端要给我寄包，目标 CID 就像收件编号。我先给它一个编号，再按需给备用编号；它换路线时用另一张。我得一直认得自己尚未退休的编号。

## 2. 签发前检查什么

构造 `LocalConnectionIds(initial_source_cid, peer_active_limit)` 时保存序号 0。`reserve_preferred_address(cid, token)` 只能在普通签发之前使用，保留序号 1，供传输参数而非 `NEW_CONNECTION_ID` 帧发送。`issue(cid, token)` 分配下一个连续序号，并返回可发送的帧；上层确认该参数或帧确实发出后，须调用 `mark_sent(sequence)`。CID 必须有 1–20 字节，不能等于曾经签发过的 CID；16 字节 Stateless Reset Token 也不能重复。若初始 CID 长度为零，就不能签发其它 ID。CID 和 token 必须由上层使用安全随机源产生，本类只检查形状与重复，不负责生成随机字节。[RFC 9000 §5.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1)、[§10.3.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.2)

对端的 `active_connection_id_limit` 是它愿意同时保留的活动 ID 数；本端不能超过它。因此 `issue()` 在签发前检查 `active_count()`。本实现还默认最多累计签发 4096 个 ID，达到上限后 `issue()` 返回空值，即使先前的 ID 已退休。RFC 允许签发端限制一条连接的总签发量；这个 4096 是实现资源策略，不是规范规定。`issue()` 返回空值也可能表示参数无效或活动池已满，连接层须根据自身策略决定何时重试。[RFC 9000 §5.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1)

## 3. 收到 RETIRE_CONNECTION_ID

对端发 `RETIRE_CONNECTION_ID(sequence)` 表示以后不再用该 CID，也请求我们补发新的 CID。`on_retire(frame, packet_dcid)` 必须同时拿到**承载这个帧的包所使用的目标 CID**。若序号尚未实际发送给对端，或者该序号所指 CID 正是 `packet_dcid`，就返回 `ProtocolViolation`，状态不变。第二项防止一个包一边靠某 CID 路由到连接、一边要求马上废弃它。已经退休的序号再次收到相同退休帧则返回 `Duplicate`。`mark_sent` 标记将“内部已分配”和“网络上已经宣布”分开，避免提前接受恶意退休帧。[RFC 9000 §19.16](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16)

成功退休后，`lookup(cid)` 不再返回该 CID 的序号；负责 UDP 分发的连接层应同步撤销它的路由，并停止使用关联的重置令牌。`needs_replacement()` 表示发生过退休且当前活动数低于对端限额，提醒连接层用新的 CID/token 调用 `issue()`。它不会自动生成随机数据，也不会直接发包。对端收到零长度 CID 时不能发送退休帧，因此本类把这类帧判为协议错误。[RFC 9000 §5.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1)、[§19.16](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16)

## 4. 与完整迁移的距离

`PeerConnectionIds` 管“我拿来发往对端”的 CID，`LocalConnectionIds` 管“我发给对端供它发往我”的 CID。两者都只是状态部件。目前还缺：UDP 包收发与 CID 路由、TLS/AEAD 验证后分发帧、实际路径切换、退休帧的重发与 ACK 关联、新路径拥塞控制，以及随机 CID/token 生成。因此测试能证明这里的状态规则，不能证明两端 QUIC 互通。
