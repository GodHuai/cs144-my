# QUIC 连接 ID 池：迁移时为什么要换标识

对应 [RFC 9000 §5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1)、[§9.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5) 与 [§19.15–19.16](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15)。`quic/peer_connection_ids.hh/.cc` 只管理**对端签发给本端、供本端填写 Destination Connection ID** 的池；本端签发 Source CID、路由和真实 UDP 路径切换尚未实现。

## 1. 连接 ID 解决两个不同问题

IP 地址或端口变化时，Connection ID（CID）让收包端仍能把数据报找到原来的连接。另一方面，若两个网络路径都用同一个非零 CID，旁观者就能把它们关联起来，削弱迁移的隐私性。RFC 因而禁止同一 CID 用于不同本地地址或不同目标地址。换路径时，本端要从对端提供的**未用过**的 CID 中取一个。[RFC 9000 §5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1)、[§9.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5)

**自己复述：**对端给我几张不同的“收件编号”。我在旧路线用过一张后，新路线要拿另一张，不能让路过的人凭同一编号认出是同一连接。编号仍都指向对端同一条连接。

## 2. 编号和来源

握手时对端第一个 Source CID 是序号 0；服务器的 `preferred_address` 参数若带 CID，该 CID 是序号 1；此后 `NEW_CONNECTION_ID` 帧再提供后续序号。没有 preferred address 时，第一帧可用序号 1。`PeerConnectionIds` 构造时保存序号 0，`add_preferred_address()` 保存序号 1，`on_new_id()` 接收帧。一个条目同时保存 CID 原始字节和可选的 16 字节 Stateless Reset Token。零长度 CID 在握手中合法，但与 `NEW_CONNECTION_ID` 帧不能混用；该情况下本类允许同一个空 CID 在不同路径继续使用，因为根本没有可换用的非零 CID。[RFC 9000 §5.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1)、[§19.15](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15)

## 3. 新帧为何要先检查，再更新

`NEW_CONNECTION_ID` 帧包含 `Sequence Number`、`Retire Prior To`、1–20 字节 CID 和 16 字节 token。接收端先检查长度、`Retire Prior To <= Sequence Number`、是否与现有序号/CID/token 冲突，再计算**应用本帧退休门槛之后**的活动 ID 数量。若超过本端声明的 `active_connection_id_limit`，返回 `ConnectionIdLimitError`，旧状态完全不变。相同帧重传则返回 `Duplicate`；更低的 `Retire Prior To` 不能把已退休 ID 重新启用。[RFC 9000 §19.15](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15)

例如活动池含序号 0 和 1，本端限额是 2。收到序号 2、`Retire Prior To = 0`，会变成三个活动 ID，应拒绝；若同一序号 2 的帧把门槛设为 1，则先停用序号 0，活动 ID 仍只有 1 和 2，允许接收。源码的 `prospective_active` 就是在提交 `entries_` 前手算这个数量。

## 4. 退休是发送义务，不是丢掉记录

退休门槛只升不降。门槛以下的序号不再供 `select_for_path()` 选择，并加入 `pending_retirements_`。调用方可用 `pending_retirements()` 生成 `RETIRE_CONNECTION_ID` 帧；在相应帧被 ACK 前保留在队列中，ACK 后调用 `acknowledge_retirement()`。若一个很旧的 `NEW_CONNECTION_ID` 后来才乱序抵达，而其序号已低于先前门槛，也需排队退休。但已经发送且确认过退休帧的序号不会因为重复的 `NEW_CONNECTION_ID` 再次排队。`retirement_queued` 标记负责区分这两种情况。[RFC 9000 §5.1.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2)、[§19.15](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15)

路径被放弃时，调用 `retire_path(path_key)` 主动停用该路径的活动 CID，并排队退休帧。这既防止旧 CID 被重新使用，也请求对端补发新 CID；此时池内活动数减一，允许随后接收替代 ID。空 CID 模式没有可退休的非零 CID，返回 `NoPath`。[RFC 9000 §5.1.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2)

资源不能无限消耗。构造时默认最多记录 4096 个历史 CID，测试可设置较小上限；超过上限返回单独的 `ResourceLimitError`，表示本端内存策略耗尽，**不能**误报为对端违反活动 CID 限额。连接层可将其作为本端资源失败关闭。未确认的退休帧最多允许本端声明的活动限额的两倍；新帧若会超过此上限，也先拒绝再修改状态，并返回 `ConnectionIdLimitError`。保留历史记录的目的是检查同一序号/CID 是否被错误地重复分配。这个固定历史上限是本实现的资源策略，**不是 RFC 指定的数值**；极长时间且频繁轮换 CID 的合法连接可能因此关闭，这是目前的实现限制。[RFC 9000 §5.1.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2)、[§20.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1)

## 5. 选哪一张 ID

`select_for_path(path_key)` 要求连接层给出稳定且唯一的**本地 IP/端口 + 对端 IP/端口**组合键。若该路径已有活动 ID，就继续用它；否则取尚未绑定的活动 ID 并把它固定给该路径。已经在旧路径使用过的非零 ID 不会被重新分给新路径。若旧 ID 已被退休，原路径再次发送时也需改用新的活动 ID。池耗尽时返回 `nullopt`，连接层必须等待对端提供新 ID 或采取规范允许的其它处理，不能偷偷复用。[RFC 9000 §9.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5)

`tests/quic_peer_connection_ids.cc` 覆盖了初始/首个新 ID、路径绑定、同帧重传、冲突帧、活动/历史/待确认退休限额、主动退休、先退休再补充、乱序晚到的旧序号、preferred address 和零长度 CID。这个池并不验证收到的帧是否来自经过 AEAD 认证的 1-RTT 包；连接层必须先完成包认证和帧放置校验，再调用它。丢包后的退休帧重发和 ACK 关联也要由连接层调用相关接口完成。
