# QUIC 路径验证：迁移前怎样确认新地址可达

对应 [RFC 9000 §8.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2) 与 [§9](https://www.rfc-editor.org/rfc/rfc9000.html#section-9)。目前 `quic/path_validation.hh/.cc` 实现**单条候选路径的验证状态**，尚未与 UDP 地址、连接 ID、反放大额度、拥塞控制或真实连接的迁移决策接线。`tests/quic_path_validation.cc` 验证状态转换和错误输入。

## 1. 为什么收到新地址的包还不够

QUIC 连接靠连接 ID 标识，因此对端 IP 或端口改变时理论上可以延续同一连接。但收到带正确连接 ID 的包，并不证明对端确实能**接收发往新地址的包**。它可能是经 NAT 变化后的真实对端，也可能是攻击者伪造来源地址。RFC 因而要求在新路径上发 `PATH_CHALLENGE`，等对端回相同数据的 `PATH_RESPONSE`，再相信这条路径可达。连接迁移只有在握手确认后才能由端点主动发起。[RFC 9000 §8.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2)、[§9](https://www.rfc-editor.org/rfc/rfc9000.html#section-9)

**自己讲一遍：**我向“新门牌”寄一张随机数字卡片。只有确实能收到卡片的人，才容易把同一个数字回给我。回复能从另一条路回来；它证明的是我**寄出卡片时选的那条路**。因此验证器按发出挑战的目标路径保存状态，不要求回应从相同路径到达。

## 2. 一次验证有哪些状态

| 状态 | 含义 | 下一步 |
| --- | --- | --- |
| `Idle` | 尚无验证尝试 | 发送挑战后 `start()` |
| `Validating` | 有待匹配的挑战 | 收到对应回应或超时 |
| `AddressValidated` | 回应匹配，但对应挑战所在数据报小于 1200 字节 | 再发一个至少 1200 字节的挑战 |
| `Validated` | 至少 1200 字节挑战的回应匹配 | 新路径的地址和最低 MTU 已验证 |
| `Failed` | 验证期限已到 | 可由连接层决定重试、留在旧路径或关闭 |

RFC 要求用不可预测的 8 字节挑战值；`PathValidation::start` 和 `record_sent_challenge` **不生成随机数**，而是接收连接层由密码学安全随机源产生的 `std::array<uint8_t, 8>`。调用方须在数据报实际发出后记录挑战，不能先登记一个根本没有发出的探测。`used_` 拒绝同一次尝试中复用挑战值；`pending_` 同时保存尚未回应的挑战及其数据报是否达到 1200 字节。重试必须使用新值，旧值仍可在期限内匹配。[RFC 9000 §8.2.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1)

## 3. 为什么要区分“地址”与“MTU”

`PATH_RESPONSE` 内容与曾经发出的挑战完全相等时，地址可达性验证成功。但如果挑战放在小于 1200 字节的数据报中，这次交换没有证明该路径能携带 QUIC 要求的最小数据报；RFC 要求再发送一个扩到至少 1200 字节的挑战。`on_response()` 从 `pending_` 取出匹配项：小数据报使状态变为 `AddressValidated`；达到 1200 字节使状态变为 `Validated`。未知或重复的回应不会改变状态，ACK 一个挑战包也不算验证成功，因此本类没有“凭 ACK 验证”的接口。[RFC 9000 §8.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.3)

例如在 `t=100 ms` 发 1199 字节挑战 A，在 `t=130 ms` 收到 A 的回应：状态只能到 `AddressValidated`。再发 1200 字节挑战 B，在 `t=140 ms` 收到 B 的回应：状态才到 `Validated`。如果 B 的回应先到，A 的回应后到，B 已足以完整验证；后到的 A 不会把状态降级。

## 4. 期限与失败

RFC 建议把验证期限设为当前路径 PTO 和新路径 PTO 中较大者的三倍，以容忍一次探测或回应丢失。`PathValidation` 接受调用方给的 `timeout_ms`：`start()` 保存第一阶段的绝对截止时间。如果第一次探测小于 1200 字节，首次发出至少 1200 字节的 MTU 探测时，`record_sent_challenge()` 会用该次发出的时间和超时值开启**第二阶段期限**。这个探测可以在小探测的回应之前或之后发出；两种顺序都不能沿用快到期的第一阶段计时器。重复发送同一阶段的挑战不会反复延长期限。`expire(now_ms)` 在 `now_ms >= deadline` 时转为 `Failed`，`on_response()` 也先检查期限，避免过期回应误判成功。零超时被拒绝。截止时间加法做饱和处理，避免 `uint64_t` 溢出。连接层将来需要从 RFC 9002 恢复状态计算 PTO，并决定失败之后是否继续使用其他可用路径。[RFC 9000 §8.2.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.4)

## 5. 到完整迁移还差什么

收到 `PATH_CHALLENGE` 的端点必须把同一 8 字节值装进 `PATH_RESPONSE`，并在**收到挑战的那条路径**发回应；除反放大限制外，要把含回应的数据报填充到至少 1200 字节。`frame.cc` 已能编解码这两种帧，但当前没有收包事件循环来触发回应，也没有发送器来选择路径、填充、执行反放大检查。[RFC 9000 §8.2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2)

完整连接迁移还必须判断握手是否确认、处理 `disable_active_migration` 与服务器 preferred address、管理新旧连接 ID、验证对端地址、限制未验证路径上的发送量、重置新路径拥塞状态并处理 NAT 重绑定。当前状态类不执行这些决策，也不代表能在网络上完成迁移。后续连接层应为每个候选路径持有一个 `PathValidation`，将 `Validated` 作为路径可用的一个必要条件，而非唯一条件。
