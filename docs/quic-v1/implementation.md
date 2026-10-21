# QUIC v1 实现讲解（进行中）

当前完成 RFC 9000 §16 的变长整数、§17.1 的包号编解码、§12.3 的部分包号空间状态、§17.2–17.3 的部分包头布局（包括版本协商和 Retry 的字段解析）、§18 的传输参数编解码与静态校验、§8.2 的单路径验证状态、§8/§9.3.1 的反放大额度记账、§5.1/§9.5 的对端连接 ID 池、§5.1.1/§19.16 的本端连接 ID 签发与退休状态、§19.1–19.20 的**核心帧线上格式**编解码、RFC 9001 §5.2–5.4 的 Initial 密钥、AES-GCM 载荷和 AES 报头保护基础操作、§5.8 的 Retry 完整性标签，以及 RFC 9002 §5 的 RTT 估计和 §6.2.1 的 PTO 时长计算。它们还没有组成 QUIC 连接；TLS 1.3 握手、Handshake/1-RTT 密钥、Retry 状态机、版本协商处理、ACK 与丢包状态机、UDP 互通仍未完成。扩展帧及逐帧语义也尚未处理。最终以完整协议代码、测试和 `coverage.md` 为准。

这份笔记按初学者能逐步手算的顺序编写：每节先说 RFC 规定什么，再解释为什么，最后回到当前 C++ 源码。笔记中的代码片段只摘取决定行为的语句；完整可编译代码以相应 `quic/*.hh`、`quic/*.cc` 和 `tests/quic_*.cc` 为准，避免复制一份会随实现变化而失真的源码。

## 先建立整体图景

QUIC 运行在 UDP 之上。UDP 只负责把一个数据报送到对端；QUIC 在数据报里放包，在包里放帧。一个数据报可以包含多个**长包头**包。收到数据后，理论上的处理顺序如下，`待实现` 的步骤在当前分支尚不能执行：

```mermaid
flowchart LR
  A[UDP 数据报<br/>待接入] --> B[定位包边界与 pn_offset<br/>packet_header.cc]
  B --> C[生成报头掩码<br/>待实现]
  C --> D[移除掩码并恢复完整包号<br/>header_protection.cc + packet_number.cc]
  D --> E[AEAD 认证与解密<br/>待实现]
  E --> F[检查包号是否已处理<br/>packet_number_space.cc]
  F --> G[解析帧<br/>frame.cc]
  G --> H[更新 ACK、流和连接状态<br/>待实现]
```

`packet number`（包号）给每个受保护包一个号码；`stream offset`（流偏移）标记字节在一条流中的位置。它们不是同一种序号。`pn_offset` 是**数据报内的字节位置**，不是包号。`ACK Delay` 是对端发送 ACK 前有意等待的时间，线上字段还需要依据对端参数换算。源码里的 `std::nullopt` 通常表示输入还不足或格式不支持；抛出的异常多用于调用方要求编码一个不合法值。

当前代码按功能分成小模块，是为了先验证线上格式和数值规则。一个包只有在后续 AEAD 认证通过、帧及连接状态检查成功后，才可能作为有效网络输入处理。单独调用某个解码函数成功，不等于连接已接受这个包。[RFC 9000 §13.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.1)

### 接口速查

| 函数 | 输入中最重要的前提 | 返回值与失败方式 |
| --- | --- | --- |
| `encode_varint` / `decode_varint` | 值不超过 `2^62−1`；解码时 `offset` 指向字段起点 | 编码得字节；截断解码得 `nullopt` 且不推进 `offset` |
| `choose_packet_number_length` / `encode_packet_number` | 使用**同一个包号空间**的最大 ACK；当前包号不复用 | 得 1–4 字节长度及其低位字节；无安全长度则抛异常 |
| `decode_packet_number` | 最大已收包号来自认证成功的包 | 得最接近期望值的完整包号；非法宽度抛异常 |
| `PacketNumberSpaces::allocate` / `record_authenticated` | 一个实例属于一条连接；接收记录只能在 AEAD 成功后调用 | 三个空间独立分配/去重；重复、过旧或越界返回 false |
| `parse_protected_packet` | 输入是数据报，`offset` 是当前包起点；短包头需已知 DCID 长度 | 得 `pn_offset`、`packet_end` 等布局；不支持或截断时得 `nullopt` |
| `build_long_header` / `build_short_header` | 密文长度包括 AEAD tag；包号长度 1–4 | 得未保护包头；不合法构造请求抛异常 |
| `decode_frames` / `encode_frame` | 解码输入应来自已认证的包载荷 | 得帧列表或单帧字节；截断/不支持得 `nullopt`，非法编码请求抛异常 |
| `decode_transport_parameters` / `encode_transport_parameters` / `validate_transport_parameters` | TLS 扩展原始字节；角色验证须提供实际 Initial/Retry 包头里的 CID | 解码拒绝重复/非法值，编码拒绝非法本地值，角色验证返回 `bool`；尚未接入 TLS |
| `PathValidation::start` / `record_sent_challenge` / `on_response` / `expire` | 每条候选路径一个实例；挑战值由安全随机源生成；仅记录实际发送的探测与认证成功的回应 | 返回验证阶段，区分地址可达与 1200 字节 MTU；未接入 UDP 或迁移决策 |
| `AntiAmplificationBudget::record_received` / `record_sent` / `validate_address` | 每个对端地址一个实例；构造时标记发起者或回应者；输入为能唯一归属连接的整个 UDP 载荷字节数 | 回应未验证地址时最多发送接收量的三倍；客户端 Initial 和主动迁移不受该规则限制；尚无 UDP 归属和发送失败回滚接线 |
| `PeerConnectionIds::on_new_id` / `select_for_path` / `retire_path` / `pending_retirements` | 输入来自已认证的包；路径键由连接层提供唯一的本地/远端地址对 | 跟踪对端签发的 CID、退休门槛、路径绑定、旧路径主动退休与资源限额；尚无发送帧、路由和生命周期接线 |
| `LocalConnectionIds::issue` / `on_retire` / `lookup` | CID/token 由上层安全随机生成；退休帧来自已认证的包，须传入承载包的真实 DCID | 连续签发本端 CID，检查退休序号和包 DCID，移除活动 ID；尚无 UDP 分发路由和自动补发 |
| `header_protection_sample` / `apply_header_mask` / `remove_header_mask` | 输入是**单个包**，`pn_offset` 相对包开头；mask 已生成 | 得 16 字节样本；掩码函数以 `bool` 表示能否完整修改 |
| `derive_initial_keys` / `encrypt_initial_payload` / `decrypt_initial_payload` / `initial_header_mask` | 使用客户端首个 Initial 的 DCID；OpenSSL 3 提供密码原语；AEAD 的 AAD 是未遮盖的单包完整包头 | 派生双向 Initial 密钥，使用 AES-128-GCM 加解密及 AES-ECB 产生五字节报头掩码；仅覆盖 Initial 级别 |
| `compute_retry_integrity_tag` / `verify_retry_integrity` | 输入客户端最初的 DCID 和 v1 Retry 原始字节；在改变连接状态前调用 | 按伪包算固定 key/nonce 的 AES-GCM 标签并做固定时间验证；尚未接入 Retry 状态机 |
| `RttEstimator::observe` / `pto_ms` | 时间单位是毫秒；调用者先筛选合法 ACK 样本 | 更新路径 RTT；给出基础 PTO 时长或 `nullopt`，不负责定时器 |

## RFC 9000 §16：变长整数

传输参数也用这里的 varint 表示 ID、长度和整数值；读完本节后可到 [传输参数专题](transport-parameters.md) 手算一段 TLS 扩展字节。

QUIC 的变长整数使用首字节最高两位表示总长度：`00` 为 1 字节，`01` 为 2 字节，`10` 为 4 字节，`11` 为 8 字节。剩余位以网络字节序表示非负整数，最大值为 `2^62 − 1`。[RFC 9000 §16](https://www.rfc-editor.org/rfc/rfc9000.html#section-16)

| 前缀 | 总字节数 | 可用于数值的位 | 最大值 |
| --- | ---: | ---: | ---: |
| `00` | 1 | 6 | `2^6−1` |
| `01` | 2 | 14 | `2^14−1` |
| `10` | 4 | 30 | `2^30−1` |
| `11` | 8 | 62 | `2^62−1` |

想象先看邮包标签就知道接下来要读几字节：首字节高两位是“长度标签”，剩下的位才是数字。例如 37 的最短写法是 `25`：二进制 `0010 0101`，前两位 `00` 表示只读这一字节，其余六位是 37。`40 25` 也能表示 37，因为前缀 `01` 让解码器读两字节。对一般整数字段，解码器允许这种非最短写法；**帧类型**必须使用最短写法，所以 `frame.cc` 不把 `40 01` 当作 PING。

`quic/varint.hh` 暴露 `encode_varint`、`decode_varint` 和上限常量。`quic/varint.cc` 的编码函数根据 6/14/30/62 位边界选最短长度，先按大端顺序写入数值，再在首字节写入长度前缀；超过 62 位直接抛出 `std::out_of_range`。这一接口供后续包头、传输参数和帧字段使用。

解码函数先读最高两位确定需要的总长度，确认输入足够后再累积数值并推进 offset。若输入截断，返回 `std::nullopt`，offset 保持原值，调用者可以在数据报解析层统一处理该错误。一般整数字段允许非最短编码，因此 `0x4025` 与 `0x25` 都解为 37。**帧类型**还有额外的最短编码规则；后续帧解析器必须单独校验，不能仅依赖此通用解码器。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

关键代码（`quic/varint.cc`，注释为阅读提示）：

```cpp
// 编码：6、14、30 位边界决定 1、2、4、8 字节。
if ( value >= ( uint64_t { 1 } << 30 ) ) length = 8;
else if ( value >= ( uint64_t { 1 } << 14 ) ) length = 4;
else if ( value >= ( uint64_t { 1 } << 6 ) ) length = 2;

// 解码：前缀 00/01/10/11 依次对应 2^0/2^1/2^2/2^3 字节。
const uint8_t first = static_cast<uint8_t>( input[offset] );
const size_t length = size_t { 1 } << ( first >> 6 );
if ( length > input.size() - offset ) return std::nullopt;
uint64_t value = first & 0x3f; // 清掉占用高两位的长度标签。
for ( size_t i = 1; i < length; ++i )
  value = ( value << 8 ) | static_cast<uint8_t>( input[offset + i] );
offset += length; // 成功后才提交读取位置。
```

这里的 `input.size() - offset` 是在先确认 `offset < input.size()` 后计算的。它避免直接计算 `offset + length` 时可能发生的整数溢出。编码函数同样先检查 `value <= max_varint`；高于 62 位的数无法由 QUIC 变长整数表示。

`tests/quic_varint.cc` 检查长度边界、62 位最大值、越界拒绝、非最短编码、截断时 offset 不变，以及 [RFC 9000 附录 A.1](https://www.rfc-editor.org/rfc/rfc9000.html#appendix-A.1) 的四组示例字节。测试使用会在 Debug 和 Release 都执行的异常检查。

验证记录：Debug 配置下构建 `quic_varint_sanitized`，`ctest -R '^quic_varint$'` 通过；Release 配置下同一目标编译并直接运行通过。Release CTest 的公共编译夹具在现有 `webget` 链接阶段失败，错误为 `FileDescriptor::CheckSystemCall<int>` 未定义；该夹具失败与新变长整数目标分开记录，尚未作为 QUIC 测试失败处理。

## RFC 9000 §17.1：包号编码与解码

`quic/packet_number.hh/.cc` 选择 1–4 字节的包号字段，只发送完整包号的低位字节。发送端依据当前包号与该包号空间的最大已确认包号选择足够宽的字段；未收到 ACK 时，字段必须装下完整包号，例如包号 128 仍只需一字节，超过四字节可表示的范围则拒绝编码。接收端在报头保护移除后，以“最大已成功认证包号 + 1”为期望值，恢复最接近期望值的完整包号。测试包括 RFC 9000 附录 A.2 的 `0xac5c02` / `0xabe8b3` 长度示例与附录 A.3 的 `0xa82f9b32` 解码示例。

为什么可以只发低位？同一个包号空间里的包号只增不复用，接收方已经知道最近成功认证的最大包号。它把下一号作为“期望值”，在所有低位相同的候选完整包号中挑距离期望值最近的一个。字段太短会产生歧义，因此发送端必须按**最大已确认包号到当前包号的距离**选足够宽的窗口。还没有 ACK 时，对端无法据此缩小范围，必须把当前完整包号装入字段。[RFC 9000 §17.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1)

`choose_packet_number_length()` 的核心判断可手算：若选 `L` 字节，低位窗口大小为 `2^(8L)`，要留一半窗口给前后位置，所以当前与最大已 ACK 包号的差必须**严格小于** `2^(8L−1)`。例如 `0xac5c02 − 0xabe8b3 = 0x734f = 29519`，小于两字节半窗口 `32768`，因此选 2 字节并在线上写 `5c 02`。没有 ACK 时包号 128 完整地装进一字节 `80`，不需要为半窗口额外加一字节。

```cpp
// 摘自 quic/packet_number.cc；不同分支代表两个不同的 RFC 条件。
if ( not largest_acked ) {
  for ( uint8_t length = 1; length <= 4; ++length )
    if ( packet_number < ( uint64_t { 1 } << ( 8 * length ) ) ) return length;
  throw std::out_of_range( "full packet number needs more than four bytes" );
}
const uint64_t unacked = packet_number - *largest_acked;
for ( uint8_t length = 1; length <= 4; ++length )
  if ( unacked < ( uint64_t { 1 } << ( 8 * length - 1 ) ) ) return length;
```

解码先算 `expected = largest_received + 1`，再用 `mask = window − 1` 把期望值的高位与收到的低位拼接为 `candidate`。如果 `candidate` 比期望值落后至少半个窗口，给它加一个完整窗口；如果超前超过半个窗口，减去一个窗口。这样包号低位绕回时仍能恢复。例如最近收到 `0xff`，接着收到一字节低位 `00`，解为 `0x100`，而不是重新回到 0。`largest_received` 必须来自**已认证成功**的包；攻击者随意发来的未认证低位不能改变这个参照值。

`packet_number.cc` 只做数字编解码；下一节的状态类负责分配和去重。输入超出 62 位范围、字段长度不是 1–4 字节或长度不足以安全表达当前未确认范围时，数字函数拒绝操作。完整连接层仍必须结合密钥、ACK 和丢包状态使用这些接口。

### RFC 9000 §12.3：三个包号空间为什么不能混用

RFC 将 Initial、Handshake、Application Data 分成三个包号空间。每个空间从 0 开始独立编号；**0-RTT 和 1-RTT 共用 Application Data 空间**。这意味着合法发包顺序可能是 `Initial #0`、`Handshake #0`、`0-RTT #0`、`1-RTT #1`。若 1-RTT 又从 0 开始，就在同一空间复用了包号；包号还参与保护密钥的 Nonce 计算，因此这是安全错误。发送号码达到 `2^62−1` 时，端点必须停止发送并关闭连接。[RFC 9000 §12.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3)

`quic/packet_number_space.hh/.cc` 用 `packet_number_space(PacketKind)` 把四种受保护包映射到三个状态槽。`PacketNumberSpaces::allocate(kind)` 从对应槽取出当前号码并递增；即使一个包后来没有成功发出，分配过的号码也不会回退。到终止号码时返回 `nullopt`，由**连接层**执行“不再发送且不发送 CONNECTION_CLOSE”的关闭规则。状态对象禁止复制和移动，以免同一连接意外出现两个都能分配相同包号的副本。Version Negotiation 和 Retry 没有包号，所以不传入此接口。

接收端不能只记“最大已收包号”：例如先收到 `5`，再收到乱序的 `3`，二者都可能是新包；随后重到的 `3` 才是重复。`record_authenticated(kind, number)` 用有序的闭区间保存已收号码。例如收到 `5` 和 `3` 后有 `[3,3]`、`[5,5]`；再收到 `4` 时合并成 `[3,5]`，下次任一号码重到都会返回 false。Initial 和 Handshake 各有独立区间，0-RTT/1-RTT 则共用一组区间。`largest_received(kind)` 仍保留最大的认证成功号码，供 `decode_packet_number` 还原线上低位使用。

为什么函数叫 `record_authenticated`？它**不能验证 AEAD**。调用者必须先移除报头保护、恢复完整包号并成功进行 AEAD 验证，再用它检查是否重复；恶意者伪造但验证失败的包不能推进最大包号，更不能占用接收区间。返回 false 表示重复、低于丢弃下限或超过 62 位上限，调用方应丢弃，不能把同一帧再交给应用。[RFC 9000 §12.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3)

保存一生收到的每个不连续包号会耗尽内存，所以 `retire_received_below(kind, minimum)` 可以单调提高下限并裁剪旧区间。比如已有 `[3,5]`，把下限设为 4 后只保留 `[4,5]`；包号 3 随后抵达会被丢弃。它不会把 `largest_received` 降回去。规范提醒下限选择要考虑较大 RTT 和迁移路径上的迟到包；当前**没有** RTT 驱动的自动清理策略，未来连接层必须调用此接口并决定何时安全地提高下限。若连接长期不清理、对端持续发送稀疏包号，区间仍可能增长；这个类不能单独作为抗资源耗尽保证。[RFC 9000 §12.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3)

测试分别验证三个空间的发送编号、0-RTT/1-RTT 共用、乱序后合并与去重、下限不倒退、`2^62−1` 接收边界，以及无效包类型。此处没有实现 ACK 区间生成或发包历史表；收到并记录一个包号也不等于可以立即发 ACK，ACK 发送时机与被确认包所在空间需要单独实现。

## RFC 9000 §17.2–17.3：受保护包头的布局

QUIC 可以把多个长包头包放进同一个 UDP 数据报。要解密其中一个包，接收端先要知道它从哪里开始、在哪里结束、包号字段从哪个字节开始。长包头的 `Length` 字段解决包边界问题：它表示**包号字段加密文载荷**的总字节数，不包括 `Length` 字段本身。短包头没有这个长度字段，所以从其起点一直占用数据报剩余部分。[RFC 9000 §17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2)、[§17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1)

读长包头时，把它看成“固定首字节 → 4 字节版本 → 有长度的 DCID → 有长度的 SCID → Initial 才有的 Token → Length → 包号 → 密文”。在处理前几项时，低位被掩盖的首字节仍能提供长/短形式和长包头类型。用 [RFC 9001 附录 A.2](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2) 的客户端 Initial 包头，可以逐字节定位：

| 数据报字节下标 | 内容 | 读法 |
| --- | --- | --- |
| `0` | `c3` | 长包头、固定比特为 1、Initial；低四位随后会被保护 |
| `1–4` | `00 00 00 01` | QUIC v1 版本号 |
| `5` | `08` | DCID 长 8 字节 |
| `6–13` | `83 94 c8 f0 3e 51 57 08` | DCID |
| `14–15` | `00 00` | SCID 长 0；Initial Token 长 0 |
| `16–17` | `44 9e` | QUIC 变长整数，解为 1182 |
| `18–21` | `00 00 00 02` | 4 字节包号，**仅在去除报头保护后**解释 |
| `22–1199` | 受保护载荷 | `1182 − 4 = 1178` 字节 |

因此 `pn_offset = 18`，`packet_end = 18 + 1182 = 1200`。如果数据报从下标 1200 开始还有字节，可继续解析下一个长包头包；短包头包没有显式 Length，必须放在数据报最后。构造包头的测试直接比对了上面的 RFC 字节，而非只做“自己编码、自己解码”的往返检查。

`quic/packet_header.hh/.cc` 的 `parse_protected_packet()` 从未加密字段读出版本、目的/源连接 ID、Initial Token 和长包头 Length，返回包类型、包号字段起点 `pn_offset` 与包结束位置 `packet_end`。再次以 `packet_end` 为起点调用即可定位下一个拼接的长包头包。短包头的目的连接 ID **没有长度字节**，因此调用者必须从连接状态传入 `short_dcid_length`。两个连接 ID 的 v1 长度均限制为 20 字节；超过界限、字段截断或 Length 超出数据报都拒绝解析。这个接口只接受 v1 Initial、0-RTT、Handshake 和 1-RTT；版本协商包与 Retry 包使用下面的独立入口。

为什么这里不直接读包号？包号长度写在首字节低两位，但这两位已经被 RFC 9001 的报头保护掩盖。解析器只读首字节的长/短格式、固定位和长包头类型，**不使用低位计算包号长度，也不提前检查保留位**。后续应在 `pn_offset + 4` 取 16 字节样本，生成报头掩码，恢复首字节与包号，再用完整包号解开 AEAD，认证成功后才验证保留位和更新接收状态。为保证样本存在，布局解析器要求从 `pn_offset` 到包末尾至少 20 字节。[RFC 9001 §5.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4)

```cpp
// 摘自 quic/packet_header.cc；cursor 此时位于 Length 字段之后。
const auto length = decode_varint( datagram, cursor );
if ( !length || *length < 20 || *length > datagram.size() - cursor )
  return std::nullopt; // 不足以取样，或 Length 指向数据报之外。
layout.pn_offset = cursor;
layout.packet_end = cursor + static_cast<size_t>( *length );
```

这里检查 `20` 并不假设包号长度是 4。RFC 9001 规定样本固定从 `pn_offset + 4` 开始取 16 字节，所以从 `pn_offset` 算起至少要有 `4 + 16 = 20` 字节。若实际包号只占一字节，样本前的另外三字节属于密文，这也是接收端能在恢复包号长度之前先生成掩码的原因。

发送端用 `build_long_header()` 或 `build_short_header()` 构造**尚未保护的**包头和 1–4 字节截断包号。两者都要求调用者提供将来的密文及 AEAD tag 长度 `protected_payload_length`，用它检查样本长度；长包头还会计算 `Length = 包号字节数 + protected_payload_length`。这段未保护包头将来要作为 AEAD 的 associated data；密文生成后才应用报头保护。RFC 9001 附录 A.2 的 Initial 包头 `c3 00 00 00 01 ... 44 9e 00 00 00 02` 是测试向量：包号起点为字节 18，`44 9e` 编出的 Length 为 1182，整个包长为 1200 字节。[RFC 9001 附录 A.2](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2)

`tests/quic_packet_header.cc` 还验证拼接的 Handshake 包、0-RTT 包、带 Token 的 Initial、1-RTT 短包头，以及损坏的连接 ID、Token、Length、版本和固定位。构造函数不会分配包号、不会加密或认证，也不会生成 Retry 完整性标签；本模块的“布局正确”不能当作真实网络包已经有效。

### RFC 9000 §17.2.1：版本协商包

客户端发出服务器不支持的版本时，服务器可以回复 Version Negotiation（VN）包。它的版本字段固定为四字节零，后面依次是目的连接 ID 长度与内容、源连接 ID 长度与内容、每项四字节的支持版本列表。它**没有**包号和 Length，因此占满一个 UDP 数据报；不能拿普通长包头解析器去找下一个拼接包。首字节最高位为 1，其余七位是任意值；其中平时称作 Fixed Bit 的 `0x40` 位，在 VN 中也只是 unused，接收方要忽略。[RFC 9000 §17.2.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1)

`build_version_negotiation(dcid, scid, versions)` 默认把 unused 的 `0x40` 位置 1，符合规范对与其他协议复用时的建议；调用者也能指定完整的七位 unused 值。`parse_version_negotiation(datagram)` 则接受该位为 0 或 1，检查版本为零、两个连接 ID 的长度不越界，以及末尾有完整的四字节版本项。它返回字段内容，不改变连接状态。假设收到的请求包是 `SCID=xy, DCID=z`，服务器回复时应使用 `DCID=xy, SCID=z`；代码中的构造函数按**回复**字段收参数，连接层将来必须负责交换原请求的 ID。

一个容易踩的坑：普通 v1 长包头的连接 ID 最多 20 字节，VN 却不属于某个具体版本，其长度字段可表示最多 255 字节。服务器面对未来版本时不能用 v1 的 20 字节限制决定能否构造 VN；所以 VN 读写独立采用 8 位长度界限。测试用 21 字节 ID 验证这一点。解析出的版本列表并不能直接决定是否切换版本。仅支持 v1 的客户端若已成功处理其他包，或列表仍包含它最初选择的 v1，必须丢弃 VN；否则应放弃当前连接尝试。当前没有连接状态机来执行这些条件。[RFC 9000 §6.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-6.2)

### RFC 9000 §17.2.5：Retry 的字段和安全边界

Retry 的首字节高四位为 `1111`，随后是 v1 版本号、两个有长度的连接 ID、不带长度字段的 Token、最后固定 16 字节的 Retry Integrity Tag。解析时从报文尾部倒数 16 字节划出 tag，中间剩余的都是 Token；Token 为空的包应被客户端丢弃。与受保护的 Initial 不同，Retry 没有包号、Length 或经过报头保护的字段，也占满一个数据报。[RFC 9000 §17.2.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5)

`parse_retry_packet()` 只检查这些字节的布局：v1 版本、CID 不超过 20 字节、Token 非空且尾部有 16 字节 tag。**返回非空并不表示这个 Retry 可信。**攻击者可以任意填入 16 字节 tag，让字段解析照样成功。客户端必须用自己最初发送的目标连接 ID 调用 `verify_retry_integrity()`；失败必须丢弃。在此之前，不得把 Token、服务器连接 ID 或其他字段写入连接状态。`compute_retry_integrity_tag()` 也可供服务器在构造 Retry 时使用。两者的伪包、固定密钥和测试向量详见 [retry-integrity.md](retry-integrity.md)；客户端 Retry 状态机尚未接线。[RFC 9001 §5.8](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8)

可以自己检验是否理解：为何 VN 能容纳 21 字节连接 ID，而 Retry 不能？因为 VN 的格式与版本无关，而这个 Retry 明确带有 v1 版本字段。为何把 Retry 尾部 16 字节切下来还不算验证？因为字节数正确不证明 tag 是用规范密钥、Nonce 和原始目标连接 ID 算出来的。

## RFC 9000 §19：基础帧编解码

QUIC 包通过帧传递控制信息和数据。可以把一个包的明文载荷想成若干张接在一起的“小纸条”：每张先写帧类型，再写该类型约定的字段。接收方必须知道一张纸条在哪里结束，才能找到下一张。`quic/frame.hh/.cc` 的 `decode_frames()` 接收**已经完成 AEAD 认证**的整段载荷，依次解码并返回 `Frame` 列表；空载荷或任何一处格式错误都返回空值，不把已经读出的前缀交给连接层。`encode_frame()` 把单个结构化帧还原成线上字节。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

当前覆盖 RFC 9000 定义的全部**核心帧类型** `0x00`–`0x1e`：数据帧、ACK、流控制、令牌、连接 ID、路径、关闭和握手完成。除类型外，各整数均调用已有的 QUIC 变长整数编解码器。帧类型必须用最短长度，这些核心类型都只占一字节；未知类型和非最短类型会使整段解析失败。**支持线上格式不等于支持扩展帧，也不等于能作为连接处理这些帧。**[RFC 9000 §19](https://www.rfc-editor.org/rfc/rfc9000.html#section-19)

| 帧 | 类型字节 | 主要字段 | 当前代码的表示 |
| --- | --- | --- | --- |
| PADDING | `00` | 无；每字节都是一个帧 | `PaddingFrame{length}` 合并连续 0 |
| PING | `01` | 无 | `PingFrame` |
| ACK / ACK_ECN | `02` / `03` | 最大包号、延迟、区间、可选 ECN 计数 | `AckFrame{ack_delay, ranges, ecn}` |
| RESET_STREAM | `04` | 流 ID、应用错误码、最终大小 | `ResetStreamFrame` |
| STOP_SENDING | `05` | 流 ID、应用错误码 | `StopSendingFrame` |
| CRYPTO | `06` | 偏移、长度、TLS 握手字节 | `CryptoFrame{offset, data}` |
| NEW_TOKEN | `07` | 长度与非空令牌 | `NewTokenFrame` |
| STREAM | `08`–`0f` | 流 ID、可选偏移/长度、FIN、字节 | `StreamFrame` |
| MAX_DATA / MAX_STREAM_DATA | `10` / `11` | 连接额度；或流 ID 与该流额度 | `MaxDataFrame` / `MaxStreamDataFrame` |
| MAX_STREAMS | `12` / `13` | 双向或单向流的累计可开数量 | `MaxStreamsFrame` |
| DATA_BLOCKED / STREAM_DATA_BLOCKED | `14` / `15` | 被阻塞时的连接额度；或流 ID 与额度 | `DataBlockedFrame` / `StreamDataBlockedFrame` |
| STREAMS_BLOCKED | `16` / `17` | 双向或单向流的阻塞数量上限 | `StreamsBlockedFrame` |
| NEW_CONNECTION_ID / RETIRE_CONNECTION_ID | `18` / `19` | 序号、退休阈值、CID、16 字节重置令牌；或被退休的序号 | `NewConnectionIdFrame` / `RetireConnectionIdFrame` |
| PATH_CHALLENGE / PATH_RESPONSE | `1a` / `1b` | 各 8 字节不透明数据 | `PathChallengeFrame` / `PathResponseFrame` |
| CONNECTION_CLOSE | `1c` / `1d` | 错误码、可选触发帧类型、原因长度与原因 | `ConnectionCloseFrame` |
| HANDSHAKE_DONE | `1e` | 无 | `HandshakeDoneFrame` |

`Frame` 是以上结构体的 `std::variant`。`decode_frames()` 只解析格式；例如它能解析出一个 STREAM 帧，却不知道这个流是否允许对端发送、是否超出流量控制额度。`frame_allowed_in_packet()` 和 `frames_allowed_in_packet()` 另行按包类型检查 RFC 表 3 的放置规则；它们仍不知道对端角色、流状态或 ACK 引用的包是否有效。连接层必须先完成解密认证，再调用这些纯函数，最后根据错误性质决定如何处理。[RFC 9000 §12.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)、[§12.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.5)

例如 `06 02 03 61 62 63` 是一个 CRYPTO 帧：类型 `06`、偏移 2、长度 3、数据 `abc`。`0f 04 01 02 78 79` 是一个 STREAM 帧：`0f` 的 OFF/LEN/FIN 三个位全为 1，因此随后是流 ID 4、偏移 1、长度 2、数据 `xy`，且流在偏移 3 处结束。若 LEN 位为 0，数据就延伸到**当前包载荷的末尾**，因此打包器只能把这种 STREAM 放在最后；本模块的单帧编码函数无法替调用者决定排包顺序。[RFC 9000 §19.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6)、[§19.8](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8)

不要把 STREAM 的 `FIN` 误当成“这一个包结束”。它表达**整条流**的最终大小是 `offset + data.size()`；一个包含 `FIN` 的包仍可以有其他帧。如果 LEN 位为 0，STREAM 数据本身才延伸到这个包载荷末尾。代码从类型位决定字段是否存在：

```cpp
const bool offset_present = type & 4; // OFF：没有 Offset 时从流偏移 0 开始。
const bool length_present = type & 2; // LEN：没有 Length 时吃掉载荷余下全部字节。
const bool fin = type & 1;            // FIN：最终流大小是 offset + data.length。
const uint64_t length = length_present
  ? decode_varint( payload, cursor ).value_or( max_varint + 1 )
  : payload.size() - cursor;
```

源码随后用 `valid_end(offset, length)` 检查结果不超过 `2^62−1`，并检查实际剩余载荷是否够长。对 CRYPTO 帧执行同样的末尾检查。`read_data()` 的长度比较先于字节复制，解析失败时整个 `Frame` 列表被丢弃。

ACK 的 `First ACK Range` 表示从最大包号往前连续确认了多少个包。例如 `02 0a 03 01 02 01 01` 表示最大确认包号 10、原始 ACK Delay 3、后续区间数 1；第一个区间是 `[8,10]`，再经过一个缺口和一个区间得到 `[4,5]`。代码保存降序闭区间，检查每次减法不会变成负包号；ACK_ECN 另外读入 ECT(0)、ECT(1)、CE 三个累计值。这里只保留 ACK Delay 的线上整数，尚未按对端 `ack_delay_exponent` 换算，也未根据 ACK 更新已发送包、RTT、丢包与拥塞状态。[RFC 9000 §19.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3)

手算第二个区间时，前一区间最小包号是 8。Gap 的线上值是 1，表示中间有 `1 + 1 = 2` 个未确认包（7、6）；下一区间最大包号因此是 `8 − 1 − 2 = 5`。后续 ACK Range Length 也是 1，表示还要向前多确认一个包，所以最小包号是 `5 − 1 = 4`。源码对应这两步：

```cpp
if ( ack.ranges.back().smallest < *gap + 2 ) return std::nullopt;
const uint64_t range_largest = ack.ranges.back().smallest - *gap - 2;
if ( *length > range_largest ) return std::nullopt;
ack.ranges.push_back( AckRange { range_largest - *length, range_largest } );
```

两次先比较再减法，是为了防止无符号整数下溢。例如前一区间最小包号只有 1，却宣称还隔着两个未确认包，计算会变成负包号；C++ 的 `uint64_t` 不会产生负数，而会绕成巨大正数。解析器必须在这一步拒绝畸形 ACK。

### 新增流停止与额度帧：先读线上的字节

`RESET_STREAM` 是发送方结束自己那一侧的流：`04 25 02 40 40` 依次表示类型 `04`、流 ID 37 (`25`)、应用错误码 2、最终大小 64 (`40 40`)。`STOP_SENDING` 是接收方请求对端停止发送：`05 03 25` 表示流 ID 3、应用错误码 37。两者看似相近，方向不同；是否允许针对某条流发送、收到后如何处理数据，必须由将来的流状态机判断。[RFC 9000 §19.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4)、[§19.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5)

额度帧把“可以发送多少”写成**绝对上限**，而阻塞帧报告自己卡在什么上限。`10 40 40` 表示连接最多允许 64 字节；`11 03 25` 表示流 3 最多允许 37 字节。`14 40 40` 和 `15 03 25` 则是发送方分别报告连接级和流级阻塞，不会自动增加额度。实际连接层收到较小的 `MAX_DATA`、`MAX_STREAM_DATA` 时应忽略，不应把额度降回去；这些状态更新不属于当前编解码器。[RFC 9000 §4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1)、[§19.9–19.13](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9)

`MAX_STREAMS` 的 `12` / `13` 与 `STREAMS_BLOCKED` 的 `16` / `17` 用**类型字节**区分双向和单向；后面的整数都是可开流的累计数量，不是已经开了多少条。流 ID 只有 62 位，其中最低两位是发起方和方向，因此数量上限是 `2^60`，超过它的 `MAX_STREAMS` 或 `STREAMS_BLOCKED` 会被解码器拒绝。[RFC 9000 §19.11](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11)、[§19.14](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14)

源码中两字段帧先连续调用两次 `decode_varint()`，三字段的 RESET_STREAM 调用三次；任一字段截断则 `decode_frames()` 丢弃整段帧列表。`0x12`、`0x13`、`0x16`、`0x17` 共用一次 `maximum_streams <= 2^60` 检查，随后以类型最低位填充 `unidirectional`。测试把八种额度/阻塞帧顺序拼在同一载荷中，检查每个字段并比对重新编码后的字节；这样能抓到“多吃了下一个帧的字节”的错误。还检查了流数量零、`2^60` 上限、`2^60+1` 拒绝和已有 PING 后截断时不返回部分结果。

### 令牌、连接 ID、路径与关闭帧：读定长和变长字段

`NEW_TOKEN` 的 `07 02 ab cd` 表示类型 `07`、长度 2、两字节不透明令牌 `ab cd`。这里的“令牌”是未来连接的地址验证材料，不是应用数据；规范要求非空，所以 `07 00` 必须拒绝。服务器何时发令牌、客户端如何保存和以后使用，属于尚未实现的连接层。[RFC 9000 §19.7](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7)

`NEW_CONNECTION_ID` 按“序号 → Retire Prior To → 一字节 CID 长度 → CID → **固定 16 字节** Stateless Reset Token”解析。`CID` 长度只允许 1–20；`Retire Prior To` 不能大于该帧序号。测试用序号 5、退休阈值 3、CID `ab` 和十六个 `00`–`0f` 字节逐项检查。`RETIRE_CONNECTION_ID` 则只带一个序号。例如 `19 05` 表示退休序号 5。重复序号、已发 CID 清单、重置令牌存储与迁移时使用哪一个 CID 都需要连接状态，解析器尚不能判断。[RFC 9000 §19.15](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15)、[§19.16](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16)

`PATH_CHALLENGE` (`1a`) 与 `PATH_RESPONSE` (`1b`) 各带**恰好八字节**不透明数据。解析器只读出这八字节；未来收到挑战时，连接层要用同样的数据回复，并结合发送路径判断验证是否成功。`HANDSHAKE_DONE` (`1e`) 没有字段，只有服务端在完成握手后可发送；仅解析出它并不意味着可以提前确认握手。[RFC 9000 §19.17–19.20](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17)

`CONNECTION_CLOSE` 有两种**不同布局**：传输错误 `1c` 是“错误码、触发它的帧类型、原因长度、原因字节”；应用错误 `1d` 删去“触发帧类型”。例如 `1c 0a 08 03 62 61 64` 表示传输错误码 10、触发帧类型 8、三字节原因 `bad`。`1d 25 00` 表示应用错误码 37、空原因。源码用 `frame_type` 是否存在与 `application` 标志相互校验，防止编码出错位的字段；解码时以线上类型决定是否读取该字段。原因长度按**字节数**计算，可以为零，规范建议原因文本使用 UTF-8，但本层只保留字节，尚未实现文字验证或关闭状态机。[RFC 9000 §19.19](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19)

解析器对 CID、路径数据和重置令牌使用“先确认剩余长度，再读取固定字节数”的做法；对令牌与原因使用显式长度与 `read_data()`。如果完整明文载荷中任何一帧截断，就返回 `std::nullopt`，避免把前面已读出的帧误交给连接层。测试包含合法相邻帧、空令牌、CID 长度 0 或 21、退休阈值倒置、重置令牌缺字节、路径数据缺字节，以及两种关闭帧原因截断。

CRYPTO 和 STREAM 的“偏移 + 数据长度”不能超过 `2^62−1`。代码先比较剩余字节和长度，再复制数据；ACK Range Count 先受载荷剩余长度约束，以免畸形计数导致无意义的长循环。`tests/quic_frames.cc` 检查组合帧往返、无 LEN 的 STREAM、空 FIN、ACK/ACK_ECN、新增控制帧、空载荷、截断、未知类型、区间下溢、畸形大计数与数值边界。流方向、流量控制、ACK 包号空间和 CRYPTO 加密级别等语义规则仍需连接层实现，不能把“能解析”理解为“可以接受”。

### RFC 9000 §12.4–12.5：一帧能放进哪种包

Frame Type 说明**这是什么帧**；包类型又限制**这里能放什么帧**。例如一串 `02 00 00 00 00` 可以是字段完整的 ACK 帧，但把它塞进 0-RTT 包仍不符合规则。现有 `decode_frames()` 不接收包类型，因而可以独立复用；新函数 `frame_allowed_in_packet(frame, packet_kind)` 在解析后执行第二道检查，`frames_allowed_in_packet(frames, packet_kind)` 要求载荷至少一帧，并逐帧检查。两者只返回布尔值，不假装已经产生或发送 CONNECTION_CLOSE。[RFC 9000 §12.4 表 3](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4)

| 帧类别 | Initial | Handshake | 0-RTT | 1-RTT |
| --- | :---: | :---: | :---: | :---: |
| PADDING、PING、传输层 CONNECTION_CLOSE (`1c`) | ✓ | ✓ | ✓ | ✓ |
| ACK/ACK_ECN、CRYPTO | ✓ | ✓ | — | ✓ |
| STREAM、RESET_STREAM、STOP_SENDING、额度/阻塞、NEW_CONNECTION_ID、PATH_CHALLENGE、应用层 CONNECTION_CLOSE (`1d`) | — | — | ✓ | ✓ |
| NEW_TOKEN、RETIRE_CONNECTION_ID、PATH_RESPONSE、HANDSHAKE_DONE | — | — | — | ✓ |

0-RTT 与 1-RTT 使用**同一个应用数据包号空间**，但不意味着它们能携带同样的帧。特别是 ACK、CRYPTO、HANDSHAKE_DONE、NEW_TOKEN、PATH_RESPONSE、RETIRE_CONNECTION_ID 不能放入 0-RTT；规范允许服务器将收到这些帧视为 PROTOCOL_VIOLATION。Initial/Handshake 中只有 `1c` 传输层关闭帧可以出现，`1d` 应用层关闭帧不行。`ConnectionCloseFrame::application` 决定这一区别；若只看 C++ 结构体名字会漏检。[RFC 9000 §12.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.5)

处理流程应是“认证包 → 解出完整明文 → `decode_frames` → 检查每帧所在包类型 → 结合连接状态执行帧”。字节格式失败、包类型不允许、ACK 引用了未发送的包等属于不同检查；目前只有前两项各自具备基础接口，并没有能产生协议错误的完整连接处理器。测试把现有全部 20 种 Frame 变体（并将 CONNECTION_CLOSE 的两种形式分开）对四种包类型逐项比对 RFC 表 3，也检查空载荷和合法帧后面藏有非法帧的情况。读完可以自问：为什么 ACK 与 CRYPTO 都能放 1-RTT，但不能放 0-RTT？答案是同属应用数据包号空间只说明**包号如何编号与确认**，不取消 0-RTT 的帧放置限制。

## RFC 9001 §5.4：报头保护的掩码操作

`quic/header_protection.hh/.cc` 的 `header_protection_sample` 从包号字段起点往后跳四字节，取得 16 字节密文样本；长度不够返回空值。`apply_header_mask` 先从未保护的首字节读出包号长度，再只异或长报头最低四位或短报头最低五位及对应的 1–4 字节包号。`remove_header_mask` 顺序相反：先恢复首字节，再确定包号长度，最后恢复包号。任何字段不足都在写入前返回失败，因此不会留下半修改的报头。`initial_header_mask()` 已能从 Initial 密钥和样本生成 AES 掩码。RFC 9001 附录 A.2 的客户端 Initial 报头、密文样本与掩码是测试向量；计算过程见 [initial-packet-protection.md](initial-packet-protection.md)。

报头保护隐藏的是一部分报头位与线上包号，不是整个包的加密。接收端至少还看得到长/短格式、长包头类型、版本、连接 ID 与 Length，所以前面的布局解析才有可能运行。保护用的五字节 mask 来自 `pn_offset + 4` 处的 16 字节密文样本；这里的“+4”始终固定，即使线上包号只有 1 字节。[RFC 9001 §5.4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2)

接口边界要特别注意：`packet_header.cc` 返回的 `pn_offset` 是**整个数据报**里的下标，而 `header_protection.cc` 改写的是传入 `std::string` 的第 0 字节。处理拼接包时，调用方要先按 `[包起点, packet_end)` 切出当前包，再把 `pn_offset − 包起点` 传给报头保护函数；直接把整个数据报和全局 `pn_offset` 交进去会改错首字节。当前尚无把两模块接起来的连接层。

发送和接收的处理顺序不完全相同：

1. 发送：先知道明文首字节里的包号长度，产生密文及 mask，再异或首字节的可保护位，最后异或实际的 1–4 字节包号。
2. 接收：首字节的包号长度位已被掩盖，先用 mask 恢复首字节，**此时才能**读出包号长度，再异或相应包号字节。接下来还要恢复完整包号并做 AEAD 认证。

```cpp
// 摘自 quic/header_protection.cc；long 只保护低 4 位，short 保护低 5 位。
const uint8_t unmasked_first = first ^ ( mask[0] & ( first & 0x80 ? 0x0f : 0x1f ) );
const size_t pn_length = ( unmasked_first & 0x03 ) + 1;
if ( packet.size() - pn_offset < pn_length ) return false;
packet[0] = static_cast<char>( unmasked_first );
for ( size_t i = 0; i < pn_length; ++i )
  packet[pn_offset + i] = static_cast<char>(
    static_cast<uint8_t>( packet[pn_offset + i] ) ^ mask[i + 1] );
```

异或同一个 mask 两次能恢复原值，但发送和接收不能简单调用同一个步骤顺序，因为接收端一开始不知道正确的包号长度。`remove_header_mask()` 在检查字段足够长后才修改报文；这一点防止畸形短包留下“首字节已改、包号还没改”的半修改状态。

这两个函数接收**已经生成的五字节掩码**。Initial 包的 AES 掩码和 AES-GCM 载荷认证现由 `initial_keys.cc` 提供，推导与向量见 [initial-packet-protection.md](initial-packet-protection.md)。TLS 产生的 Handshake/1-RTT 密钥、其它算法和整包收发仍未接线；后续收到受保护包时，必须在 AEAD 认证通过后才更新包号空间状态。

## RFC 9002 §5、§6.2.1：RTT 估计和 PTO 时长

`quic/rtt_estimator.hh/.cc` 默认用 333 ms 初始化 `smoothed_rtt`，用其一半初始化 `rttvar`。第一份 RTT 样本会重置这两个估计值；`min_rtt` 保留未扣除 ACK delay 的最小原始样本。之后只有在扣除 ACK delay 不低于 `min_rtt` 时才调整样本；握手确认后还会把对端的 ACK delay 限在其 `max_ack_delay` 之内。按 RFC 给出的 7/8 与 3/4 权重更新平滑值和变动值。`pto_ms()` 计算 `smoothed_rtt + max(4*rttvar, 1 ms) + max_ack_delay`；Initial/Handshake 取 0 ACK delay，应用数据在握手未确认前不给出 PTO 值。`reset()` 用于新路径重新初始化估计器。

RTT 是“发出包到收到确认的往返时间”。若接收方收到包后故意等一会儿才回 ACK，直接把这段等待算入网络往返会偏大，因此估计器可能扣除 ACK Delay。但 RTT 不能被对端报告的 Delay 压到比观测到的最小 RTT 更小。握手确认前也不能用对端声明的 `max_ack_delay` 去截断它。[RFC 9002 §5.3](https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3)

对照 `quic/rtt_estimator.cc` 可以把更新过程写成四步：

```cpp
min_rtt_ms_ = min( *min_rtt_ms_, latest_rtt_ms ); // 先保留原始样本的最小值。
const double allowed_ack_delay = handshake_confirmed
  ? min( ack_delay_ms, max_ack_delay_ms )          // 握手确认后才限制对端 Delay。
  : ack_delay_ms;
double adjusted_rtt = latest_rtt_ms;
if ( latest_rtt_ms >= *min_rtt_ms_ + allowed_ack_delay )
  adjusted_rtt -= allowed_ack_delay;                // 不能扣到 min_rtt 以下。
rttvar_ms_ = 0.75 * rttvar_ms_ + 0.25 * abs( smoothed_rtt_ms_ - adjusted_rtt );
smoothed_rtt_ms_ = 0.875 * smoothed_rtt_ms_ + 0.125 * adjusted_rtt;
```

用测试中的数字手算一次：第一份样本 100 ms 使 `min_rtt=100`、`smoothed_rtt=100`、`rttvar=50`。第二份原始样本 130 ms、ACK Delay 20 ms，握手尚未确认。因为 `130 ≥ 100 + 20`，调整样本为 110 ms；**先用旧的** `smoothed_rtt=100` 计算变动值 `0.75×50 + 0.25×|100−110| = 40` ms；然后更新平滑 RTT 为 `0.875×100 + 0.125×110 = 101.25` ms。原 RFC 9002 §5.3 将这两行的顺序写反，[已核实的勘误 7539](https://www.rfc-editor.org/errata/rfc9002) 给出了正确顺序，附录 A.7 也使用这个顺序。`tests/quic_packet_primitives.cc` 直接检查这些值，能抓住更新顺序出错。

PTO（Probe Timeout）是“等待确认过久时，什么时候尝试发探测包”的时长基础，不等于完整定时器。初始化值手算为 `333 + max(4×166.5, 1) = 999 ms`。在应用数据空间，握手确认后还要加上 `max_ack_delay`；Initial/Handshake 不加。`pto_ms()` 只给出基础时长，真正的定时器还必须考虑是否有引发 ACK 的包在途、包号空间、指数退避、反放大等。[RFC 9002 §6.2.1](https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1)

调用者必须确保 ACK 帧中的 Largest Acknowledged 包是新确认的，且这次 ACK 至少新确认了一个会引发 ACK 的包，才调用 `observe()`。RTT 样本取自 Largest Acknowledged 包的发送时间；这个包本身可以不引发 ACK。该 ACK 处理器尚未实现。这里也没有实现 PTO 定时器、指数退避、包号空间选择或丢包判定。测试覆盖首次样本、ACK delay 上下限、未确认握手的应用 PTO、路径重置和非法输入。

`observe()` 接收的时间单位是**毫秒**，而 ACK 帧保存的是尚未按对端 `ack_delay_exponent` 换算的线上整数。未来 ACK 处理器必须先完成指数和微秒到毫秒的转换，再把合法样本传给估计器；直接把 `AckFrame::ack_delay` 当毫秒会产生错误的 RTT。

## 从这些模块到真正的 QUIC 连接，还差什么

| 规范范围 | 已有的可调用代码 | 必须继续实现的内容 |
| --- | --- | --- |
| RFC 9000 | 变长整数、包号数值编解码与三空间的基础发送/接收记录、部分 v1 受保护包头、VN 构造与解析、Retry 字段解析、`0x00`–`0x1e` 核心帧线上格式与按包类型放置检查 | VN 接受逻辑、Retry 完整性验证及发送、扩展帧、ACK/发送历史与接收区间保留策略、方向/角色与流量控制等帧语义、连接与迁移状态、UDP 数据报组装 |
| RFC 9001 | Initial 密钥派生、AES-128-GCM 载荷认证、AES 报头掩码与样本位置 | TLS 1.3 集成、Handshake/1-RTT 密钥、其它套件、整包接线、密钥更新和丢弃 |
| RFC 9002 | RTT 估计、PTO 基础时长 | ACK 处理、发包记录、丢包判断、PTO 定时器与退避、拥塞控制及 ECN 验证 |

这张表刻意区分“字节格式能解析”和“网络协议能工作”。例如 `AckFrame` 已能保存 `[4,5]` 和 `[8,10]`，但没有发包历史表就无法判断这些包是否真的发过，也无法释放 bytes-in-flight。`StreamFrame` 已能读出流 ID 和 FIN，但没有每流状态与流量控制，便不能把字节安全地交给应用。完整目标见 `requirements.md`；当前事实以源码、测试和 `coverage.md` 为准。

## 验证记录与可复现命令

### 本次逐模块复核

| 模块 | 对照规范与检查重点 | 结论范围 |
| --- | --- | --- |
| `varint` | RFC 9000 §16、附录 A.1；长度边界、非最短编码与截断 | 现有实现和测试中的行为与对照规则一致 |
| `packet_number` / `packet_number_space` | RFC 9000 §12.3、§17.1、附录 A.2/A.3；半窗口、三空间映射、乱序去重与 62 位上限 | 数值接口与基础收发状态已实现；自动记录清理、ACK 及密钥状态尚不存在 |
| `packet_header` / `retry_integrity` | RFC 9000 §17.2–17.3、RFC 9001 §5.4、§5.8；v1 包型、CID、Length、样本与 Retry 标签 | 已实现受保护包头布局、VN 线上格式、Retry 字段解析与标签验证原语；客户端接受规则和 Retry 状态机尚未实现 |
| `frame` | RFC 9000 §12.4–12.5、§19.1–19.20；长度、ACK gap、流终点、包类型限制和本地数值界限 | 核心帧线上字段与按包类型放置规则已实现；角色、方向、包号空间内容及连接语义未实现 |
| `header_protection` | RFC 9001 §5.4；样本位置、首字节掩码宽度、收发操作顺序 | 基础操作与 Initial AES 掩码生成已对照 RFC 向量；其它套件和整包认证接线未实现 |
| `rtt_estimator` | RFC 9002 §5.3、§6.2.1 与勘误 7539；ACK Delay、更新顺序、PTO | 修正一处变动值更新顺序；ACK 处理与定时器未实现 |

这里的“与对照规则一致”仅指表中列出的基础函数及检查过的输入，不代表完整 RFC 一致性或网络互通。独立审阅没有找到其他能复现的基础函数协议错误。还有一个重要接口约定：`PacketLayout::pn_offset` 是**整个数据报**的下标，而报头掩码函数用 `packet[0]` 当作当前包首字节。处理拼接包时，应先切出 `datagram.substr(packet_start, packet_end - packet_start)`，再将 `pn_offset` 换为 `pn_offset - packet_start`；直接传整个数据报会改错首字节。

在虚拟机的 `quic-v1-proposal` 工作树中运行：

```sh
cd /home/huai/minnow-quic-proposal
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
ctest --test-dir build -R '^quic_' --output-on-failure
ctest --test-dir build --output-on-failure -j2
```

补全核心帧并格式化后，QUIC 定向测试（含公共编译夹具）为 **5/5 通过**。同一源码下、无额外 12 秒超时限制的全量 CTest **43 项中 41 项通过**；`net_interface` 与 `router` 因缺少相应的测试可执行文件而未运行，因此全量测试命令退出状态为 8。这组数字是运行记录，不会随着文档编辑自动更新。

代码实现时使用测试先行：先看见缺少接口、缺少 ACK 支持或空载荷缺陷使测试失败，再补实现。独立审查发现的 ACK 取样条件、ACK Delay 上限测试、62 位边界与短包头样本长度问题已修正。本次复核又发现 RTT 变动值与 RFC 9002 勘误的顺序不符：先将断言改为 40 ms，观察到 `quic_packet_primitives` 因得到旧结果 39.6875 ms 而失败；再调整实现顺序，定向测试恢复通过。各里程碑的任务与具体测试范围记录在 `docs/superpowers/plans/2026-10-19-quic-packet-primitives.md`、`2026-10-19-quic-basic-frames.md` 和 `2026-10-19-quic-packet-header.md`。

## 自测：能否用自己的话解释

1. `40 25` 为什么能解为 37，而 `40 01` 不能作为 PING 的帧类型？答：一般 QUIC 变长整数允许非最短形式；帧类型必须用最短形式，PING 应直接编码为单字节 `01`。
2. `pn_offset` 后面只有 19 字节时为什么拒绝？答：报头保护样本必须从 `pn_offset + 4` 开始连续取 16 字节，合计至少 20 字节。
3. 为什么 ACK 的线上值 3 不能直接传给 `observe()` 作为 3 ms？答：它先要按对端 `ack_delay_exponent` 转成微秒，再转换成估计器使用的毫秒；当前代码缺少这层处理。
4. 为什么一个 STREAM 帧带 FIN 不代表 UDP 数据报到此结束？答：FIN 是该**流**的最终大小标记；只有缺少 LEN 位的 STREAM 才占满当前包载荷的剩余部分。
