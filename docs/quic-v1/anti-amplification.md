# QUIC 反放大限制：未验证地址为什么只能发三倍

对应 [RFC 9000 §8](https://www.rfc-editor.org/rfc/rfc9000.html#section-8)、[§8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1) 与 [§9.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3.1)。目前 `quic/anti_amplification.hh/.cc` 实现每个对端传输地址的**发送额度记账**，没有 UDP 收发事件循环；调用方未来仍要把每个数据报正确归属到地址和连接。

## 1. 先看攻击，再看规则

攻击者可伪造受害者的源地址，向服务器发送很小的数据报。若服务器向这个假地址返回大量字节，就变成了攻击者的流量放大器。QUIC 因此规定：**回应**一个尚未验证的地址时，发送的字节数不得超过从它收到的字节数的三倍。建连初期服务器对客户端地址适用此规则；迁移时对端换了新地址，回应者也需要给新地址重新记账。客户端发送首次 Initial，或任一端**主动发起**迁移时，不受此三倍规则限制；它们仍受拥塞控制等其它限制。[RFC 9000 §8](https://www.rfc-editor.org/rfc/rfc9000.html#section-8)、[§21.1.1.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-21.1.1.1)

**自己复述：**陌生地址先寄来 400 字节，我最多回 1200 字节。回满后要等它再寄字节，或证明它真的能收我的包，才能继续发。旧地址先前寄来的额度不能挪给新地址。

## 2. 哪些字节进入账本

记的是**UDP 载荷字节**，包括 QUIC 包头、密文和填充，不是 STREAM 帧应用数据的长度。建连时，只要一个数据报能唯一归属到同一连接，服务器应把它的全部载荷计入接收数；即使报内包最终都被丢弃，也照计。一个 UDP 数据报即便包含多个 QUIC 包，也只按实际 UDP 载荷大小计一次。[RFC 9000 §8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1)

构造 `AntiAmplificationBudget` 时必须明确选择 `AmplificationRole::Responder` 或 `Initiator`。只有回应者从零额度开始并按三倍记账；发起者 `remaining_bytes()` 从一开始就返回 `nullopt`，但 `address_validated()` 仍为 `false`，不能误以为已经验证了地址。`record_received(n)` 只接受字节数，**不会自行判断归属**。未来 UDP/连接层必须先判断这是哪条路径、能否唯一归属，再调用它。每个对端地址应有独立实例；新回应地址的实例从零额度开始。

## 3. 发送时怎样算

未验证时，`remaining_bytes()` 计算 `3 × received − sent`。`record_sent(n)` 先核对本次拟发的**整个 UDP 载荷**是否装得下，再一次性扣账；不足则返回 `false` 且不改变已发送量。这样一个 1200 字节的 `PATH_RESPONSE` 也必须先拿到至少 1200 字节额度；若额度不足，发送层不能违规填充或超额发送，而应遵守 RFC 的反放大例外处理。[RFC 9000 §8.2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2)

例如收到 400 字节，剩余额度 1200；发出 1200 后余额为 0。再收到 100 字节，余额变 300；拟发 301 字节会失败，拟发 299 字节可通过并留下 1 字节。`tests/quic_anti_amplification.cc` 用手算常量检查这些边界，还验证新地址不会继承旧地址额度。

计数使用 `uint64_t`。`record_received()` 对加法做饱和处理，`remaining_bytes()` 在 `3 × received` 会溢出时返回可表达的最大额度，不让溢出把限制绕开。达到该极端数值后可能保守地停止增加额度，但不会多发。实际网络中的其它限制（拥塞窗口、PMTU、流量控制）仍独立生效。

## 4. 什么时候解除

服务器处理完能证明客户端确实收到了其 Initial 的 Handshake 包，或经其他 RFC 允许的地址验证方式确认地址时，连接层可调用 `validate_address()`。此后 `remaining_bytes()` 返回 `nullopt`，含义是**本限制解除**，不是允许无限制网络发送。不能因为仅解析成功一个未认证的帧就调用它。路径迁移时，上一地址的验证结果也不能自动传给新地址；新地址必须用自己的验证过程或规范允许的例外。[RFC 9000 §8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1)、[§9.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3.1)

## 5. 与当前代码的边界

`PathValidation` 负责确认 `PATH_RESPONSE` 与发出的挑战匹配；这个账本负责发送额度。未来迁移控制器需要把两者按地址关联，并在发送每个数据报时先检查额度。当前没有真实 UDP 数据报、TLS 握手和地址来源，因此这两块基础代码**尚未形成可工作的迁移功能**。发包预留若最终没有进入网络，未来发送器还需处理失败时的额度回滚或采用能保证一次性入队的发送接口。
