# 协议/TLS 错误与握手期间关闭通知

本轮把认证错误接到 `CONNECTION_CLOSE` 输出，并补齐握手确认前的多保护级别关闭。承接 [connection-lifecycle.md](connection-lifecycle.md) 的 Closing/Draining、固定三 PTO 期限、流量上限和缓存密文回复机制。

## 错误状态和接收结果分开

认证后的帧格式、包级别限制、非法 ACK、流控或 TLS 错误，现在尽可能先封装传输关闭帧，再进入 Closing。`transport_error()` 保留首个错误，`close_info()` 保存传输类别、错误码和触发帧；原因不发送内部 TLS/OpenSSL 文本。触发错误的 `receive()` 仍返回 Failed；Closing 中后续归属流量也返回 Failed，不代表调用方可以跳过排空 `poll_transmit()`。

`ConnectionReceive::Failed` 是本次接收结果，`ConnectionState::Closing` 是连接仍需保留关闭通知和计时的状态，两者不矛盾。应用事件循环应处理输出和 `next_timeout_us()`，等 Closed 再从连接表删除。原有 `ConnectionState::Failed` 留给无法安全构造关闭包的本地故障，例如时钟倒退、包号耗尽、封包异常或没有可用密钥；这类故障静默清理。对端关闭仍进入 Draining，不回显。

已知触发帧会写入线上 frame_type，例如非法 ACK 为 0x02/0x03、后握手 CRYPTO 为 0x06、放错级别的 HANDSHAKE_DONE 为 0x1e。无法归因到某一帧时写 0，例如解码失败、保留位错误或整组应用流事务失败。

## 第一份 Initial 发生错误如何回复

第一份 Initial 尚未走过 TLS 建立路径，也可能已经认证但帧内容错误。此时只在认证成功或详细解包器明确报告“已认证的保留位错误”后，保存最小回复路由：对端实际 SCID、原始 DCID 和对应 Initial 密钥。这样回复使用正确方向的密钥和对端 CID，而不是猜测。普通 TLS 建立、参数绑定及帧交付仍在完整预检后执行。

错误地址/CID、解包失败或 AEAD 损坏不会触发错误关闭，也不会建立上述错误路由。反放大仍按归属数据报记账，不能把“计入字节信用”误写成“认证成功”。本实现是已分配的单连接引擎，第一份认证 Initial 的最小状态保留到 Closing 到期；尚未提供无状态监听器拒绝路径。

## 为什么需要 TLS 写密钥观察接口

`TlsHandshake::fail()` 会清除所有内部密钥，`secret()` 在失败后仍返回空。证书验证失败可能发生在同一次 `advance()` 中：前半段刚产生 Handshake 写密钥，后半段收到 TLS 告警并清除它。仅在 `advance()` 返回后取密钥，已经太晚。

新增可选 `TlsHandshake::WriteSecretObserver` 构造参数。TLS 产生写密钥时同步通知连接；不通知读密钥，不能重入 TLS，回调抛异常由已有 C 回调边界捕获并以本地错误终止。未传观察器的 TLS 使用方行为不变。

连接仅保留 Handshake 和 1-RTT 两份写密钥的有界副本。独立 RAII 容器声明在 TLS 对象之前，使 TLS 先析构；构造异常也会清除缓存。Handshake 退役立即擦除对应副本；封好关闭密文后，或其它终态清理时，全部副本擦除。临时派生包密钥也由作用域 guard 擦除。没有修改“失败 TLS 不再暴露 secret()”的约束。

## 一个数据报包含哪些保护级别

确认前，关闭包使用仍可用、未退役的 Initial、Handshake 和 1-RTT；确认后只使用 1-RTT。每个组成包在自己的包号空间分配新包号。缓存数据报按 Initial → Handshake → 1-RTT 排列，因为短头包必须位于最后。

包含 Initial 时，先计算后续包的实际长度，再补 Initial 的 PADDING，使整个 UDP 数据报恰好 1200 字节；不把每个组成包各补到 1200。最终长度有显式检查。已退役级别不重新派生回来，任一级别分配包号耗尽则整次关闭不发送。

应用主动关闭在 1-RTT 中保留应用错误码与原因；放进 Initial/Handshake 的副本必须转换为传输关闭：APPLICATION_ERROR=0x0c、frame_type=0、原因清空。`close_info()` 本地仍保留应用原始诊断。因此客户端在发送 Finished 之前关闭时，服务端可以仅用 Handshake 副本获知结束，且低级别包不泄露应用状态。服务端尚未发出 ServerHello 时检测错误，客户端则可仅用 Initial 副本收到通知。依据 [RFC 9000 §10.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3)。

多级别组成一次缓存输出；后续仍只在归属入站流量触发、限速和三倍额度允许时重放同一密文，不重新使用密钥构造新副本，不延长原 Closing 期限。丢弃接收密钥后，已有握手信用不代表独立三倍限制可删除。

## 回归证据与后续

新增或扩展的用例覆盖：

- 第一份 Initial 的未知帧、非法 ACK、放错级别的 HANDSHAKE_DONE，8/20 字节本地 CID，关闭包解密、方向、错误码与触发帧；AEAD 损坏静默。
- 已认证 Initial 保留位错误的关闭回复可解密，代码和 CID 正确，首个错误保持不变。
- 客户端未发送 Finished 的应用关闭：仅转交 Handshake 副本仍能使服务端 Draining，通用错误和空原因不泄露应用诊断。
- 服务端尚未输出 ServerHello 的协议错误：仅靠客户端已有 Initial 密钥即可接收多级关闭。
- 错误主机名导致同次 TLS advance 证书失败：刚生成的写密钥仍能封装 Handshake 错误通知，服务端成功解密并得到原 TLS 告警。
- 确认后应用关闭和协议错误只输出 1-RTT；TLS 写观察器抛异常被隔离，失败后的 TLS secret()/输出/参数仍为空。

行为 RED 分别复现“认证 Initial 错误没有关闭包”“缺少 Handshake 回退”“同次 TLS 失败丢失写密钥”；审查回归另复现“已知触发帧诊断不正确”，随后修复。密钥擦除还依赖 RAII 生命周期和独立代码审查，没有通过读取已销毁内存来声称验证擦除。

仍缺 stateless reset、监听/动态多连接 CID 分发、密钥更新、会话恢复/0-RTT、迁移、PMTU、持续拥塞/ECN 和第三方互通。`close()` 主动应用接口仍要求 TLS 完成；握手中的协议/TLS 错误由引擎自动关闭。

全量首轮还定位了一处性能退化：新错误路由快照原本每个认证应用包都复制字符串，导致既有 129 轮连续建流超出 30 秒（单独 31.18 秒）。同编译参数临时链接上一提交连接/TLS 对象为 28.47 秒；限制为未绑定对端的首次 Initial 才保存快照后，同测试 26.75 秒。独立审查确认后续错误使用既有路由，不依赖重复快照；没有增加超时或减少覆盖轮数。

最终全量 CTest **58/65**（156.85 秒），QUIC **27/27**（含公共编译夹具，25 个程序及其中一个的第二入口）。连续建流29.29秒、握手连接29.10秒、生命周期4.69秒；没有提高测试上限。剩余仍为五项既有30秒超时 wrapping_integers_roundtrip、wrapping_integers_extra、recv_transmit、recv_reorder_more、send_transmit，以及缺少可执行文件的 net_interface、router，无新增失败。命令：ctest --test-dir build --output-on-failure --timeout 30 -j2。最终格式、差异空白和 Markdown 本地链接检查通过。
