# Handshake 与 1-RTT 整包保护

当前 `quic/protected_packet.hh/.cc` 能用 TLS 派生的 AES-128-GCM/SHA256 traffic secret 封装和认证解封 QUIC v1 Handshake、1-RTT 单包。`tests/quic_protected_packet.cc` 把真实 TLS 双端握手放进受保护的 Initial/Handshake 包，再验证双向加密的 1-RTT STREAM 帧。它是一条内存中的密码数据路径，尚不是带 UDP、ACK、恢复和流量控制的完整连接。

依据：[RFC 9001 §5.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.1)、[§5.3–5.5](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3)，[RFC 9000 §12.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2)、[§17.2.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.4)、[§17.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3)。

## 从 traffic secret 到线上包

TLS 回调给出的 32 字节 secret 不是 AES key。`derive_packet_keys(secret)` 用 HKDF-Expand-Label/SHA256 分别展开：

| 标签 | 输出 | 用途 |
| --- | --- | --- |
| `quic key` | 16 字节 | AES-128-GCM payload key |
| `quic iv` | 12 字节 | nonce 基础值 |
| `quic hp` | 16 字节 | AES-ECB 报头保护 key |

标签编码包含 TLS 的 `tls13 ` 前缀及空 Context。这里不再使用 Initial salt，也不再次展开 `client in` / `server in`。Initial 特有的提取和双向 secret 仍由 `derive_initial_keys(dcid)` 完成，然后与 TLS secret 共用相同的包密钥展开。新公共类型 `PacketProtectionKeys` 通过 `InitialPacketKeys` 别名保留原来的源码接口；密码实现继续共用 `initial_keys.cc` 的已有后端，旧 Initial 函数仅转发，不另写一份 AES。

nonce 等于 12 字节 IV 与左补零的**完整包号**异或。AAD 是尚未遮盖的完整包头，包含截断包号。先对载荷做 AES-GCM，加上 16 字节 tag，然后从 `pn_offset + 4` 取 16 字节密文样本生成报头掩码。长报头遮盖首字节低四位，短报头遮盖低五位；两者都遮盖包号字段。

```mermaid
flowchart LR
  A[TLS 当前方向、级别的 secret] --> B[derive_packet_keys]
  B --> C[key、iv、hp]
  C --> D[未保护包头作 AAD<br/>IV XOR 完整包号作 nonce]
  D --> E[AES-GCM 载荷和 tag]
  E --> F[AES-ECB 样本生成 HP 掩码]
  F --> G[遮盖首字节和包号]
```

## 接口与调用方责任

| 接口 | 行为 |
| --- | --- |
| `seal_handshake_packet(keys, dcid, scid, pn, pn_length, plaintext)` | 创建 v1 Handshake 长报头及受保护载荷 |
| `seal_one_rtt_packet(keys, dcid, pn, pn_length, plaintext, key_phase=false, spin=false)` | 创建短报头；phase、spin 只编码传入的位 |
| `open_handshake_packet(keys, datagram, offset, largest_received)` | 按 Length 截出一个 Handshake 包后解封 |
| `open_one_rtt_packet(keys, datagram, offset, short_dcid_length, largest_received)` | 用连接上下文给出的 DCID 长度解析短报头；占数据报剩余部分 |

`packet_number_length` 只能是 1–4；完整 PN 不超过 `2^62-1`。本地非法字段抛标准异常（越界 PN 沿用 `out_of_range`，非法长度等用 `invalid_argument`）；库或分配失败可抛异常。接收端的正常畸形输入及认证失败用空结果表示。

调用方必须选择正确的本端写/对端读方向及 Initial、Handshake、Application 级别密钥；同一密钥下不能复用包号。模块不维护发送包号、ACK、重复接收、使用次数、密钥销毁或路由状态。`secret`、派生 keys 都是敏感值副本，调用方管理其生命周期，不能输出到日志。

调用方还必须提供足够 PADDING：`pn_length + plaintext.size() + 16 >= 20`。因此包号长 1、2、3、4 时，密码层最少分别需要 3、2、1、0 字节明文。本模块不会自动插帧；测试中的零明文仅验证密码边界，不表示不带帧的包已满足 QUIC 包语义。Initial 最低数据报长度仍由 Initial 调用方负责。

## 认证之后才暴露结果

接收时先定位包边界、截出当前包，再用样本移除报头保护，恢复完整 PN，生成 nonce，验证 AEAD。只有 AEAD 成功后，才检查保留位并提供 key phase、spin、明文和可信的布局信息。

| `PacketOpenResult` | 含义 | 后续连接层动作 |
| --- | --- | --- |
| `packet` 有值、`transport_error` 无值 | 已认证且保留位合法 | 校验连接/CID、去重、帧格式和允许的状态，再处理 |
| 两者都无值 | 畸形、截断、密钥不符或认证失败 | 丢弃；不按未认证字段关闭连接或更新接收状态 |
| `packet` 无值、`transport_error=0x0a` | AEAD 成功但保留位非零 | 按 PROTOCOL_VIOLATION 关闭；不交出明文 |

Handshake 的保留位掩码是 `0x0c`，1-RTT 是 `0x18`。即使报头保护移除后看见非法位，也必须先认证：攻击者不能靠随机字节迫使连接关闭。本层给出错误码，尚不发送 CONNECTION_CLOSE。

返回的 `PacketLayout::pn_offset`、`packet_end` 是整个数据报的绝对下标。Handshake 受 Length 限制，不能借后续包的数据取得样本或补齐 tag；1-RTT 没有 Length，只能作为合并数据报的最后一个包。`largest_received` 必须来自对应包号空间，只能在成功后更新为已收最大值；解密函数本身不修改状态，也不去重。当前共用包号恢复器在 `largest_received >= 2^62-1` 时拒绝恢复，连接耗尽状态仍待上层处理。

key phase 和 spin 都是认证后的元数据。本阶段只验证它们的线上编码和读取；传入不同 phase 不会派生新密钥，也不证明发送方完成了合法的密钥更新。真正的更新状态机必须管理新旧 traffic secret、旧包重排、计数限制及确认。

## 测试如何证明数据路径

`quic_protected_packet` 同时检查：

- RFC 9001 A.1 的公开 traffic secret、key/iv/hp 向量；另用 Python cryptography 的 AESGCM/AES-ECB 独立生成 Handshake 与 1-RTT 整包固定向量，不只做自己封包再自己拆包。
- 错误密钥、报头/载荷/tag 篡改、逐字节截断、认证与未认证的非法保留位。
- 1–4 字节包号、255→256 恢复、62 位最大 PN、非法宽度/CID/上下文，以及恰好够/不够的 HP 样本。
- 非零数据报 offset、多个 Handshake 加末尾短包、短包必须最后，以及不能从后包借样本。
- 真实 TLS 证书/ALPN/参数验证；CRYPTO 片段倒序、重复，并分别封装为 Initial 或 Handshake 包，经认证后再喂给 TLS。握手后用两个方向的真实 Application secret 发送和解出 STREAM request/response；错误级别及真实反方向的 TLS 密钥均不能解开。

构建依赖和证书夹具沿用 [tls-handshake.md](tls-handshake.md)。运行：

```sh
cmake --build build --target functionality_testing quic_debug -j2
ctest --test-dir build -R 'quic_' --output-on-failure --timeout 30
```

后续需要生产连接层和 UDP 接线、握手确认、密钥丢弃/更新、ACK/丢包/拥塞/流量控制及独立实现互通。当前结果不能代替这些验收。

2026-10-21 验证记录：Debug 和 ASan/UBSan 静态库构建成功；QUIC 专项 **16/16** 通过（含编译夹具），旧 Initial 向量保持通过。独立审查无重要问题，补齐了真实 TLS 反方向密钥拒绝覆盖。格式与 diff 空白检查通过。

全量 CTest 使用 `--timeout 30 -j2`，共 **47/54** 通过，耗时 103.82 秒。原有 `wrapping_integers_roundtrip`、`wrapping_integers_extra`、`recv_transmit`、`recv_reorder_more`、`send_transmit` 超时；`net_interface`、`router` 因缺少测试可执行程序未运行。全部 QUIC 用例在全量运行中通过，但全量命令退出码 8，不能称全量通过。日志保存在 `build/quic-packet-full-ctest.log`。
