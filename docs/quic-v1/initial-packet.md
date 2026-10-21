# Initial 整包：如何把明文变成网络上的 QUIC 包

依据 [RFC 9000 §17.2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2)、[RFC 9001 §5.3–5.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3) 和 [附录 A.3](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.3)。代码在 `quic/initial_packet.hh/.cc`，测试在 `tests/quic_initial_packet.cc`。

## 1. 先看规范要求

Initial 包的未保护头包含版本、连接 ID、Token、Length 和截断包号。Length 是**包号字段 + 加密载荷 + 16 字节认证标签**的长度。AEAD 使用未遮盖的完整头作附加认证数据（AAD）；报头保护再遮盖首字节的低四位和包号字段。用于生成报头掩码的 16 字节样本从**包号字段开始后四字节**取，不能从实际包号长度后取。

接收顺序反过来：先读未遮盖的字段来定位包边界和样本；用样本移除报头掩码；由恢复的包号长度读截断包号，结合当前 Initial 包号空间已收到的最大号恢复完整包号；最后用恢复后的完整头和包号做 AES-GCM 认证解密。认证失败不能更新包号空间、连接状态或向应用交付数据。保留位在认证后检查。[RFC 9001 §5.4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2)

**自己复述：**先用外露的地址栏找到信封，揭开被遮住的编号，再拿编号和未遮盖信封核对封口。核对成功才把信里的内容当真。

## 2. 对应代码步骤

`seal_initial_packet()` 调用 `build_long_header()`，把密文加标签的长度传进去；`encrypt_initial_payload()` 使用这个**未遮盖**的头作为 AAD；随后在 `pn_offset + 4` 取样本，用 `initial_header_mask()` 和 `apply_header_mask()` 遮盖首字节及包号。

`open_initial_packet()` 用 `parse_protected_packet()` 只读取未被遮盖的字段。它截出单个包，因此合并 UDP 数据报里后续包不会进入当前包的 AEAD；再移除报头掩码、重建包号、解密并检查保留位。函数返回 `nullopt` 时，调用方不应更改包号空间状态。返回的 `layout.packet_end` 是相对**整个数据报**的偏移，方便调用方继续读下一个包。

发送方必须给出匹配方向的 Initial 密钥、`InitialSender` 角色、未复用的包号，并填充需要的 PADDING 帧。服务器 Initial 的 Token 必须为空；封装会拒绝非空 Token，解封会丢弃这样的包。客户端带 Initial 的 UDP 数据报至少 1200 字节；这个单包函数尚不负责数据报填充、UDP 发送或反放大额度检查。[RFC 9000 §17.2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2)、[§14.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1)

## 3. 测试怎样证明顺序正确

测试用 RFC 9001 附录 A.3 的服务器 Initial 明文、密钥和连接 ID 生成**完整网络字节**，与规范整包逐字节比较，然后解封核对明文和包号。这能同时检查 Length、AAD、Nonce、样本偏移和报头掩码。测试还修改认证标签和头，换成错误方向密钥，截断包，读取合并数据报第二个包，并让一字节截断包号 `0x00` 在最大已收包号 255 后恢复成 256。

## 4. 还缺什么

边界测试另外构造认证有效但保留位非零的包、非空服务器 Token、以及接近 62 位上限的包号恢复，确认它们被拒绝而不会更新连接状态或抛出异常。

这是 Initial 级别的单包原语。它尚未接入 TLS 1.3、CRYPTO 帧缓存、握手状态、ACK/丢包、Retry、版本协商和 UDP 收发。Handshake、0-RTT、1-RTT 各级别的密钥和包处理也未实现；测试通过不表示连接能建立。
