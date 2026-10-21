# QUIC Initial 包的密钥从哪里来

对应 [RFC 9001 §5.1–5.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-5) 和 [附录 A.1–A.2](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A)。源码是 `quic/initial_keys.hh/.cc`，测试是 `tests/quic_initial_keys.cc`。此模块使用 OpenSSL 3 的 SHA-256 HMAC、AES-128-GCM 和 AES-128-ECB 原语。它只实现 **QUIC v1 Initial 级别**；握手和 1-RTT 密钥仍须从 TLS 1.3 得到。

## 1. 为什么双方还没握手就能加密 Initial

客户端第一个 Initial 包中的 Destination Connection ID（DCID）公开可见。RFC 用固定的 v1 salt 和这个 DCID 算出双方都能重现的 Initial 密钥。攻击者也能重现，所以这种加密**不证明对端身份**；它只让 QUIC 的早期包具有统一的包保护格式。`derive_initial_keys(dcid)` 接收客户端第一个 Initial 的 DCID。若服务器发 Retry，后续 Initial 改用 Retry 的 Source CID 派生新密钥；收到服务器普通 Initial 导致客户端改变发送用 DCID 时，不因此改密钥。[RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2)

**自己复述：**两人开口前还没有协商秘密，于是用包上公开的编号和规范固定的盐算出一把“临时包装钥匙”。任何旁观者也能算，所以不能把这把钥匙当成身份认证。

## 2. 从 DCID 到两套方向密钥

第一步是 `initial_secret = HKDF-Extract(initial_salt, dcid)`。在 SHA-256 下，HKDF-Extract 等于以 salt 为 HMAC key、以 DCID 为数据计算 HMAC-SHA256。`initial_salt` 是 RFC 9001 v1 的固定 20 字节值 `38762cf7f55934b34d179ae6a4c80cadccbb7f0a`。[RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2)

第二步分别使用标签 `client in` 和 `server in` 生成 32 字节的客户端/服务器 Initial traffic secret。`expand_label` 构造 TLS 1.3 的 `HkdfLabel`：2 字节输出长度、1 字节标签长度、`tls13 ` 前缀加标签、1 字节零长度 context。再按 HKDF-Expand 给消息尾部加块计数 `01` 并做 HMAC。这里输出最长 32 字节，只有一个 SHA-256 块。不能直接拿标签字符串做 HMAC，否则得不到 RFC 密钥。[RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2)、[RFC 8446 §7.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1)

第三步从每个方向的 traffic secret 分别扩展 `quic key`（16 字节 AES-GCM 密钥）、`quic iv`（12 字节 nonce 基础值）、`quic hp`（16 字节 AES 报头保护密钥）。`InitialKeys` 同时保存 client 和 server 两套值；发送方用自己的方向，接收方用对端的方向。RFC 附录 A.1 的 DCID `8394c8f03e515708` 会得到客户端 key `1f369613dd76d5467730efcbe3b1a22d`、IV `fa044b2f42a3fd3b46fb255c` 和 HP key `9f50449e04a0e810283a1e9933adedd2`，测试逐字节比较两方向所有值。[RFC 9001 附录 A.1](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.1)

## 3. 包号怎样进入 AES-GCM

每个包用不同的 nonce。`packet_nonce` 复制 12 字节 IV，再把完整包号写成 8 字节大端整数，右对齐后与 IV 异或。它拒绝超过 QUIC 变长整数上限的包号。`encrypt_initial_payload` 把**尚未遮盖的完整包头**作为 AEAD 的 Additional Authenticated Data（AAD），把帧载荷加密，最后追加 16 字节认证标签。先 AES-GCM 加密，再生成报头保护掩码；接收时顺序相反。[RFC 9001 §5.3](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3)

`decrypt_initial_payload` 只有 OpenSSL 验证标签成功后才返回明文。改动密文、标签、包号或 AAD 包头都会返回空值。若包裹在 UDP 数据报内，调用方必须先定位**单个包的边界**并去掉报头掩码，再拿恢复后的完整包号和原始明文包头调用解密函数；不能把整个数据报都当作一个 AEAD 输入。

## 4. 为什么报头还需要另一把钥匙

`initial_header_mask` 用 `quic hp` 密钥对 16 字节密文样本做 AES-ECB，取前五字节作为掩码。这里 ECB **只用于一个块的报头掩码生成**，载荷用的是带认证的 GCM。样本的位置固定为包号字段开始后四字节，不随实际包号编码宽度移动；`header_protection_sample` 和 `apply_header_mask` / `remove_header_mask` 已在 `quic/header_protection.cc` 中处理该偏移与位掩码。[RFC 9001 §5.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4)

附录 A.2 给出样本 `d1b1c98dd7689fb8ec11d242b123dc9b`，对应掩码 `437b9aec36`。测试构造该附录的 1162 字节明文、包号 2 和明文包头，比较加密后前 16 字节、末尾认证标签、掩码及遮盖后的包头 `c000000001088394c8f03e5157080000449e7b9aec34`；随后解密并做篡改测试。附录 A.3 的服务器 Initial 则逐字节比较**整个**受保护包，验证另一方向的密钥和短于四字节的包号。外部向量比只做自我往返更能发现双方共享的同一个编码错误。[RFC 9001 附录 A.2](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2)、[A.3](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.3)

## 5. 当前边界和构建依赖

这是一组 Initial 密钥与载荷保护原语，尚未自动构造/解密整个 QUIC 包，也没有 TLS 握手、证书、Handshake/1-RTT 密钥、Retry 完整性验证和密钥丢弃。`initial_keys.cc` 调用 OpenSSL 3；普通开发环境需要 OpenSSL 3 开发头文件与 `libcrypto`（Ubuntu 可安装 `libssl-dev`）。项目 CMake 通过 `find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)` 查找它。当前虚拟机使用同版本开发包的用户目录副本编译，路径记录在本地 CMake 缓存中；换机器时需按正常方式安装开发包或指定 OpenSSL 路径。
