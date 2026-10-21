# Retry 完整性标签：客户端为什么要先验再用

依据 [RFC 9001 §5.8](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8) 和 [附录 A.4](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.4)。代码在 `quic/retry_integrity.hh/.cc`，测试在 `tests/quic_retry_integrity.cc`。

## 1. Retry 到底做什么

服务器收到客户端 Initial 后，可以回 Retry，要求客户端带着 Token 再发 Initial。这通常用于验证客户端地址。Retry 线上已有自己的 DCID、SCID、Token 和 16 字节完整性标签。`parse_retry_packet()` 只能拆字段；任意人都可以填 16 字节，因此**解析成功不等于可信**。客户端必须用自己最初 Initial 的目标 CID（ODCID）验证标签，才能使用 Retry 的 Token、SCID 和其它状态。[RFC 9000 §17.2.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5)、[RFC 9001 §5.8](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8)

**自己复述：**收到一张“请重新寄送”的纸条，先确认它确实对应我刚才寄出的那封信。纸条写得像真的，不代表核对通过。

## 2. 为什么要构造一个不上网的伪包

Retry 自身不包含 ODCID；它的字段里只有服务器选用的新 ID。若标签只覆盖线上 Retry 字节，同一份 Retry 可能被错误地用到另一条连接。RFC 定义用于计算的 `Retry Pseudo-Packet`：一个字节的 ODCID 长度、ODCID 原始字节、再接**去掉末尾 16 字节标签的 Retry 包**。这个伪包只用于计算，不会通过 UDP 发送。[RFC 9001 §5.8](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8)

`compute_retry_integrity_tag(original_dcid, retry_without_tag)` 先用现有 Retry 解析器检查 v1 格式、CID 长度和非空 Token，再拼出伪包。`original_dcid` 是**第一次**客户端 Initial 的 DCID，不是收到 Retry 后准备使用的新 DCID。改变 ODCID 的任一字节都会改变标签。

## 3. AES-GCM 在这里怎样用

QUIC v1 固定使用 16 字节 key `be0c690b9f66575a1d766b54e368c84e` 和 12 字节 nonce `461599d35d632bf2239825bb`。AES-128-GCM 的明文为空，伪包作为 Additional Authenticated Data（AAD），输出只有 16 字节标签。`verify_retry_integrity()` 先检查收到的整个 Retry 布局，再算预期标签，并用 OpenSSL 的 `CRYPTO_memcmp` 做固定时间比较。[RFC 9001 §5.8](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8)

这里的 key 和 nonce 是规范公开的固定值，因此标签**不是服务器身份认证**。它的作用是发现损坏，并把 Retry 绑定到知道客户端原始 DCID 的参与者。证书身份仍属于后续 TLS 1.3 握手。[RFC 9001 §5.8](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8)

## 4. 用规范向量自己核对

RFC 附录 A.4 的 ODCID 是 `8394c8f03e515708`，最终 Retry 包是 `ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba`。测试从去掉标签的前半段重新计算，逐字节比较标签，然后分别修改 Token、标签、原始 DCID 和版本，确认验证失败。只对自己生成的标签做往返检查，无法发现双方共享的相同实现错误，所以这里用 RFC 字节作为外部依据。

## 5. 与连接状态的界线

本模块返回布尔验证结果，尚未把它接入客户端 Retry 状态机。连接层还必须检查是否已经接受过 Retry、是否与当前握手状态一致，并在验证失败时丢弃包，不能先保存 Token 或换 Initial 密钥。Retry Token 的签发、加密、过期、地址验证和重发也不由这个完整性标签函数处理。
