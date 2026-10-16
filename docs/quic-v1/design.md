# QUIC v1 设计草案

## 基线与架构

基线：Minnow `my-work`，提交 `7d30f0b7b1545ef997005440fb5be3b1e90f7e6e`。新增独立 `quic/` 库和示例客户端/服务端，保留 TCP 实验。现有 `UDPSocket`、`EventLoop` 提供 I/O 基础；`ByteStream` 和 `Reassembler` 用于每条流的数据缓存与重组。

建议依赖关系：

```text
应用 API → QUIC 连接/流 → 帧调度、流量控制、恢复 → 包编解码/保护 → UDP socket
                                 ↕
                           TLS 1.3 适配层
```

## 关键状态

- **Connection**：角色、连接 ID、握手/关闭状态、传输参数、三个包号空间、流表、连接流量额度和定时器。
- **Packet number space**：下一个发送包号、已接收包号区间、待确认区间、已发送包元数据。包号只标识包，不作为流的字节偏移。
- **Stream**：方向、发送 offset、接收 `Reassembler`、final size、已发送/确认/待恢复字节区间、每流额度和状态。
- **Recovery**：RTT 估计、PTO、丢包阈值、拥塞窗口、bytes-in-flight。ACK 更新包状态，并将仍需传输的帧信息交回调度器。
- **TLS adapter**：消费/产出 CRYPTO 数据、提供读写密钥和加密级别、传输参数及证书结果；包保护和 TLS 握手状态不混入 TCP 类。

## 复用与边界

`Reassembler::insert(offset, data, fin)` 与 STREAM 帧的 offset/data/FIN 接近，但它只处理字节重组。调用前要在 QUIC 层校验流 ID、状态、final size、流量额度、重复范围和总连接额度。若现有 Reassembler 对冲突片段或终止条件的行为与 RFC 不符，应扩展适配层或在独立分支修正并补测试。

TLS 计划优先验证具有 QUIC 握手回调的成熟库。BoringSSL 提供 `SSL_set_quic_method` 与传输参数 API，可作为首选技术验证对象；虚拟机当前只确认有 OpenSSL 3.0.13 命令，尚未确认可用于本项目的 QUIC TLS 开发接口。先做最小握手探针并固定依赖版本、许可证和构建方式，再锁定设计。不能手写 TLS 或自行设计密码协议。

## 首轮不包含的能力

0-RTT、HTTP/3、QUIC v2、主动迁移和性能调优分别作为后续变更。对方发来相关帧或参数时，按 RFC 判断可忽略、拒绝还是关闭连接；不可一概静默丢弃。首轮最终支持清单以互通测试结果为准。

## 主要风险与处理

1. **TLS 库集成**：握手密钥回调、证书验证与包保护跨层；先完成可独立运行的握手探针。
2. **范围膨胀**：将编解码、安全握手、单流、恢复、多流、互通作为顺序交付点，每个交付点保留可运行测试。
3. **流量控制记账**：连接额度按各流最高已接收 offset/final size 计量，不能按重复收到的字节数累加；用重复、乱序和 RESET 场景测试。
4. **恢复状态交叉**：包确认与流字节确认分离，测试同一数据由两个不同包号承载时的 ACK/丢包顺序。
5. **安全边界**：模糊输入、长度溢出、无效认证标签与反放大限制由解析/连接层集中检查。

## 参考

- [RFC 9000：QUIC 传输](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001：TLS 集成](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9002：丢包恢复与拥塞控制](https://www.rfc-editor.org/rfc/rfc9002.html)
- [BoringSSL QUIC API](https://boringssl.googlesource.com/boringssl/+/main/include/openssl/ssl.h)
