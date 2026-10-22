# QUIC v1 RFC 覆盖矩阵（进行中）

当前只有表中标明的基础函数部分实现。后续须逐条展开 MUST/MUST NOT/SHOULD，记录条款 ID、角色/适用条件、实现或 N/A 理由、源码、测试和互通证据；本表只是目录，不代表已符合 RFC。特别审计 0-RTT 拒绝及只读 GET profile、无损接收/ACK、迁移、preferred_address、AEAD 限制和数据报大小。

状态读法：“计划”表示没有对应完整实现；“部分实现”仅表示表格指出的函数及测试已经存在，**不表示该范围其余要求已满足**。逐模块解释与学习顺序见 [README.md](README.md) 和 [implementation.md](implementation.md)。

| 规范 | 主题 | 任务 | 状态 |
| --- | --- | --- | --- |
| UDP / RFC 9000 §13.4、§14 | IPv4/IPv6 数据报与 ECN 元数据 | 1 | 部分实现：`quic/udp_socket.*` 提供 Linux 非阻塞收发、逐包 ECN、scope、截断丢弃；`tests/quic_udp_handshake.cc` 通过真实双栈 UDP 运行受保护 TLS 与 1-RTT 控制帧。生产连接路由、ACK_ECN/拥塞验证、PMTU 与互通待实现。详见 `udp.md` |
| RFC 9000 §7.5、§19.6 | CRYPTO 字节缓冲与分片 | 3 | 部分实现：每级别至少 4096 字节的乱序缓冲、62 位 offset 界限、唯一字节容量记账和原子错误、发送重分片及级别丢弃见 `quic/crypto_streams.*`。TLS 握手接线见 `quic/tls_handshake.*`；错误到 CONNECTION_CLOSE 与 ACK/丢包调度待完成 |
| RFC 9000 §2–4 | 流、状态与流量控制 | 4–5 | 计划 |
| RFC 9000 §5–8、§18 | 连接 ID、版本、握手、传输参数、地址验证 | 2–3、9 | 部分实现：`quic/transport_parameters.*` 解析/编码 §18 核心参数，检查重复、格式、数值界限、角色和与所给 Initial/Retry CID 的一致性；`quic/path_validation.*` 记录 §8.2 单路径挑战与回应、地址和最低 MTU 验证、超时；`quic/anti_amplification.*` 按地址记 §8 的三倍发送额度。`quic/tls_handshake.*` 已接入 TLS 扩展并验证所给 CID 上下文；实际 CID 来源、安全随机挑战生成、参数消费、0-RTT 恢复规则与 UDP 路径接线待完成。详见 `transport-parameters.md`、`path-validation.md`、`anti-amplification.md` |
| RFC 9000 §9–11、§5.1 | 迁移、路径、连接 ID 与终止 | 9–10 | 部分实现：`quic/peer_connection_ids.*` 管对端签发的 ID 与路径绑定；`quic/local_connection_ids.*` 管本端签发的 ID、退休帧检查及活动 ID 查找；§8 的额度和验证状态基础见上一行。实际迁移、地址切换、反放大与路径状态接线、UDP 路由、随机 CID/token 生成及新路径拥塞状态仍待完成。详见 `connection-ids.md`、`local-connection-ids.md` |
| RFC 9000 §12–13 | 包、帧、ACK、可靠性与 ECN | 2、6–7 | 部分实现：包号编码、§12.3 三空间映射/发送分配/认证后接收去重、受保护包边界定位、核心帧 `0x00`–`0x1e` 线上格式编解码及 §12.4 表 3 包类型放置校验见 `quic/packet_number.*`、`quic/packet_number_space.*`、`quic/packet_header.*`、`quic/frame.*`；自动接收记录保留策略、角色/方向规则、ACK 处理与可靠性待完成 |
| RFC 9000 §14–16 | 数据报大小、PMTU、编码 | 2、10 | 部分实现：§16 变长整数见 `quic/varint.hh`、`quic/varint.cc`；`tests/quic_varint.cc` 覆盖边界和附录 A.1 向量。其余待完成 |
| RFC 9000 §17–21 | v1 包格式、基础帧、错误与安全 | 2–10 | 部分实现：§17.1 包号编解码；§17.2–17.3 Initial、0-RTT、Handshake、1-RTT 的受保护包边界与未保护包头构造，其中 Initial 已有单包封装/认证解封原语；§17.2.1 VN 线上构造/解析，§17.2.5 Retry 字段解析；§19.1–19.20 的核心帧线上格式。Retry 标签验证原语见 RFC 9001 §5.8；扩展帧、VN 客户端处理、Retry 客户端接受状态机、0-RTT 保护及帧/连接语义与错误处理待完成；Handshake/1-RTT 的 AES-128-GCM 整包保护见 `protected-packets.md` |
| RFC 9001 §2–4 | TLS 与加密级别、握手 | 3、8 | 部分实现：`quic/crypto_streams.*` 分级别重组 CRYPTO 字节、限制缓冲并保留发送分片；`tests/quic_crypto_streams.cc` 验证 Initial 认证包中的乱序、重复、丢失修复和篡改拒绝。`quic/tls_handshake.*` 已用 OpenSSL 3.5 external QUIC TLS 接口完成 TLS 1.3 双端握手、CA/主机名/ALPN 校验、传输参数和独立读写级别/secret 回调；仅 AES-128-GCM-SHA256，内存测试已通过受保护的 Initial/Handshake 包贯通握手及双向 1-RTT 数据；新增真实 IPv4/IPv6 UDP 集成路径见 `udp.md`。握手确认、后握手处理、丢弃和恢复仍待实现。详见 `crypto-streams.md`、`tls-handshake.md` |
| RFC 9001 §5–6 | 包保护与密钥更新 | 3、10 | 部分实现：§5.2 的 v1 Initial 密钥派生、§5.3 的 Initial AES-128-GCM 载荷保护、§5.4 的 AES 报头掩码与单个 Initial 整包封装/认证解封、§5.8 的 v1 Retry 完整性标签，均用附录 A 向量校验；新增 `packet_keys.hh`、`protected_packet.*` 从 TLS secret 展开 AES-128-GCM key/iv/hp，封装/认证解封 Handshake 与短报头 1-RTT，区分认证后的保留位协议错误；独立整包向量与受保护 TLS 测试见 `tests/quic_protected_packet.cc`。仍缺生产连接接线、Retry 状态机、其它套件、密钥更新/丢弃与使用上限处置。详见 `protected-packets.md` |
| RFC 9001 §7–9 | 0-RTT、参数与安全 | 3、8 | 部分实现：TLS 扩展中接入现有参数角色/CID 校验；当前显式禁用 0-RTT 和恢复。其余待实现 |
| RFC 9002 §3–6 | RTT、ACK、丢包与 PTO | 6 | 部分实现：§5 的 RTT 估计与 §6.2.1 的 PTO 时长计算；ACK 样本筛选、丢包判定、PTO 定时器与退避待完成 |
| RFC 9002 §7–8 | 拥塞、ECN 与安全 | 7 | 计划 |
| QUIC Interop Runner | `hq-interop` ALPN、HTTP/0.9 测试适配层与双向角色 | 11 | 计划 |

最终完成标准：逐条区分强制、条件和推荐行为；互通成功不能代替异常、安全和资源边界测试。HTTP/3 和后续扩展不混入 QUIC v1 核心审计。
