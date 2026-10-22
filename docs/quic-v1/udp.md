# QUIC UDP 收发与真实回环握手

`quic/udp_socket.hh`、`udp_socket.cc` 提供 Linux 专用的非阻塞 UDP 接口。IPv4 和 IPv6 各用独立 socket；IPv6 设置 `IPV6_V6ONLY`。原有 TCP/UDP 工具保持兼容。

## 地址与事件循环

`UdpEndpoint::numeric("127.0.0.1", 0)` 或 `numeric("::1", 0)` 表示回环地址和临时端口。`local_endpoint()` 读取实际绑定端口。地址只接受数字形式；IPv6 scope ID 通过第三个参数传入，不解析 DNS 和 `%zone`。相等比较包含地址族、地址、端口和 IPv6 scope。

`UdpSocket` 独占描述符，析构关闭，禁止复制；创建时设置 `SOCK_NONBLOCK | SOCK_CLOEXEC`。`native_handle()` 是供 poll/epoll 使用的借用描述符，不可由调用者关闭。

`send(peer, payload, ecn)` 一次发送一个数据报。`false` 只表示 EAGAIN，调用者保留数据并等待可写；其它系统错误抛出 `system_error`。参数不合法时在发送前抛异常。IPv4 最大 UDP payload 为 65507 字节，IPv6 普通数据报最大为 65527 字节；这只是 UDP 编码上限，**不是 QUIC 可用路径 MTU**。

`receive(capacity)` 每次只读取一个数据报，容量为 1..65535 字节。无数据返回 `nullopt`；收到空 UDP 数据报则返回 payload 为空的有效对象。`MSG_TRUNC` 或 `MSG_CTRUNC` 会消费并丢弃整个数据报，抛出 `length_error`，不向上层暴露部分密文。事件循环应捕获后继续收包；不能把它当作已经认证的对端协议错误。

## ECN 元数据

发送使用 `sendmsg` 的逐包 `IP_TOS` / `IPV6_TCLASS` 控制消息，ECN 参数范围为 0..3，DSCP 当前固定为 0。接收开启 `IP_RECVTOS` / `IPV6_RECVTCLASS`，通过 `recvmsg` 解析 IPv4 的单字节 TOS 或 IPv6 的整型 traffic class，再取低两位。缺少控制消息返回 ECN `nullopt`，不能默认为 Not-ECT。

这只完成网络接口上的 ECN 标记和读取；ACK_ECN 计数、对端反馈验证和拥塞响应仍未实现。

## 真实 UDP 集成路径

`tests/quic_udp_handshake.cc` 在虚拟机的 IPv4/IPv6 回环上分别执行：

1. TLS 产生 CRYPTO，按 257 字节分片，封装为受保护 Initial/Handshake 包，通过真实 UDP 发送；每个 Initial 数据报至少 1200 字节。
2. 接收端核对来源，认证包、恢复完整包号、检查帧放置，再把 CRYPTO 交给 TLS。三套包号空间使用现有 `PacketNumberSpaces`。
3. 服务端使用 `AntiAmplificationBudget`，每次发送前检查三倍额度；认证收到客户端 Handshake 后才解除地址反放大限制。
4. 双端 TLS 完成后核对证书、ALPN 和传输参数；服务端通过 1-RTT 发送 HANDSHAKE_DONE，客户端在认证并解码后确认握手。双向 1-RTT PING 验证应用级密钥。损坏的 1-RTT 包不能暴露控制帧。

该驱动是**测试工具**，预先指定地址和 CID，只在无丢包的本地回环中逐包推进；它没有被包装成生产连接类。真实服务端监听与动态 CID 路由、接收先于密钥的包、ACK/恢复/PTO、拥塞/流量控制、STREAM 交付、密钥丢弃、迁移、关闭和外部互通仍待实现。测试里的 `confirmed` 仅验证认证后控制帧路径，不代表已有完整连接状态机。

## 验证

新增 `quic_udp_socket` 与 `quic_udp_handshake` 两个 ASan/UBSan CTest 用例，共享现有编译 fixture 与测试证书生成目标。

```sh
cmake --build build --target quic_udp_socket_sanitized quic_udp_handshake_sanitized -j2
ctest --test-dir build -R 'quic_' --output-on-failure -j2
ctest --test-dir build --output-on-failure --timeout 30 -j2
```

2026-10-21 虚拟机实测：QUIC 专项 18/18 通过（含编译 fixture，11.01 秒）；全量 49/56 通过（101.68 秒）。失败项与前一轮一致：`wrapping_integers_roundtrip`、`wrapping_integers_extra`、`recv_transmit`、`recv_reorder_more`、`send_transmit` 达到 30 秒超时；`net_interface`、`router` 缺少可执行文件而未运行。全部 QUIC 检查通过不代表全量套件通过。完整日志保存在忽略的 `build/quic-udp-full-ctest.log`。

独立审查未发现严重或重要问题。保留一项轻微测试改进：为 IPv4 单独增加 65508 字节拒绝断言；当前实现的 65507 上限正确，现有超限断言使用 65528 字节。

后续里程碑已新增独立的 [HandshakeConnection](handshake-connection.md) 库类；本页所述原始 UDP 驱动仍保留为底层组合测试。
