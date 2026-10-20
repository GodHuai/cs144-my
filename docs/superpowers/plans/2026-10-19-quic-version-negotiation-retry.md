# QUIC v1 版本协商与 Retry 字段里程碑

## 范围与依据

- RFC 9000 §6.1–6.2、§17.2.1：VN 的回复格式、任意 unused 位、8 位连接 ID 长度和整数据报边界。
- RFC 9000 §17.2.5、RFC 9001 §5.8：Retry 字段、非空 Token，以及完整性标签验证的必要性。
- 本里程碑只建立线上字段接口；连接状态处理和 Retry tag 加密验证单列后续任务。

## 执行与验证

1. 在 `tests/quic_packet_header.cc` 先加入独立字节向量、畸形输入、21 字节 VN CID 和空 Token 用例；编译失败，证实缺少接口。
2. 在 `quic/packet_header.hh/.cc` 加 VN 构造/解析和 Retry 字段解析；VN 不复用 v1 的 20 字节 CID 上限，Retry 返回值明确不代表通过认证。
3. 格式化并运行包头定向测试、QUIC 测试组；审阅构造字节和失败路径。
4. 在 `docs/quic-v1/implementation.md` 解释 RFC 规则、字段边界和安全前提；同步 `coverage.md`。

## 后续连接层要求

- 客户端实现 RFC 9000 §6.2 的 VN 丢弃/放弃规则，记录已经处理的包和最初选择的版本。
- 服务器从原请求交换 DCID/SCID 后构造 VN，并遵守每 UDP 数据报最多一个 VN 回复。
- Retry 在任何状态变更前执行 RFC 9001 §5.8 完整性验证；发送端生成合法 tag，客户端遵守单次处理、CID/Token 更新和包号不重置规则。
