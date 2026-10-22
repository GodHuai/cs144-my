#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <sys/socket.h>

namespace quic {

// Numeric, single-family UDP address. IPv6 scope is explicit (no DNS or %zone parsing).
class UdpEndpoint
{
public:
  static UdpEndpoint numeric( std::string_view ip, uint16_t port, uint32_t scope_id = 0 );
  int family() const { return address_.ss_family; }
  std::string ip() const;
  uint16_t port() const;
  uint32_t scope_id() const;
  bool operator==( const UdpEndpoint& other ) const;

private:
  sockaddr_storage address_ {};
  UdpEndpoint() = default;
  socklen_t length() const;
  friend class UdpSocket;
};

struct UdpDatagram
{
  UdpEndpoint peer;
  std::string payload;
  std::optional<uint8_t> ecn;
};

// Linux nonblocking, CLOEXEC socket; IPv6 sockets use IPV6_V6ONLY.
// One owner / event-loop thread. native_handle is borrowed, never close it externally.
class UdpSocket
{
public:
  explicit UdpSocket( const UdpEndpoint& bind_address );
  ~UdpSocket();
  UdpSocket( const UdpSocket& ) = delete;
  UdpSocket& operator=( const UdpSocket& ) = delete;

  UdpEndpoint local_endpoint() const;
  int native_handle() const { return fd_; }
  // false means EAGAIN, with no datagram sent. Other OS failures throw system_error.
  // ECN is 0..3; DSCP is zero. Family mismatch and oversize payloads throw before I/O.
  bool send( const UdpEndpoint& peer, std::string_view payload, uint8_t ecn = 0 );
  // nullopt means EAGAIN; an empty payload is a successfully received datagram.
  // Capacity is 1..65535. Truncated datagrams are consumed and throw length_error,
  // without exposing partial payload. Missing ECN is nullopt, never assumed Not-ECT.
  std::optional<UdpDatagram> receive( size_t capacity = 65535 );

private:
  int fd_ { -1 };
  int family_;
};

} // namespace quic
