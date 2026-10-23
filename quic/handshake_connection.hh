#pragma once

#include "application_streams.hh"
#include "congestion_control.hh"
#include "rtt_estimator.hh"
#include "tls_handshake.hh"
#include "udp_socket.hh"
#include <functional>

#include <memory>
#include <optional>
#include <string>

namespace quic {
struct ConnectionConfig
{
  TlsConfig tls {};
  std::function<uint64_t()> clock_us {}; // Optional monotonic clock; default steady_clock.
  std::string local_cid {};
  std::string initial_dcid {}; // Client only, 8..20 bytes; no Retry in this engine.
};
enum class ConnectionState
{
  WaitingInitial,
  Handshaking,
  Established,
  Confirmed,
  Draining,
  Failed
};
enum class ConnectionReceive
{
  Discarded,
  Processed,
  Failed
};

// Single-threaded, single pinned UDP peer; reusable sans-I/O handshake engine.
// Bounded reliable streams, flow control, recovery, NewReno and pacing; no listener, migration or
// close timers yet. It is not a complete QUIC transport. Caller provides random
// 8..20-byte CIDs and dispatches datagrams to the appropriate connection.
class HandshakeConnection
{
public:
  HandshakeConnection( ConnectionConfig config, UdpEndpoint peer );
  ~HandshakeConnection();
  HandshakeConnection( const HandshakeConnection& ) = delete;
  HandshakeConnection& operator=( const HandshakeConnection& ) = delete;
  ConnectionReceive receive( const UdpDatagram& datagram );
  // Handoff reserves amplification bytes and advances send cursors. If UDP
  // would block, retain/retry THIS datagram, without polling for its replacement.
  std::optional<UdpDatagram> poll_transmit();
  std::optional<uint64_t> next_timeout_us() const;
  void on_timeout();
  RttEstimator rtt_estimate() const;
  CongestionStats congestion_stats() const;
  size_t packets_awaiting_ack( PacketKind kind ) const;
  bool send_ping(); // One bounded pending PING, only after TLS completion.
  // Application operations require TLS completion; absent stream credits default to zero.
  std::optional<uint64_t> open_stream( bool unidirectional );
  bool write_stream( uint64_t id, std::string_view data, bool fin = false );
  StreamRead read_stream( uint64_t id, size_t maximum );
  std::vector<uint64_t> stream_ids() const;
  bool reset_stream( uint64_t id, uint64_t error );
  bool stop_sending( uint64_t id, uint64_t error );
  size_t stream_send_buffered() const;
  ConnectionState state() const;
  std::optional<uint64_t> transport_error() const;
  std::string peer_cid() const;
  std::optional<TransportParameters> peer_parameters() const;
  std::string negotiated_alpn() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace quic
