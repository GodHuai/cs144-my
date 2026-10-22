#pragma once

#include "frame.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

enum class CryptoReceiveError : uint64_t
{
  FrameEncodingError = 0x07,
  ProtocolViolation = 0x0a,
  BufferExceeded = 0x0d
};

// CRYPTO byte transport for one connection, independently per encryption level.
// Receive only authenticated, decoded frames. The connection must translate a
// returned error into CONNECTION_CLOSE; this class does not send or ACK packets.
class CryptoStreams
{
public:
  explicit CryptoStreams( size_t receive_capacity = 65536, size_t send_capacity = 65536 );

  // All reported errors are atomic. Conflicting unread overlaps are rejected;
  // data already handed to TLS is ignored without keeping duplicate history.
  std::optional<CryptoReceiveError> receive( PacketKind kind, const CryptoFrame& frame );
  std::string take_contiguous( PacketKind kind );
  size_t bytes_buffered( PacketKind kind ) const;
  uint64_t read_offset( PacketKind kind ) const;

  // Outgoing bytes stay available for refragmentation until discard(). Appends
  // fail atomically at the send limit. max_data excludes CRYPTO wire overhead.
  bool append( PacketKind kind, std::string_view data );
  std::optional<CryptoFrame> frame( PacketKind kind, uint64_t offset, size_t max_data ) const;

  // Terminal per-level release when its keys are discarded. Late input is
  // ignored and outgoing data cannot resurrect it. Other levels are untouched.
  void discard( PacketKind kind );

private:
  struct State
  {
    uint64_t read_offset {};
    size_t buffered {};
    std::map<uint64_t, std::string> pending {};
    std::string outgoing {};
    bool discarded { false };
  };

  State* state( PacketKind kind );
  const State* state( PacketKind kind ) const;
  std::array<State, 3> states_ {};
  size_t receive_capacity_;
  size_t send_capacity_;
};

} // namespace quic
