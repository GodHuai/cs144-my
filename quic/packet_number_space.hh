#pragma once

#include "packet_header.hh"
#include "packet_number.hh"

#include <array>
#include <cstdint>
#include <map>
#include <optional>

namespace quic {

enum class PacketNumberSpaceId : uint8_t
{
  Initial,
  Handshake,
  Application
};

PacketNumberSpaceId packet_number_space( PacketKind kind );

// Packet number state for one connection. Receive records are inclusive ranges.
// Call record_authenticated only after packet protection has been removed and
// AEAD authentication succeeded. The connection chooses when to retire old
// receive ranges, accounting for delayed packets and path RTT.
class PacketNumberSpaces
{
public:
  PacketNumberSpaces();
  PacketNumberSpaces( const PacketNumberSpaces& ) = delete;
  PacketNumberSpaces& operator=( const PacketNumberSpaces& ) = delete;
  PacketNumberSpaces( PacketNumberSpaces&& ) = delete;
  PacketNumberSpaces& operator=( PacketNumberSpaces&& ) = delete;

  // The terminal packet number 2^62-1 must not be sent. An empty result means
  // the connection must stop sending as required by RFC 9000 Section 12.3.
  std::optional<uint64_t> allocate( PacketKind kind );
  bool record_authenticated( PacketKind kind, uint64_t number );
  std::optional<uint64_t> largest_received( PacketKind kind ) const;
  void retire_received_below( PacketKind kind, uint64_t minimum );

private:
  struct State
  {
    State();
    uint64_t next_send;
    uint64_t min_acceptable;
    std::optional<uint64_t> largest_received;
    std::map<uint64_t, uint64_t> received_ranges;
  };

  State& state( PacketKind kind );
  const State& state( PacketKind kind ) const;
  std::array<State, 3> states_;
};

} // namespace quic
