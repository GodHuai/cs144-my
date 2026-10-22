#pragma once

#include "frame.hh"
#include "packet_number_space.hh"

#include <array>
#include <map>
#include <set>

namespace quic {
// Bounded immediate-ACK policy. Times are monotonic microseconds. The connection
// must hand off consecutive packet numbers in each active space; preparation is
// not a send. Retiring a space is terminal for its caller.
class PacketAcknowledgments
{
public:
  struct PendingAck
  {
    AckFrame frame;
    uint64_t generation;
  };
  bool received( PacketKind kind, uint64_t number, bool ack_eliciting, uint64_t now_us );
  std::optional<PendingAck> pending_ack( PacketKind kind, uint64_t now_us, uint8_t exponent ) const;
  void ack_sent( PacketKind kind, uint64_t generation );
  bool can_send( PacketKind kind ) const;
  void sent( PacketKind kind, uint64_t number, bool ack_eliciting );
  bool valid_ack( PacketKind kind, const AckFrame& ack ) const;
  void apply_ack( PacketKind kind, const AckFrame& ack );
  void release( PacketKind kind, uint64_t number );
  size_t outstanding( PacketKind kind ) const;
  void discard( PacketKind kind );

private:
  struct State
  {
    std::map<uint64_t, uint64_t> received {};
    std::optional<uint64_t> largest {};
    uint64_t largest_time {}, generation {};
    bool pending {};
    uint64_t next_sent {};
    std::set<uint64_t> outstanding {};
  };
  std::array<State, 3> spaces_ {};
  State& state( PacketKind kind );
  const State& state( PacketKind kind ) const;
};
} // namespace quic
