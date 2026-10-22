#pragma once

#include <cstdint>
#include <limits>
#include <optional>

namespace quic {
struct CongestionStats
{
  uint64_t window { 12000 }, bytes_in_flight {};
  uint64_t slow_start_threshold { std::numeric_limits<uint64_t>::max() };
};
// Single fixed-1200-byte path NewReno foundation. No pacing, ECN or persistent
// congestion detector. Packet recovery owns exactly-once physical flight events.
class NewReno
{
public:
  bool can_send( uint64_t bytes, bool probe = false ) const;
  void sent( uint64_t bytes );
  void acknowledged( uint64_t bytes, uint64_t sent_at, bool limited );
  void lost( uint64_t bytes, uint64_t sent_at, uint64_t now );
  void discard( uint64_t bytes );
  CongestionStats stats() const { return state_; }

private:
  CongestionStats state_ {};
  std::optional<uint64_t> recovery_start_ {};
  long double credit_ {};
};
} // namespace quic
