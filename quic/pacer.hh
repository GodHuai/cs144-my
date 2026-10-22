#pragma once

#include <cstdint>
#include <optional>

namespace quic {
// One path's bounded byte token bucket. All times are monotonic microseconds.
// The caller exempts pure ACKs; PTO may bypass deadline(), but still calls sent().
class PacketPacer
{
public:
  std::optional<uint64_t> deadline( uint64_t now, uint64_t bytes, uint64_t window, double rtt_us );
  void sent( uint64_t now, uint64_t bytes, uint64_t window, double rtt_us );

private:
  std::optional<uint64_t> updated_ {};
  long double tokens_ { 12000 }, rate_ {};
  uint64_t capacity_ { 12000 };
  void update( uint64_t now, uint64_t bytes, uint64_t window, double rtt_us );
};
} // namespace quic
