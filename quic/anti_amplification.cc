#include "anti_amplification.hh"

#include <limits>

using namespace std;

namespace quic {

void AntiAmplificationBudget::record_received( const uint64_t udp_payload_bytes )
{
  if ( validated_ || role_ == AmplificationRole::Initiator ) {
    return;
  }
  const uint64_t max = numeric_limits<uint64_t>::max();
  received_ = udp_payload_bytes > max - received_ ? max : received_ + udp_payload_bytes;
}

optional<uint64_t> AntiAmplificationBudget::remaining_bytes() const
{
  if ( validated_ || role_ == AmplificationRole::Initiator ) {
    return nullopt;
  }
  const uint64_t max = numeric_limits<uint64_t>::max();
  const uint64_t limit = received_ > max / 3 ? max : 3 * received_;
  return limit - sent_;
}

bool AntiAmplificationBudget::record_sent( const uint64_t udp_payload_bytes )
{
  const auto remaining = remaining_bytes();
  if ( remaining && udp_payload_bytes > *remaining ) {
    return false;
  }
  if ( !validated_ && role_ == AmplificationRole::Responder ) {
    sent_ += udp_payload_bytes;
  }
  return true;
}

} // namespace quic
