#pragma once

#include <optional>

namespace quic {

// RFC 9002 section 5.1: The ACK processor calls observe only if the ACK frame's
// Largest Acknowledged is newly acknowledged and at least one newly acknowledged
// packet is ack-eliciting. Measure from that Largest Acknowledged packet, even
// when it is not itself ack-eliciting.
class RttEstimator
{
public:
  explicit RttEstimator( double initial_rtt_ms = 333 );

  void reset( double initial_rtt_ms = 333 );
  void observe( double latest_rtt_ms, double ack_delay_ms, bool handshake_confirmed, double max_ack_delay_ms );

  double latest_ms() const { return latest_rtt_ms_; }
  std::optional<double> min_ms() const { return min_rtt_ms_; }
  double smoothed_ms() const { return smoothed_rtt_ms_; }
  double rttvar_ms() const { return rttvar_ms_; }

  // RFC 9002 section 6.2.1. The timer owner handles backoff and in-flight rules.
  std::optional<double> pto_ms( bool application_data, bool handshake_confirmed, double max_ack_delay_ms ) const;

private:
  double latest_rtt_ms_ {};
  std::optional<double> min_rtt_ms_ {};
  double smoothed_rtt_ms_ {};
  double rttvar_ms_ {};
};

} // namespace quic
