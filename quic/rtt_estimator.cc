#include "rtt_estimator.hh"

#include <algorithm>
#include <cmath>
#include <stdexcept>

using namespace std;

namespace quic {

namespace {
void require_nonnegative_finite( const double value )
{
  if ( !isfinite( value ) or value < 0 ) {
    throw invalid_argument( "RTT and ACK-delay values must be finite and nonnegative" );
  }
}
} // namespace

RttEstimator::RttEstimator( const double initial_rtt_ms )
{
  reset( initial_rtt_ms );
}

void RttEstimator::reset( const double initial_rtt_ms )
{
  require_nonnegative_finite( initial_rtt_ms );
  if ( initial_rtt_ms == 0 ) {
    throw invalid_argument( "initial RTT must be positive" );
  }
  latest_rtt_ms_ = 0;
  min_rtt_ms_.reset();
  smoothed_rtt_ms_ = initial_rtt_ms;
  rttvar_ms_ = initial_rtt_ms / 2;
}

void RttEstimator::observe( const double latest_rtt_ms,
                            const double ack_delay_ms,
                            const bool handshake_confirmed,
                            const double max_ack_delay_ms )
{
  require_nonnegative_finite( latest_rtt_ms );
  require_nonnegative_finite( ack_delay_ms );
  require_nonnegative_finite( max_ack_delay_ms );
  if ( latest_rtt_ms == 0 ) {
    throw invalid_argument( "RTT sample must be positive" );
  }

  latest_rtt_ms_ = latest_rtt_ms;
  if ( !min_rtt_ms_ ) {
    min_rtt_ms_ = latest_rtt_ms;
    smoothed_rtt_ms_ = latest_rtt_ms;
    rttvar_ms_ = latest_rtt_ms / 2;
    return;
  }
  min_rtt_ms_ = min( *min_rtt_ms_, latest_rtt_ms );
  const double allowed_ack_delay = handshake_confirmed ? min( ack_delay_ms, max_ack_delay_ms ) : ack_delay_ms;
  double adjusted_rtt = latest_rtt_ms;
  if ( latest_rtt_ms >= *min_rtt_ms_ + allowed_ack_delay ) {
    adjusted_rtt -= allowed_ack_delay;
  }
  smoothed_rtt_ms_ = 0.875 * smoothed_rtt_ms_ + 0.125 * adjusted_rtt;
  rttvar_ms_ = 0.75 * rttvar_ms_ + 0.25 * abs( smoothed_rtt_ms_ - adjusted_rtt );
}

optional<double> RttEstimator::pto_ms( const bool application_data,
                                       const bool handshake_confirmed,
                                       const double max_ack_delay_ms ) const
{
  require_nonnegative_finite( max_ack_delay_ms );
  if ( application_data and !handshake_confirmed ) {
    return nullopt;
  }
  const double ack_delay = application_data ? max_ack_delay_ms : 0;
  return max( 1.0, smoothed_rtt_ms_ + max( 4 * rttvar_ms_, 1.0 ) + ack_delay );
}

} // namespace quic
