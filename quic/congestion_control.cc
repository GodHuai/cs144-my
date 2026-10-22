#include "congestion_control.hh"

#include <algorithm>
#include <stdexcept>

namespace quic {
bool NewReno::can_send( const uint64_t bytes, const bool probe ) const
{
  return probe || ( state_.bytes_in_flight <= state_.window && bytes <= state_.window - state_.bytes_in_flight );
}
void NewReno::sent( const uint64_t bytes )
{
  if ( bytes > UINT64_MAX - state_.bytes_in_flight )
    throw std::overflow_error( "QUIC bytes in flight overflow" );
  state_.bytes_in_flight += bytes;
}
void NewReno::discard( const uint64_t bytes )
{
  if ( bytes > state_.bytes_in_flight )
    throw std::logic_error( "QUIC bytes in flight underflow" );
  state_.bytes_in_flight -= bytes;
}
void NewReno::acknowledged( const uint64_t bytes, const uint64_t sent_at, const bool limited )
{
  discard( bytes );
  if ( limited || ( recovery_start_ && sent_at <= *recovery_start_ ) )
    return;
  const long double increase = state_.window < state_.slow_start_threshold
                                 ? static_cast<long double>( bytes )
                                 : 1200.L * static_cast<long double>( bytes ) / state_.window;
  credit_ += increase;
  const uint64_t room = UINT64_MAX - state_.window;
  const auto whole = credit_ >= static_cast<long double>( room ) ? room : static_cast<uint64_t>( credit_ );
  state_.window += whole;
  credit_ -= static_cast<long double>( whole );
}
void NewReno::lost( const uint64_t bytes, const uint64_t sent_at, const uint64_t now )
{
  discard( bytes );
  if ( recovery_start_ && sent_at <= *recovery_start_ )
    return;
  recovery_start_ = now;
  state_.slow_start_threshold = state_.window / 2;
  state_.window = std::max<uint64_t>( state_.slow_start_threshold, 2400 );
  credit_ = 0;
}
} // namespace quic
