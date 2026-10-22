#include "pacer.hh"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace quic {
void PacketPacer::update( const uint64_t now, const uint64_t bytes, const uint64_t window, const double rtt_us )
{
  const auto capacity = std::min<uint64_t>( window, 12000 );
  if ( !window || bytes > capacity || !std::isfinite( rtt_us ) || rtt_us <= 0 )
    throw std::invalid_argument( "invalid QUIC pacing parameters" );
  if ( updated_ && now < *updated_ )
    throw std::logic_error( "QUIC pacing clock moved backwards" );
  if ( updated_ )
    tokens_ = std::min( static_cast<long double>( capacity_ ),
                        tokens_ + static_cast<long double>( now - *updated_ ) * rate_ );
  tokens_ = std::min( tokens_, static_cast<long double>( capacity ) );
  capacity_ = capacity;
  rate_ = 1.25L * static_cast<long double>( window ) / std::max( rtt_us, 1000. );
  updated_ = now;
}
std::optional<uint64_t> PacketPacer::deadline( const uint64_t now,
                                               const uint64_t bytes,
                                               const uint64_t window,
                                               const double rtt_us )
{
  update( now, bytes, window, rtt_us );
  // Ignore only sub-nanosecond floating-point residue at exact boundaries.
  if ( tokens_ + 1e-9L >= bytes )
    return std::nullopt;
  const auto wait = std::max( 1.L, std::ceil( ( bytes - tokens_ ) / rate_ - 1e-9L ) );
  const auto room = UINT64_MAX - now;
  return wait >= static_cast<long double>( room ) ? UINT64_MAX : now + static_cast<uint64_t>( wait );
}
void PacketPacer::sent( const uint64_t now, const uint64_t bytes, const uint64_t window, const double rtt_us )
{
  update( now, bytes, window, rtt_us );
  tokens_ = std::max( 0.L, tokens_ - bytes );
}
} // namespace quic
