#include "wrapping_integers.hh"

#include <limits>

using namespace std;

Wrap32 Wrap32::wrap( uint64_t n, Wrap32 zero_point )
{
  return Wrap32 { zero_point.raw_value_ + static_cast<uint32_t>( n ) };
}

uint64_t Wrap32::unwrap( Wrap32 zero_point, uint64_t checkpoint ) const
{
  constexpr uint64_t modulus = uint64_t { 1 } << 32;
  // The smallest nonnegative absolute sequence number with this wrapped value.
  uint64_t candidate = static_cast<uint32_t>( raw_value_ - zero_point.raw_value_ );

  if ( checkpoint > candidate ) {
    candidate += ( ( checkpoint - candidate ) / modulus ) * modulus;
  }

  // candidate is the nearest value at or below checkpoint, if one exists.
  // Compare it with the next wrap without overflowing uint64_t.
  if ( candidate <= numeric_limits<uint64_t>::max() - modulus ) {
    const uint64_t next = candidate + modulus;
    if ( next >= checkpoint
         && next - checkpoint < ( candidate > checkpoint ? candidate - checkpoint : checkpoint - candidate ) ) {
      candidate = next;
    }
  }

  return candidate;
}
