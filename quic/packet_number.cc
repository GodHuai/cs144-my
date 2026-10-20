#include "packet_number.hh"

#include <stdexcept>

using namespace std;

namespace quic {

uint8_t choose_packet_number_length( const uint64_t packet_number, const optional<uint64_t> largest_acked )
{
  if ( packet_number > max_packet_number ) {
    throw out_of_range( "QUIC packet number exceeds 62 bits" );
  }
  if ( largest_acked and *largest_acked >= packet_number ) {
    throw invalid_argument( "largest ACK must precede new packet number" );
  }
  if ( not largest_acked ) {
    for ( uint8_t length = 1; length <= 4; ++length ) {
      if ( packet_number < ( uint64_t { 1 } << ( 8 * length ) ) ) {
        return length;
      }
    }
    throw out_of_range( "full initial packet number needs more than four bytes" );
  }

  const uint64_t unacked = packet_number - *largest_acked;
  for ( uint8_t length = 1; length <= 4; ++length ) {
    if ( unacked < ( uint64_t { 1 } << ( 8 * length - 1 ) ) ) {
      return length;
    }
  }
  throw out_of_range( "packet number cannot be safely encoded in four bytes" );
}

string encode_packet_number( const uint64_t packet_number, const uint8_t length )
{
  if ( packet_number > max_packet_number ) {
    throw out_of_range( "QUIC packet number exceeds 62 bits" );
  }
  if ( length < 1 or length > 4 ) {
    throw invalid_argument( "packet number field must use one to four bytes" );
  }
  string result( length, '\0' );
  for ( uint8_t i = 0; i < length; ++i ) {
    result[length - 1 - i] = static_cast<char>( packet_number >> ( 8 * i ) );
  }
  return result;
}

uint64_t decode_packet_number( const uint64_t truncated,
                               const uint8_t length,
                               const optional<uint64_t> largest_received )
{
  if ( length < 1 or length > 4 ) {
    throw invalid_argument( "packet number field must use one to four bytes" );
  }
  const uint64_t window = uint64_t { 1 } << ( 8 * length );
  if ( truncated >= window ) {
    throw invalid_argument( "truncated packet number exceeds field width" );
  }
  if ( largest_received and *largest_received >= max_packet_number ) {
    throw out_of_range( "packet number space exhausted" );
  }

  const uint64_t expected = largest_received ? *largest_received + 1 : 0;
  const uint64_t half_window = window / 2;
  const uint64_t mask = window - 1;
  uint64_t candidate = ( expected & ~mask ) | truncated;
  if ( candidate <= expected and expected - candidate >= half_window and candidate <= max_packet_number - window ) {
    candidate += window;
  } else if ( candidate > expected + half_window and candidate >= window ) {
    candidate -= window;
  }
  if ( candidate > max_packet_number ) {
    throw out_of_range( "decoded packet number exceeds 62 bits" );
  }
  return candidate;
}

} // namespace quic
