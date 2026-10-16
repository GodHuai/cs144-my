#include "varint.hh"

#include <stdexcept>

using namespace std;

namespace quic {

string encode_varint( const uint64_t value )
{
  if ( value > max_varint ) {
    throw out_of_range( "QUIC varint exceeds 62 bits" );
  }

  size_t length = 1;
  if ( value >= ( uint64_t { 1 } << 30 ) ) {
    length = 8;
  } else if ( value >= ( uint64_t { 1 } << 14 ) ) {
    length = 4;
  } else if ( value >= ( uint64_t { 1 } << 6 ) ) {
    length = 2;
  }

  string result( length, '\0' );
  for ( size_t i = 0; i < length; ++i ) {
    result[length - 1 - i] = static_cast<char>( value >> ( i * 8 ) );
  }
  result[0] = static_cast<char>( static_cast<uint8_t>( result[0] )
                                 | ( ( length == 1   ? 0
                                       : length == 2 ? 1
                                       : length == 4 ? 2
                                                     : 3 )
                                     << 6 ) );
  return result;
}

optional<uint64_t> decode_varint( const string_view input, size_t& offset )
{
  if ( offset >= input.size() ) {
    return nullopt;
  }

  const uint8_t first = static_cast<uint8_t>( input[offset] );
  const size_t length = size_t { 1 } << ( first >> 6 );
  if ( length > input.size() - offset ) {
    return nullopt;
  }

  uint64_t value = first & 0x3f;
  for ( size_t i = 1; i < length; ++i ) {
    value = ( value << 8 ) | static_cast<uint8_t>( input[offset + i] );
  }
  offset += length;
  return value;
}

} // namespace quic
