#include "header_protection.hh"

namespace quic {

std::optional<std::string_view> header_protection_sample( const std::string_view packet, const size_t pn_offset )
{
  if ( pn_offset > packet.size() or packet.size() - pn_offset < 20 ) {
    return std::nullopt;
  }
  return packet.substr( pn_offset + 4, 16 );
}

bool apply_header_mask( std::string& packet, const size_t pn_offset, const std::array<uint8_t, 5>& mask )
{
  if ( packet.empty() or pn_offset > packet.size() ) {
    return false;
  }
  const uint8_t first = static_cast<uint8_t>( packet[0] );
  const size_t pn_length = ( first & 0x03 ) + 1;
  if ( packet.size() - pn_offset < pn_length ) {
    return false;
  }
  packet[0] = static_cast<char>( first ^ ( mask[0] & ( first & 0x80 ? 0x0f : 0x1f ) ) );
  for ( size_t i = 0; i < pn_length; ++i ) {
    packet[pn_offset + i] = static_cast<char>( static_cast<uint8_t>( packet[pn_offset + i] ) ^ mask[i + 1] );
  }
  return true;
}

bool remove_header_mask( std::string& packet, const size_t pn_offset, const std::array<uint8_t, 5>& mask )
{
  if ( packet.empty() or pn_offset > packet.size() ) {
    return false;
  }
  const uint8_t first = static_cast<uint8_t>( packet[0] );
  const uint8_t unmasked_first = first ^ ( mask[0] & ( first & 0x80 ? 0x0f : 0x1f ) );
  const size_t pn_length = ( unmasked_first & 0x03 ) + 1;
  if ( packet.size() - pn_offset < pn_length ) {
    return false;
  }
  packet[0] = static_cast<char>( unmasked_first );
  for ( size_t i = 0; i < pn_length; ++i ) {
    packet[pn_offset + i] = static_cast<char>( static_cast<uint8_t>( packet[pn_offset + i] ) ^ mask[i + 1] );
  }
  return true;
}

} // namespace quic
