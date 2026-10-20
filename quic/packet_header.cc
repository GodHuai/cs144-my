#include "packet_header.hh"

#include "packet_number.hh"
#include "varint.hh"

#include <stdexcept>

namespace quic {

namespace {
constexpr size_t max_connection_id_length = 20;

bool read_cid( const std::string_view datagram, size_t& cursor, std::string& output, const size_t max_length )
{
  if ( cursor >= datagram.size() ) {
    return false;
  }
  const size_t length = static_cast<uint8_t>( datagram[cursor++] );
  if ( length > max_length || length > datagram.size() - cursor ) {
    return false;
  }
  output.assign( datagram.substr( cursor, length ) );
  cursor += length;
  return true;
}

uint32_t read_u32( const std::string_view bytes, size_t& cursor )
{
  uint32_t value = 0;
  for ( size_t i = 0; i < 4; ++i ) {
    value = ( value << 8 ) | static_cast<uint8_t>( bytes[cursor++] );
  }
  return value;
}

void append_u32( std::string& bytes, const uint32_t value )
{
  for ( int shift = 24; shift >= 0; shift -= 8 ) {
    bytes += static_cast<char>( value >> shift );
  }
}
} // namespace

std::optional<VersionNegotiationPacket> parse_version_negotiation( const std::string_view datagram )
{
  if ( datagram.size() < 7 || !( static_cast<uint8_t>( datagram[0] ) & 0x80 ) ) {
    return std::nullopt;
  }
  size_t cursor = 1;
  if ( read_u32( datagram, cursor ) != 0 ) {
    return std::nullopt;
  }
  VersionNegotiationPacket packet { "", "", {} };
  if ( !read_cid( datagram, cursor, packet.dcid, 255 ) || !read_cid( datagram, cursor, packet.scid, 255 )
       || datagram.size() - cursor < 4 || ( datagram.size() - cursor ) % 4 != 0 ) {
    return std::nullopt;
  }
  while ( cursor < datagram.size() ) {
    packet.supported_versions.push_back( read_u32( datagram, cursor ) );
  }
  return packet;
}

std::string build_version_negotiation( const std::string_view dcid,
                                       const std::string_view scid,
                                       const std::vector<uint32_t>& supported_versions,
                                       const uint8_t unused_bits )
{
  if ( dcid.size() > 255 || scid.size() > 255 || supported_versions.empty() || unused_bits > 0x7f ) {
    throw std::invalid_argument( "invalid Version Negotiation fields" );
  }
  std::string result( 1, static_cast<char>( 0x80 | unused_bits ) );
  append_u32( result, 0 );
  result += static_cast<char>( dcid.size() );
  result += dcid;
  result += static_cast<char>( scid.size() );
  result += scid;
  for ( const uint32_t version : supported_versions ) {
    append_u32( result, version );
  }
  return result;
}

std::optional<RetryPacket> parse_retry_packet( const std::string_view datagram )
{
  if ( datagram.size() < 1 + 4 + 1 + 1 + 1 + 16 || ( static_cast<uint8_t>( datagram[0] ) & 0xf0 ) != 0xf0 ) {
    return std::nullopt;
  }
  size_t cursor = 1;
  if ( read_u32( datagram, cursor ) != 1 ) {
    return std::nullopt;
  }
  RetryPacket packet { "", "", "", "" };
  if ( !read_cid( datagram, cursor, packet.dcid, max_connection_id_length )
       || !read_cid( datagram, cursor, packet.scid, max_connection_id_length ) || datagram.size() - cursor <= 16 ) {
    return std::nullopt;
  }
  packet.token.assign( datagram.substr( cursor, datagram.size() - cursor - 16 ) );
  packet.integrity_tag.assign( datagram.substr( datagram.size() - 16 ) );
  return packet;
}

std::optional<PacketLayout> parse_protected_packet( const std::string_view datagram,
                                                    const size_t offset,
                                                    const size_t short_dcid_length )
{
  if ( offset >= datagram.size() || short_dcid_length > max_connection_id_length ) {
    return std::nullopt;
  }
  const uint8_t first = static_cast<uint8_t>( datagram[offset] );
  if ( !( first & 0x40 ) ) {
    return std::nullopt;
  }
  size_t cursor = offset + 1;
  if ( !( first & 0x80 ) ) {
    if ( short_dcid_length > datagram.size() - cursor ) {
      return std::nullopt;
    }
    PacketLayout layout { PacketKind::OneRtt,
                          1,
                          std::string( datagram.substr( cursor, short_dcid_length ) ),
                          "",
                          "",
                          cursor + short_dcid_length,
                          datagram.size() };
    if ( datagram.size() - layout.pn_offset < 20 ) {
      return std::nullopt;
    }
    return layout;
  }

  if ( datagram.size() - cursor < 4 ) {
    return std::nullopt;
  }
  const uint32_t version = read_u32( datagram, cursor );
  if ( version != 1 ) {
    return std::nullopt;
  }
  const uint8_t type = ( first >> 4 ) & 3;
  if ( type == 3 ) { // Retry has no protected packet number or Length field.
    return std::nullopt;
  }
  PacketLayout layout { static_cast<PacketKind>( type ), version, "", "", "", 0, 0 };
  if ( !read_cid( datagram, cursor, layout.dcid, max_connection_id_length )
       || !read_cid( datagram, cursor, layout.scid, max_connection_id_length ) ) {
    return std::nullopt;
  }
  if ( type == 0 ) {
    const auto token_length = decode_varint( datagram, cursor );
    if ( !token_length || *token_length > datagram.size() - cursor ) {
      return std::nullopt;
    }
    layout.token.assign( datagram.substr( cursor, static_cast<size_t>( *token_length ) ) );
    cursor += static_cast<size_t>( *token_length );
  }
  const auto length = decode_varint( datagram, cursor );
  if ( !length || *length < 20 || *length > datagram.size() - cursor ) {
    return std::nullopt;
  }
  layout.pn_offset = cursor;
  layout.packet_end = cursor + static_cast<size_t>( *length );
  return layout;
}

std::string build_long_header( const LongPacketType type,
                               const std::string_view dcid,
                               const std::string_view scid,
                               const std::string_view token,
                               const uint64_t packet_number,
                               const uint8_t pn_length,
                               const size_t protected_payload_length )
{
  if ( static_cast<uint8_t>( type ) > 2 || dcid.size() > max_connection_id_length
       || scid.size() > max_connection_id_length || ( type != LongPacketType::Initial && !token.empty() ) ) {
    throw std::invalid_argument( "invalid long-header type, connection ID or token" );
  }
  if ( pn_length < 1 || pn_length > 4 || protected_payload_length < size_t { 20 } - pn_length
       || protected_payload_length > max_varint - pn_length ) {
    throw std::invalid_argument( "invalid protected payload or packet-number length" );
  }
  std::string result( 1, static_cast<char>( 0xc0 | ( static_cast<uint8_t>( type ) << 4 ) | ( pn_length - 1 ) ) );
  result += std::string( "\x00\x00\x00\x01", 4 );
  result += static_cast<char>( dcid.size() );
  result += dcid;
  result += static_cast<char>( scid.size() );
  result += scid;
  if ( type == LongPacketType::Initial ) {
    result += encode_varint( token.size() );
    result += token;
  }
  result += encode_varint( protected_payload_length + pn_length );
  result += encode_packet_number( packet_number, pn_length );
  return result;
}

std::string build_short_header( const std::string_view dcid,
                                const uint64_t packet_number,
                                const uint8_t pn_length,
                                const bool spin,
                                const bool key_phase,
                                const size_t protected_payload_length )
{
  if ( dcid.size() > max_connection_id_length || pn_length < 1 || pn_length > 4
       || protected_payload_length < size_t { 20 } - pn_length ) {
    throw std::invalid_argument( "invalid short-header connection ID, packet-number length or payload" );
  }
  const uint8_t first = 0x40 | ( spin ? 0x20 : 0 ) | ( key_phase ? 0x04 : 0 ) | ( pn_length - 1 );
  return std::string( 1, static_cast<char>( first ) ) + std::string( dcid )
         + encode_packet_number( packet_number, pn_length );
}

} // namespace quic
