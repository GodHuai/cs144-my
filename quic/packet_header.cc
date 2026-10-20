#include "packet_header.hh"

#include "packet_number.hh"
#include "varint.hh"

#include <stdexcept>

namespace quic {

namespace {
constexpr size_t max_connection_id_length = 20;

bool read_cid( const std::string_view datagram, size_t& cursor, std::string& output )
{
  if ( cursor >= datagram.size() ) {
    return false;
  }
  const size_t length = static_cast<uint8_t>( datagram[cursor++] );
  if ( length > max_connection_id_length || length > datagram.size() - cursor ) {
    return false;
  }
  output.assign( datagram.substr( cursor, length ) );
  cursor += length;
  return true;
}
} // namespace

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
  uint32_t version = 0;
  for ( size_t i = 0; i < 4; ++i ) {
    version = ( version << 8 ) | static_cast<uint8_t>( datagram[cursor++] );
  }
  if ( version != 1 ) {
    return std::nullopt;
  }
  const uint8_t type = ( first >> 4 ) & 3;
  if ( type == 3 ) { // Retry has no protected packet number or Length field.
    return std::nullopt;
  }
  PacketLayout layout { static_cast<PacketKind>( type ), version, "", "", "", 0, 0 };
  if ( !read_cid( datagram, cursor, layout.dcid ) || !read_cid( datagram, cursor, layout.scid ) ) {
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
