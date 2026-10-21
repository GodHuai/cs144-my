#include "initial_packet.hh"

#include "header_protection.hh"
#include "packet_number.hh"

#include <stdexcept>
#include <string>
#include <utility>

namespace quic {

std::string seal_initial_packet( const InitialPacketKeys& keys,
                                 const InitialSender sender,
                                 const std::string_view dcid,
                                 const std::string_view scid,
                                 const std::string_view token,
                                 const uint64_t packet_number,
                                 const uint8_t packet_number_length,
                                 const std::string_view plaintext )
{
  if ( sender == InitialSender::Server && !token.empty() ) {
    throw std::invalid_argument( "server Initial token must be empty" );
  }
  auto packet = build_long_header( LongPacketType::Initial,
                                   dcid,
                                   scid,
                                   token,
                                   packet_number,
                                   packet_number_length,
                                   plaintext.size() + 16 );
  const size_t pn_offset = packet.size() - packet_number_length;
  packet += encrypt_initial_payload( keys, packet, packet_number, plaintext );
  const auto sample = header_protection_sample( packet, pn_offset );
  if ( !sample ) {
    throw std::invalid_argument( "Initial packet too short for header protection sample" );
  }
  const auto mask = initial_header_mask( keys.hp, *sample );
  if ( !mask || !apply_header_mask( packet, pn_offset, *mask ) ) {
    throw std::runtime_error( "Initial header protection failed" );
  }
  return packet;
}

std::optional<OpenedInitialPacket> open_initial_packet( const InitialPacketKeys& keys,
                                                        const InitialSender sender,
                                                        const std::string_view datagram,
                                                        const size_t offset,
                                                        const std::optional<uint64_t> largest_received )
{
  if ( largest_received && *largest_received >= max_packet_number ) {
    return std::nullopt;
  }
  const auto layout = parse_protected_packet( datagram, offset, 0 );
  if ( !layout || layout->kind != PacketKind::Initial
       || ( sender == InitialSender::Server && !layout->token.empty() ) ) {
    return std::nullopt;
  }
  const size_t pn_offset = layout->pn_offset - offset;
  std::string packet { datagram.substr( offset, layout->packet_end - offset ) };
  const auto sample = header_protection_sample( packet, pn_offset );
  if ( !sample ) {
    return std::nullopt;
  }
  const auto mask = initial_header_mask( keys.hp, *sample );
  if ( !mask || !remove_header_mask( packet, pn_offset, *mask ) ) {
    return std::nullopt;
  }
  const uint8_t first = static_cast<uint8_t>( packet[0] );
  const uint8_t pn_length = ( first & 3 ) + 1;
  if ( packet.size() - pn_offset < size_t { pn_length } + 16 ) {
    return std::nullopt;
  }
  uint64_t truncated_pn = 0;
  for ( uint8_t i = 0; i < pn_length; ++i ) {
    truncated_pn = ( truncated_pn << 8 ) | static_cast<uint8_t>( packet[pn_offset + i] );
  }
  uint64_t packet_number = 0;
  try {
    packet_number = decode_packet_number( truncated_pn, pn_length, largest_received );
  } catch ( const std::out_of_range& ) {
    return std::nullopt;
  }
  const size_t header_length = pn_offset + pn_length;
  auto plaintext = decrypt_initial_payload( keys,
                                            std::string_view { packet }.substr( 0, header_length ),
                                            packet_number,
                                            std::string_view { packet }.substr( header_length ) );
  // RFC 9000 §17.2: validate protected reserved bits after authentication.
  if ( !plaintext || ( first & 0x0c ) != 0 ) {
    return std::nullopt;
  }
  return OpenedInitialPacket { *layout, packet_number, std::move( *plaintext ) };
}

} // namespace quic
