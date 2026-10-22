#include "protected_packet.hh"

#include "header_protection.hh"
#include "packet_number.hh"

#include <limits>
#include <stdexcept>
#include <utility>

namespace quic {
namespace {
size_t protected_size( const std::string_view plaintext )
{
  if ( plaintext.size() > static_cast<size_t>( std::numeric_limits<int>::max() ) - 16 ) {
    throw std::invalid_argument( "AEAD input exceeds OpenSSL length limit" );
  }
  return plaintext.size() + 16;
}

std::string seal( const PacketProtectionKeys& keys,
                  std::string header,
                  const uint64_t packet_number,
                  const uint8_t packet_number_length,
                  const std::string_view plaintext )
{
  const size_t pn_offset = header.size() - packet_number_length;
  const auto ciphertext = encrypt_packet_payload( keys, header, packet_number, plaintext );
  header += ciphertext;
  const auto sample = header_protection_sample( header, pn_offset );
  const auto mask = sample ? packet_header_mask( keys.hp, *sample ) : std::nullopt;
  if ( !mask || !apply_header_mask( header, pn_offset, *mask ) ) {
    throw std::runtime_error( "packet header protection failed" );
  }
  return header;
}

PacketOpenResult open( const PacketProtectionKeys& keys,
                       const std::string_view datagram,
                       const size_t offset,
                       const size_t short_dcid_length,
                       const std::optional<uint64_t> largest_received,
                       const PacketKind expected )
{
  if ( largest_received && *largest_received >= max_packet_number ) {
    return {};
  }
  const auto layout = parse_protected_packet( datagram, offset, short_dcid_length );
  if ( !layout || layout->kind != expected ) {
    return {};
  }
  const size_t pn_offset = layout->pn_offset - offset;
  std::string packet { datagram.substr( offset, layout->packet_end - offset ) };
  const auto sample = header_protection_sample( packet, pn_offset );
  const auto mask = sample ? packet_header_mask( keys.hp, *sample ) : std::nullopt;
  if ( !mask || !remove_header_mask( packet, pn_offset, *mask ) ) {
    return {};
  }
  const uint8_t first = static_cast<uint8_t>( packet.front() );
  const uint8_t pn_length = ( first & 3 ) + 1;
  if ( packet.size() - pn_offset < size_t { pn_length } + 16 ) {
    return {};
  }
  uint64_t truncated = 0;
  for ( uint8_t i = 0; i < pn_length; ++i ) {
    truncated = ( truncated << 8 ) | static_cast<uint8_t>( packet[pn_offset + i] );
  }
  uint64_t packet_number = 0;
  try {
    packet_number = decode_packet_number( truncated, pn_length, largest_received );
  } catch ( const std::out_of_range& ) {
    return {};
  }
  const size_t header_length = pn_offset + pn_length;
  auto plaintext = decrypt_packet_payload( keys,
                                           std::string_view { packet }.substr( 0, header_length ),
                                           packet_number,
                                           std::string_view { packet }.substr( header_length ) );
  if ( !plaintext ) {
    return {};
  }
  const bool application = expected == PacketKind::OneRtt;
  if ( ( first & ( application ? 0x18 : 0x0c ) ) != 0 ) {
    return { std::nullopt, 0x0a }; // Authenticated PROTOCOL_VIOLATION, no plaintext.
  }
  return { OpenedProtectedPacket { *layout,
                                   packet_number,
                                   std::move( *plaintext ),
                                   application && ( first & 0x04 ),
                                   application && ( first & 0x20 ) },
           std::nullopt };
}
} // namespace

std::string seal_handshake_packet( const PacketProtectionKeys& keys,
                                   const std::string_view dcid,
                                   const std::string_view scid,
                                   const uint64_t packet_number,
                                   const uint8_t packet_number_length,
                                   const std::string_view plaintext )
{
  auto header = build_long_header(
    LongPacketType::Handshake, dcid, scid, "", packet_number, packet_number_length, protected_size( plaintext ) );
  return seal( keys, std::move( header ), packet_number, packet_number_length, plaintext );
}

std::string seal_one_rtt_packet( const PacketProtectionKeys& keys,
                                 const std::string_view dcid,
                                 const uint64_t packet_number,
                                 const uint8_t packet_number_length,
                                 const std::string_view plaintext,
                                 const bool key_phase,
                                 const bool spin )
{
  auto header
    = build_short_header( dcid, packet_number, packet_number_length, spin, key_phase, protected_size( plaintext ) );
  return seal( keys, std::move( header ), packet_number, packet_number_length, plaintext );
}

PacketOpenResult open_handshake_packet( const PacketProtectionKeys& keys,
                                        const std::string_view datagram,
                                        const size_t offset,
                                        const std::optional<uint64_t> largest_received )
{
  return open( keys, datagram, offset, 0, largest_received, PacketKind::Handshake );
}

PacketOpenResult open_one_rtt_packet( const PacketProtectionKeys& keys,
                                      const std::string_view datagram,
                                      const size_t offset,
                                      const size_t short_dcid_length,
                                      const std::optional<uint64_t> largest_received )
{
  return open( keys, datagram, offset, short_dcid_length, largest_received, PacketKind::OneRtt );
}

} // namespace quic
