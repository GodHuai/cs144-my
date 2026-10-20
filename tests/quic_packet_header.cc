#include "quic/packet_header.hh"

#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( bool condition, std::string_view message )
{
  if ( !condition ) {
    throw std::runtime_error( std::string( message ) );
  }
}

int main()
{
  // RFC 9001 Appendix A.2: unprotected client Initial header, PN=2, four PN bytes.
  const std::string initial_header { "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00"
                                     "\x44\x9e\x00\x00\x00\x02",
                                     22 };
  const std::string dcid { "\x83\x94\xc8\xf0\x3e\x51\x57\x08", 8 };
  const auto built = build_long_header( LongPacketType::Initial, dcid, "", "", 2, 4, 1178 );
  require( built == initial_header, "RFC Initial header build" );
  std::string datagram = initial_header + std::string( 1178, '\0' );
  const auto initial = parse_protected_packet( datagram, 0, 0 );
  require( initial && initial->kind == PacketKind::Initial, "Initial layout" );
  require( initial->dcid == dcid && initial->scid.empty() && initial->token.empty(), "Initial CIDs and token" );
  require( initial->pn_offset == 18 && initial->packet_end == 1200 && initial->version == 1,
           "RFC Initial packet boundaries" );

  const auto handshake = build_long_header( LongPacketType::Handshake, "", "", "", 0, 1, 19 );
  require( handshake == std::string( "\xe0\x00\x00\x00\x01\x00\x00\x14\x00", 9 ), "Handshake header bytes" );
  datagram += handshake + std::string( 19, '\0' );
  const auto second = parse_protected_packet( datagram, initial->packet_end, 0 );
  require( second && second->kind == PacketKind::Handshake && second->pn_offset == 1208
             && second->packet_end == 1228,
           "coalesced packet boundary" );

  const auto zero_rtt_header = build_long_header( LongPacketType::ZeroRtt, "", "", "", 0, 1, 19 );
  require( zero_rtt_header == std::string( "\xd0\x00\x00\x00\x01\x00\x00\x14\x00", 9 ), "0-RTT header bytes" );
  const auto zero_rtt = parse_protected_packet( zero_rtt_header + std::string( 19, '\0' ), 0, 0 );
  require( zero_rtt && zero_rtt->kind == PacketKind::ZeroRtt && zero_rtt->pn_offset == 8, "0-RTT layout" );

  const auto token_header = build_long_header( LongPacketType::Initial, "", "", "xy", 0, 1, 19 );
  require( token_header == std::string( "\xc0\x00\x00\x00\x01\x00\x00\x02xy\x14\x00", 12 ), "Initial token bytes" );
  const auto token_layout = parse_protected_packet( token_header + std::string( 19, '\0' ), 0, 0 );
  require( token_layout && token_layout->token == "xy" && token_layout->pn_offset == 11, "Initial token layout" );

  std::string masked = datagram;
  masked[0] = static_cast<char>( 0xcf ); // PN length and reserved bits are protected.
  const auto masked_layout = parse_protected_packet( masked, 0, 0 );
  require( masked_layout && masked_layout->pn_offset == 18 && masked_layout->packet_end == 1200,
           "protected first-byte low bits affect layout" );

  std::string invalid = datagram;
  invalid[5] = static_cast<char>( 21 );
  require( !parse_protected_packet( invalid, 0, 0 ), "oversize DCID accepted" );
  invalid = datagram;
  invalid[16] = static_cast<char>( 0x44 );
  invalid[17] = static_cast<char>( 0xff );
  require( !parse_protected_packet( invalid, 0, 0 ), "Length crossing datagram accepted" );
  invalid = datagram;
  invalid[16] = 0x40;
  invalid[17] = 0x13;
  require( !parse_protected_packet( invalid, 0, 0 ), "packet too short for HP sample accepted" );
  invalid = datagram;
  invalid[0] = static_cast<char>( 0x83 );
  require( !parse_protected_packet( invalid, 0, 0 ), "zero fixed bit accepted" );
  invalid = datagram;
  invalid[4] = 0;
  require( !parse_protected_packet( invalid, 0, 0 ), "version negotiation accepted" );
  invalid = datagram;
  invalid[0] = static_cast<char>( 0xf3 );
  require( !parse_protected_packet( invalid, 0, 0 ), "Retry accepted as protected packet" );
  require( !parse_protected_packet( std::string( "\xc0\x00\x00\x00\x01\x00\x00\x05xy", 10 ), 0, 0 ),
           "truncated Initial token accepted" );

  const std::string one_rtt_header = build_short_header( dcid, 7, 2, true, true, 18 );
  require( one_rtt_header == std::string( "\x65\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x07", 11 ),
           "1-RTT short header bytes" );
  const auto one_rtt = parse_protected_packet( one_rtt_header + std::string( 18, '\0' ), 0, 8 );
  require( one_rtt && one_rtt->kind == PacketKind::OneRtt && one_rtt->pn_offset == 9 && one_rtt->packet_end == 29
             && one_rtt->dcid == dcid,
           "short header consumes remainder" );
  require( !parse_protected_packet( one_rtt_header + std::string( 17, '\0' ), 0, 8 ),
           "short packet without HP sample accepted" );
  require( !parse_protected_packet( one_rtt_header + std::string( 18, '\0' ), 0, 21 ),
           "oversize short DCID accepted" );
  bool rejected = false;
  try {
    build_short_header( dcid, 7, 2, true, true, 17 );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "short-header builder accepted insufficient HP sample" );
}
