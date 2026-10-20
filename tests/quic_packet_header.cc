#include "quic/packet_header.hh"

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

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

  // RFC 9000 17.2.1: VN has no packet number or Length and occupies one datagram.
  const std::string vn_wire { "\xc0\x00\x00\x00\x00\x02xy\x01z\x00\x00\x00\x02\x0a\x1a\x2a\x3a", 18 };
  require( build_version_negotiation( "xy", "z", { 2, 0x0a1a2a3a } ) == vn_wire, "VN wire bytes" );
  const auto vn = parse_version_negotiation( vn_wire );
  require( vn && vn->dcid == "xy" && vn->scid == "z"
             && vn->supported_versions == std::vector<uint32_t> { 2, 0x0a1a2a3a },
           "VN fields" );
  auto arbitrary_unused = vn_wire;
  arbitrary_unused[0] = static_cast<char>( 0x8f ); // Fixed Bit is unused in VN.
  require( parse_version_negotiation( arbitrary_unused ).has_value(), "VN arbitrary unused bits" );
  require( !parse_version_negotiation( vn_wire.substr( 0, vn_wire.size() - 1 ) ), "VN partial version" );
  require( !parse_version_negotiation( vn_wire.substr( 0, 11 ) ), "VN missing version list" );
  auto bad_vn = vn_wire;
  bad_vn[0] = 0x40;
  require( !parse_version_negotiation( bad_vn ), "VN short header" );
  bad_vn = vn_wire;
  bad_vn[4] = 1;
  require( !parse_version_negotiation( bad_vn ), "VN nonzero version" );
  bad_vn = vn_wire;
  bad_vn[5] = static_cast<char>( 255 );
  require( !parse_version_negotiation( bad_vn ), "VN truncated CID" );
  const std::string long_cid( 21, 'x' );
  const auto long_vn = parse_version_negotiation( build_version_negotiation( long_cid, "", { 2 } ) );
  require( long_vn && long_vn->dcid == long_cid, "VN future-version CID lengths" );
  rejected = false;
  try {
    build_version_negotiation( "", "", {} );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "VN empty supported version list" );
  rejected = false;
  try {
    build_version_negotiation( std::string( 256, 'x' ), "", { 2 } );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "VN unencodable CID length" );

  // RFC 9000 17.2.5: Retry has an opaque token and trailing 16-byte tag.
  const std::string tag( 16, '\x7f' );
  const std::string retry_wire { "\xf0\x00\x00\x00\x01\x02xy\x01ztoken", 15 };
  const auto retry = parse_retry_packet( retry_wire + tag );
  require( retry && retry->dcid == "xy" && retry->scid == "z" && retry->token == "token"
             && retry->integrity_tag == tag,
           "Retry fields" );
  require( !parse_retry_packet( retry_wire ), "Retry missing tag" );
  require( !parse_retry_packet( retry_wire.substr( 0, 10 ) + tag ), "Retry empty token" );
  auto bad_retry = retry_wire + tag;
  bad_retry[0] = static_cast<char>( 0xb0 );
  require( !parse_retry_packet( bad_retry ), "Retry fixed bit" );
  bad_retry = retry_wire + tag;
  bad_retry[4] = 0;
  require( !parse_retry_packet( bad_retry ), "Retry wrong version" );
  bad_retry = retry_wire + tag;
  bad_retry[5] = 21;
  require( !parse_retry_packet( bad_retry ), "Retry oversize CID" );
}
