#include "quic/header_protection.hh"
#include "quic/packet_number.hh"
#include "quic/packet_number_space.hh"
#include "quic/rtt_estimator.hh"

#include <array>
#include <cmath>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

using namespace quic;

void require( bool condition, std::string_view message )
{
  if ( !condition ) {
    throw std::runtime_error( std::string { message } );
  }
}

void near( double actual, double expected, std::string_view message )
{
  require( std::abs( actual - expected ) < 0.000001, message );
}

int main()
{
  // RFC 9000 Appendix A.2: 0xac5c02 after ACK 0xabe8b3 needs two bytes.
  require( choose_packet_number_length( 0xac5c02, 0xabe8b3 ) == 2, "RFC encoding length" );
  require( encode_packet_number( 0xac5c02, 2 ) == std::string( "\x5c\x02", 2 ), "RFC encoded bytes" );
  require( choose_packet_number_length( 0xace8fe, 0xabe8b3 ) == 3, "RFC wider encoding" );

  // RFC 9000 Appendix A.3: reconstruct nearest number to the expected next packet.
  require( decode_packet_number( 0x9b32, 2, 0xa82f30ea ) == 0xa82f9b32, "RFC packet number reconstruction" );
  require( decode_packet_number( 0xff, 1, 0xff ) == 0xff, "decode reordered number" );
  require( decode_packet_number( 0x00, 1, 0xff ) == 0x100, "decode wrapped low bits" );

  require( choose_packet_number_length( 0, std::nullopt ) == 1, "first packet length" );
  require( choose_packet_number_length( 128, std::nullopt ) == 1, "full initial packet number fits in one byte" );
  require( choose_packet_number_length( ( uint64_t { 1 } << 32 ) - 1, std::nullopt ) == 4,
           "largest full packet number that fits in wire field" );
  require( encode_packet_number( 0x123456, 3 ) == std::string( "\x12\x34\x56", 3 ), "big-endian bytes" );

  bool rejected = false;
  try {
    choose_packet_number_length( max_packet_number + 1, std::nullopt );
  } catch ( const std::out_of_range& ) {
    rejected = true;
  }
  require( rejected, "packet number above 62 bits accepted" );

  rejected = false;
  try {
    encode_packet_number( 7, 0 );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "zero-byte packet number accepted" );

  // RFC 9001 Appendix A.2: applying the specified mask to a client Initial header.
  std::string initial { "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00"
                        "\x44\x9e\x00\x00\x00\x02",
                        22 };
  const std::string plain_initial = initial;
  const std::array<uint8_t, 5> mask { 0x43, 0x7b, 0x9a, 0xec, 0x36 };
  require( apply_header_mask( initial, 18, mask ), "Initial header mask rejected" );
  require( initial
             == std::string( "\xc0\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00"
                             "\x44\x9e\x7b\x9a\xec\x34",
                             22 ),
           "RFC Initial protected header" );
  require( remove_header_mask( initial, 18, mask ), "Initial header unmask rejected" );
  require( initial == plain_initial, "Initial unmask did not restore original" );

  std::string short_header { "\x41\xab\xcd", 3 }; // short header, two-byte packet number
  const std::array<uint8_t, 5> short_mask { 0x1f, 0x01, 0x02, 0, 0 };
  require( apply_header_mask( short_header, 1, short_mask ), "short header mask rejected" );
  require( static_cast<uint8_t>( short_header[0] ) == 0x5e, "short header mask width" );
  require( remove_header_mask( short_header, 1, short_mask ), "short header unmask rejected" );
  require( short_header == std::string( "\x41\xab\xcd", 3 ), "short header roundtrip" );

  const std::string too_short { "\xc3\x00\x00", 3 };
  std::string invalid = too_short;
  require( !apply_header_mask( invalid, 1, mask ), "truncated packet number accepted" );
  require( invalid == too_short, "invalid mask mutated packet" );
  require( !header_protection_sample( std::string( 19, '\0' ), 0 ).has_value(), "short sample accepted" );
  require( header_protection_sample( std::string( 20, '\0' ), 0 )->size() == 16, "sample length" );

  RttEstimator rtt;
  near( rtt.smoothed_ms(), 333, "initial smoothed RTT" );
  near( rtt.rttvar_ms(), 166.5, "initial RTT variation" );
  near( *rtt.pto_ms( false, false, 25 ), 999, "initial handshake PTO" );
  require( !rtt.pto_ms( true, false, 25 ).has_value(), "application PTO armed before confirmation" );

  rtt.observe( 100, 90, false, 25 ); // first sample ignores ACK delay
  near( *rtt.min_ms(), 100, "first minimum RTT" );
  near( rtt.smoothed_ms(), 100, "first smoothed RTT" );
  near( rtt.rttvar_ms(), 50, "first RTT variation" );
  rtt.observe( 130, 20, false, 25 );
  near( rtt.smoothed_ms(), 101.25, "unconfirmed ACK delay adjustment" );
  // RFC 9002 verified erratum 7539: compare the sample with the previous smoothed RTT.
  near( rtt.rttvar_ms(), 40, "RTT variation uses previous smoothed RTT" );
  rtt.observe( 105, 100, true, 25 );
  near( *rtt.min_ms(), 100, "min RTT is not ACK-delay adjusted" );
  near( rtt.smoothed_ms(), 101.71875, "do not adjust below min RTT" );
  near( *rtt.pto_ms( true, true, 25 ),
        101.71875 + 4 * rtt.rttvar_ms() + 25,
        "application PTO includes maximum ACK delay" );
  rtt.observe( 140, 100, true, 25 );
  near( rtt.smoothed_ms(), 103.37890625, "confirmed ACK delay is capped at peer maximum" );

  rtt.reset( 200 );
  require( !rtt.min_ms().has_value(), "path reset retained minimum" );
  near( rtt.smoothed_ms(), 200, "path reset smoothed RTT" );
  rejected = false;
  try {
    rtt.observe( -1, 0, false, 25 );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "negative RTT accepted" );

  // RFC 9000 §12.3: Initial and Handshake each have a space; 0-RTT and 1-RTT share one.
  static_assert( !std::is_copy_constructible_v<PacketNumberSpaces> );
  static_assert( !std::is_move_constructible_v<PacketNumberSpaces> );
  PacketNumberSpaces spaces;
  require( packet_number_space( PacketKind::Initial ) == PacketNumberSpaceId::Initial, "Initial space" );
  require( packet_number_space( PacketKind::Handshake ) == PacketNumberSpaceId::Handshake, "Handshake space" );
  require( packet_number_space( PacketKind::ZeroRtt ) == PacketNumberSpaceId::Application,
           "0-RTT application space" );
  require( packet_number_space( PacketKind::OneRtt ) == PacketNumberSpaceId::Application,
           "1-RTT application space" );
  require( spaces.allocate( PacketKind::Initial ) == 0 && spaces.allocate( PacketKind::Handshake ) == 0,
           "independent first send numbers" );
  require( spaces.allocate( PacketKind::ZeroRtt ) == 0 && spaces.allocate( PacketKind::OneRtt ) == 1,
           "0-RTT and 1-RTT share send sequence" );
  require( spaces.allocate( PacketKind::Initial ) == 1, "Initial send number reused" );

  require( spaces.record_authenticated( PacketKind::Initial, 5 ), "first Initial received" );
  require( !spaces.record_authenticated( PacketKind::Initial, 5 ), "duplicate Initial received" );
  require( spaces.record_authenticated( PacketKind::Handshake, 5 ), "same number in Handshake rejected" );
  require( spaces.record_authenticated( PacketKind::ZeroRtt, 5 ), "first application number received" );
  require( !spaces.record_authenticated( PacketKind::OneRtt, 5 ), "0-RTT number replayed in 1-RTT" );
  require( spaces.record_authenticated( PacketKind::OneRtt, 3 ), "reordered application number rejected" );
  require( spaces.record_authenticated( PacketKind::OneRtt, 4 ), "gap-filling application number rejected" );
  require( !spaces.record_authenticated( PacketKind::ZeroRtt, 4 ), "merged range lost duplicate" );
  require( spaces.largest_received( PacketKind::OneRtt ) == 5, "application largest received" );
  require( spaces.largest_received( PacketKind::Initial ) == 5, "Initial largest received" );
  require( spaces.largest_received( PacketKind::Handshake ) == 5, "Handshake largest received" );

  spaces.retire_received_below( PacketKind::OneRtt, 4 );
  require( !spaces.record_authenticated( PacketKind::ZeroRtt, 3 ), "retired application number accepted" );
  require( !spaces.record_authenticated( PacketKind::OneRtt, 4 ), "retained duplicate accepted" );
  spaces.retire_received_below( PacketKind::OneRtt, 2 );
  require( !spaces.record_authenticated( PacketKind::OneRtt, 3 ), "retirement floor moved backwards" );
  require( spaces.record_authenticated( PacketKind::OneRtt, 6 ), "new application number rejected" );
  require( spaces.largest_received( PacketKind::ZeroRtt ) == 6, "shared largest received" );
  require( !spaces.record_authenticated( PacketKind::Initial, max_packet_number + 1 ),
           "62-bit receive limit ignored" );
  spaces.retire_received_below( PacketKind::Initial, 6 );
  require( !spaces.record_authenticated( PacketKind::Initial, 5 ), "Initial retirement failed" );
  require( spaces.largest_received( PacketKind::Initial ) == 5, "retirement reset decoding reference" );
  require( spaces.record_authenticated( PacketKind::Handshake, max_packet_number ),
           "largest valid received packet number rejected" );
  require( !spaces.record_authenticated( PacketKind::Handshake, max_packet_number ),
           "largest packet-number duplicate accepted" );
  rejected = false;
  try {
    spaces.retire_received_below( PacketKind::Handshake, max_packet_number + 2 );
  } catch ( const std::out_of_range& ) {
    rejected = true;
  }
  require( rejected, "retirement floor above packet-number space accepted" );
  rejected = false;
  try {
    packet_number_space( static_cast<PacketKind>( 255 ) );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "invalid packet kind mapped to a space" );
}
