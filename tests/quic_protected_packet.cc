#include "quic/header_protection.hh"
#include "quic/initial_packet.hh"
#include "quic/packet_keys.hh"
#include "quic/packet_number.hh"
#include "quic/protected_packet.hh"
#include "quic/tls_handshake.hh"

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace quic;

namespace {
void require( bool ok, std::string_view message )
{
  if ( !ok )
    throw std::runtime_error( std::string { message } );
}
std::string unhex( std::string_view input )
{
  std::string result;
  for ( size_t i = 0; i < input.size(); i += 2 ) {
    result += static_cast<char>( std::stoul( std::string { input.substr( i, 2 ) }, nullptr, 16 ) );
  }
  return result;
}
template<size_t N>
std::string bytes( const std::array<uint8_t, N>& value )
{
  return { reinterpret_cast<const char*>( value.data() ), value.size() };
}
PacketProtectionKeys fixture_keys()
{
  const auto raw = unhex( "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" );
  std::array<uint8_t, 32> secret {};
  std::copy( raw.begin(), raw.end(), secret.begin() );
  return derive_packet_keys( secret );
}
void empty_result( const PacketOpenResult& result, std::string_view message )
{
  require( !result.packet && !result.transport_error, message );
}

void vectors()
{
  // RFC 9001 A.1 traffic secret and derived values; the same expansion applies
  // to any TLS AES-128-GCM/SHA256 traffic secret (no Initial salt step here).
  const auto keys = fixture_keys();
  require( bytes( keys.key ) == unhex( "1f369613dd76d5467730efcbe3b1a22d" ), "QUIC key label/vector" );
  require( bytes( keys.iv ) == unhex( "fa044b2f42a3fd3b46fb255c" ), "QUIC IV label/vector" );
  require( bytes( keys.hp ) == unhex( "9f50449e04a0e810283a1e9933adedd2" ), "QUIC HP label/vector" );
  // Wire fixtures independently generated with Python cryptography 41.0.7:
  // AESGCM.encrypt(nonce=iv XOR full_pn, plaintext, header), AES-ECB HP sample.
  // Headers: e2|v1|6:server|6:client|Length=22|123456 and 66|server|123456.
  const auto handshake
    = unhex( "ec000000010673657276657206636c69656e7416369aa96f96045dec5381ed4767d4eababa48e7f11f0c" );
  const auto application = unhex( "6f736572766572b7650161960486bb3a32fe7d2880a13d75fc608b4f246bdc60444a87" );
  const auto hpayload = unhex( "010000" );
  const auto apayload = unhex( "0f000005" ) + "hello";
  require( seal_handshake_packet( keys, "server", "client", 0x123456, 3, hpayload ) == handshake,
           "Handshake wire fixture differs" );
  require( seal_one_rtt_packet( keys, "server", 0x123456, 3, apayload, true, true ) == application,
           "1-RTT wire fixture differs" );
  const auto h = open_handshake_packet( keys, handshake, 0, std::nullopt );
  const auto a = open_one_rtt_packet( keys, application, 0, 6, std::nullopt );
  require( h.packet && h.packet->plaintext == hpayload && h.packet->packet_number == 0x123456,
           "Handshake fixture open failed" );
  require( a.packet && a.packet->plaintext == apayload && a.packet->packet_number == 0x123456 && a.packet->key_phase
             && a.packet->spin,
           "1-RTT fixture open/flags failed" );
  require( h.packet->layout.kind == PacketKind::Handshake && !h.packet->key_phase && !h.packet->spin,
           "Handshake leaked short-header flags" );
  empty_result( open_handshake_packet( keys, application, 0, std::nullopt ), "short packet opened as Handshake" );
  empty_result( open_one_rtt_packet( keys, handshake, 0, 6, std::nullopt ), "long packet opened as 1-RTT" );
}

void damage_and_boundaries()
{
  const auto keys = fixture_keys();
  auto wrong_secret = keys.secret;
  wrong_secret[0] ^= 1;
  const auto wrong = derive_packet_keys( wrong_secret );
  const std::string plaintext = "authenticated payload";
  for ( const bool app : { false, true } ) {
    const auto sealed = app ? seal_one_rtt_packet( keys, "id", 256, 1, plaintext )
                            : seal_handshake_packet( keys, "id", "source", 256, 1, plaintext );
    const auto open = [&]( const std::string& wire, const PacketProtectionKeys& use ) {
      return app ? open_one_rtt_packet( use, wire, 0, 2, 255 ) : open_handshake_packet( use, wire, 0, 255 );
    };
    const auto restored = open( sealed, keys );
    require( restored.packet && restored.packet->packet_number == 256 && restored.packet->plaintext == plaintext,
             "packet number not reconstructed before AEAD" );
    require( !restored.packet->key_phase && !restored.packet->spin, "default short-header flags" );
    empty_result( open( sealed, wrong ), "wrong traffic secret accepted" );
    for ( const size_t index : { size_t { 0 }, size_t { 2 }, sealed.size() / 2, sealed.size() - 1 } ) {
      auto damaged = sealed;
      damaged[index] ^= 1;
      empty_result( open( damaged, keys ), "damaged packet exposed data/error" );
    }
    for ( size_t length = 0; length < sealed.size(); ++length ) {
      empty_result( open( sealed.substr( 0, length ), keys ), "truncated packet accepted" );
    }
    const auto bad_largest = app ? open_one_rtt_packet( keys, sealed, 0, 2, max_packet_number )
                                 : open_handshake_packet( keys, sealed, 0, max_packet_number );
    empty_result( bad_largest, "out-of-range reconstruction context accepted" );

    // Authenticated illegal reserved bits must be distinguishable from damage.
    auto header
      = app ? build_short_header( "id", 10, 2, false, false, plaintext.size() + 16 )
            : build_long_header( LongPacketType::Handshake, "id", "source", "", 10, 2, plaintext.size() + 16 );
    header[0] = static_cast<char>( static_cast<uint8_t>( header[0] ) | ( app ? 0x08 : 0x04 ) );
    const auto pn_offset = header.size() - 2;
    auto illegal = header + encrypt_packet_payload( keys, header, 10, plaintext );
    const auto sample = header_protection_sample( illegal, pn_offset );
    require( sample.has_value(), "illegal-bit fixture sample" );
    const auto mask = packet_header_mask( keys.hp, *sample );
    require( mask && apply_header_mask( illegal, pn_offset, *mask ), "illegal-bit fixture protect" );
    const auto result = app ? open_one_rtt_packet( keys, illegal, 0, 2, std::nullopt )
                            : open_handshake_packet( keys, illegal, 0, std::nullopt );
    require( !result.packet && result.transport_error == 0x0a, "authenticated reserved bit not protocol error" );
    illegal.back() ^= 1;
    empty_result( open( illegal, keys ), "unauthenticated reserved bits exposed protocol error" );
  }
  for ( uint8_t width = 1; width <= 4; ++width ) {
    const std::string minimum( 4 - width, '\0' );
    const auto h = seal_handshake_packet( keys, "", "", 7, width, minimum );
    const auto a = seal_one_rtt_packet( keys, "", 7, width, minimum );
    require( open_handshake_packet( keys, h, 0, std::nullopt ).packet.has_value(), "minimum Handshake sample" );
    require( open_one_rtt_packet( keys, a, 0, 0, std::nullopt ).packet.has_value(), "minimum short sample" );
    if ( !minimum.empty() ) {
      bool h_rejected = false, a_rejected = false;
      try {
        seal_handshake_packet( keys, "", "", 7, width, minimum.substr( 1 ) );
      } catch ( const std::invalid_argument& ) {
        h_rejected = true;
      }
      try {
        seal_one_rtt_packet( keys, "", 7, width, minimum.substr( 1 ) );
      } catch ( const std::invalid_argument& ) {
        a_rejected = true;
      }
      require( h_rejected && a_rejected, "short HP sample sealed" );
    }
  }
  const auto maximum = seal_one_rtt_packet( keys, "id", max_packet_number, 4, plaintext );
  const auto opened = open_one_rtt_packet( keys, maximum, 0, 2, max_packet_number - 1 );
  require( opened.packet && opened.packet->packet_number == max_packet_number, "maximum PN did not authenticate" );
  for ( const auto bad_width : { uint8_t { 0 }, uint8_t { 5 } } ) {
    bool rejected = false;
    try {
      seal_one_rtt_packet( keys, "id", 1, bad_width, plaintext );
    } catch ( const std::invalid_argument& ) {
      rejected = true;
    }
    require( rejected, "invalid PN width accepted" );
  }
  bool rejected = false;
  try {
    seal_handshake_packet( keys, "", "", max_packet_number + 1, 4, plaintext );
  } catch ( const std::out_of_range& ) {
    rejected = true;
  }
  require( rejected, "out-of-range full PN sealed" );
  rejected = false;
  try {
    seal_one_rtt_packet( keys, std::string( 21, 'x' ), 1, 2, plaintext );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "oversized CID sealed" );
}

void coalescing()
{
  const auto keys = fixture_keys();
  const auto h = seal_handshake_packet( keys, "id", "src", 3, 2, "hello" );
  const auto a = seal_one_rtt_packet( keys, "id", 4, 2, "application" );
  const auto joined = std::string { "prefix" } + h + h + a;
  const auto second_offset = size_t { 6 } + h.size();
  const auto second = open_handshake_packet( keys, joined, second_offset, 2 );
  require( second.packet && second.packet->layout.packet_end == second_offset + h.size()
             && second.packet->layout.pn_offset >= second_offset && second.packet->plaintext == "hello",
           "coalesced Handshake absolute boundaries" );
  const auto app = open_one_rtt_packet( keys, joined, second_offset + h.size(), 2, 3 );
  require( app.packet && app.packet->layout.packet_end == joined.size() && app.packet->plaintext == "application",
           "coalesced trailing short packet" );
  empty_result( open_one_rtt_packet( keys, a + h, 0, 2, 3 ), "short header did not consume remainder" );
  empty_result( open_handshake_packet( keys, joined, joined.size(), std::nullopt ), "invalid offset accepted" );
  empty_result( open_one_rtt_packet( keys, a, 0, 21, std::nullopt ), "invalid short CID length accepted" );
  auto too_short = seal_handshake_packet( keys, "", "", 1, 4, "" );
  const auto layout = parse_protected_packet( too_short, 0, 0 );
  require( layout.has_value(), "short fixture layout" );
  too_short[layout->pn_offset - 1] = 19; // Length is below minimum HP sample.
  empty_result( open_handshake_packet( keys, too_short + h, 0, std::nullopt ), "sample borrowed from next packet" );
}

TlsConfig config( bool server )
{
  TlsConfig result;
  result.server = server;
  result.alpn = "minnow-quic";
  result.server_name = "localhost";
  result.ca_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.pem";
  result.certificate_file = result.ca_file;
  result.private_key_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.key";
  result.local_parameters = { { 0x0f, server ? "server" : "client" } };
  result.peer_initial_source_connection_id = server ? "client" : "server";
  if ( server )
    result.local_parameters.emplace( 0x00, "original" );
  else
    result.original_destination_connection_id = "original";
  return result;
}
struct Endpoint
{
  TlsHandshake tls;
  std::array<uint64_t, 2> offsets {};
  std::array<uint64_t, 2> next_pn {};
  std::array<std::optional<uint64_t>, 2> largest {};
  explicit Endpoint( bool server ) : tls( config( server ) ) {}
};
void transmit( Endpoint& from, Endpoint& to, bool server, const InitialKeys& initial )
{
  const std::array levels { PacketKind::Initial, PacketKind::Handshake };
  for ( size_t level = 0; level < levels.size(); ++level ) {
    std::vector<CryptoFrame> fragments;
    while ( const auto frame = from.tls.outgoing( levels[level], from.offsets[level], 61 ) ) {
      from.offsets[level] += frame->data.size();
      fragments.push_back( *frame );
    }
    for ( auto it = fragments.rbegin(); it != fragments.rend(); ++it ) {
      auto plaintext = encode_frame( *it );
      const auto pn = from.next_pn[level]++;
      std::string wire;
      const auto& initial_key = server ? initial.server : initial.client;
      if ( level == 0 ) {
        plaintext.resize( 1200, '\0' ); // Initial datagram lower bound, caller-owned padding.
        wire = seal_initial_packet( initial_key,
                                    server ? InitialSender::Server : InitialSender::Client,
                                    server ? "client" : "original",
                                    server ? "server" : "client",
                                    "",
                                    pn,
                                    2,
                                    plaintext );
      } else {
        const auto secret = from.tls.secret( PacketKind::Handshake, true );
        require( secret.has_value(), "missing Handshake write secret" );
        wire = seal_handshake_packet( derive_packet_keys( *secret ),
                                      server ? "client" : "server",
                                      server ? "server" : "client",
                                      pn,
                                      2,
                                      plaintext );
      }
      std::string received;
      if ( level == 0 ) {
        const auto result = open_initial_packet(
          initial_key, server ? InitialSender::Server : InitialSender::Client, wire, 0, to.largest[level] );
        require( result.has_value(), "protected Initial failed in TLS bridge" );
        to.largest[level] = result->packet_number;
        received = result->plaintext;
      } else {
        const auto secret = to.tls.secret( PacketKind::Handshake, false );
        require( secret.has_value(), "missing Handshake read secret" );
        const auto receive_keys = derive_packet_keys( *secret );
        const auto opposite = to.tls.secret( PacketKind::Handshake, true );
        require( opposite.has_value(), "missing opposite-direction Handshake secret" );
        empty_result( open_handshake_packet( derive_packet_keys( *opposite ), wire, 0, to.largest[level] ),
                      "opposite TLS direction opened Handshake packet" );
        auto damaged = wire;
        damaged.back() ^= 1;
        empty_result( open_handshake_packet( receive_keys, damaged, 0, to.largest[level] ),
                      "damaged Handshake reached TLS" );
        const auto result = open_handshake_packet( receive_keys, wire, 0, to.largest[level] );
        require( result.packet.has_value(), "TLS Handshake packet did not authenticate" );
        to.largest[level] = result.packet->packet_number;
        received = result.packet->plaintext;
      }
      const auto frames = decode_frames( received );
      require( frames.has_value(), "authenticated TLS CRYPTO frame decode failed" );
      for ( const auto& frame : *frames ) {
        if ( const auto* crypto = std::get_if<CryptoFrame>( &frame ) ) {
          require( to.tls.receive( levels[level], *crypto ), "authenticated CRYPTO rejected" );
          require( to.tls.receive( levels[level], *crypto ), "CRYPTO replay rejected" );
        }
      }
      require( to.tls.advance() != TlsProgress::Failed, "protected-packet TLS handshake failed" );
    }
  }
}
void protected_tls()
{
  Endpoint client { false }, server { true };
  const auto initial = derive_initial_keys( "original" );
  require( initial.has_value(), "Initial derivation" );
  for ( size_t round = 0; round < 50 && !( client.tls.complete() && server.tls.complete() ); ++round ) {
    require( client.tls.advance() != TlsProgress::Failed, "client TLS failed" );
    transmit( client, server, false, *initial );
    transmit( server, client, true, *initial );
  }
  require( client.tls.complete() && server.tls.complete(), "protected TLS handshake stalled" );
  for ( const bool server_sends : { false, true } ) {
    auto& sender = server_sends ? server : client;
    auto& receiver = server_sends ? client : server;
    const auto write = sender.tls.secret( PacketKind::OneRtt, true );
    const auto read = receiver.tls.secret( PacketKind::OneRtt, false );
    require( write && read, "application traffic secrets missing" );
    const StreamFrame stream { 0, 0, server_sends ? "response" : "request", true, true, true };
    const auto payload = encode_frame( stream );
    const auto wire
      = seal_one_rtt_packet( derive_packet_keys( *write ), server_sends ? "client" : "server", 0, 2, payload );
    require( wire.find( stream.data ) == std::string::npos, "application payload exposed on wire" );
    const auto result = open_one_rtt_packet( derive_packet_keys( *read ), wire, 0, 6, std::nullopt );
    require( result.packet.has_value(), "TLS-derived 1-RTT packet rejected" );
    const auto frames = decode_frames( result.packet->plaintext );
    require( frames && frames->size() == 1, "1-RTT STREAM decode failed" );
    const auto* decoded = std::get_if<StreamFrame>( &frames->front() );
    require( decoded && decoded->data == stream.data && decoded->fin, "1-RTT STREAM payload changed" );
    const auto other_level = sender.tls.secret( PacketKind::Handshake, true );
    require( other_level.has_value(), "test Handshake secret missing" );
    const auto opposite = receiver.tls.secret( PacketKind::OneRtt, true );
    require( opposite.has_value(), "missing opposite-direction application secret" );
    empty_result( open_one_rtt_packet( derive_packet_keys( *opposite ), wire, 0, 6, std::nullopt ),
                  "opposite TLS direction opened application packet" );
    empty_result( open_one_rtt_packet( derive_packet_keys( *other_level ), wire, 0, 6, std::nullopt ),
                  "Handshake secret opened application packet" );
  }
}
} // namespace
int main()
{
  try {
    vectors();
    damage_and_boundaries();
    coalescing();
    protected_tls();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
