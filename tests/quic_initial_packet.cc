#include "quic/initial_packet.hh"
#include "quic/header_protection.hh"
#include "quic/packet_number.hh"

#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( const bool ok, std::string_view message )
{
  if ( !ok ) { throw std::runtime_error( std::string { message } ); }
}

std::string unhex( std::string_view hex )
{
  std::string bytes;
  for ( size_t i = 0; i < hex.size(); i += 2 ) {
    bytes += static_cast<char>( std::stoul( std::string { hex.substr( i, 2 ) }, nullptr, 16 ) );
  }
  return bytes;
}

int main()
{
  const auto keys = derive_initial_keys( unhex( "8394c8f03e515708" ) );
  require( keys.has_value(), "RFC Initial key derivation failed" );
  const auto payload = unhex( "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
                              "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
                              "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
                              "020304" );
  const auto packet = seal_initial_packet( keys->server, InitialSender::Server, "", unhex( "f067a5502a4262b5" ), "", 1, 2, payload );
  require( packet == unhex( "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
                            "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
                            "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
                            "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
                            "2158407dd074ee" ), "complete server Initial differs from RFC 9001 A.3" );
  const auto opened = open_initial_packet( keys->server, InitialSender::Server, packet, 0, std::nullopt );
  require( opened && opened->packet_number == 1 && opened->plaintext == payload,
           "RFC server Initial did not authenticate and decrypt" );
  require( opened->layout.packet_end == packet.size() && opened->layout.scid == unhex( "f067a5502a4262b5" ),
           "opened Initial layout incorrect" );

  auto corrupted = packet;
  corrupted.back() ^= 1;
  require( !open_initial_packet( keys->server, InitialSender::Server, corrupted, 0, std::nullopt ), "modified tag accepted" );
  corrupted = packet;
  corrupted[5] ^= 1; // Public DCID length changes the parsed authenticated header.
  require( !open_initial_packet( keys->server, InitialSender::Server, corrupted, 0, std::nullopt ), "modified header accepted" );
  require( !open_initial_packet( keys->client, InitialSender::Server, packet, 0, std::nullopt ), "wrong direction keys accepted" );
  require( !open_initial_packet( keys->server, InitialSender::Server, packet.substr( 0, 30 ), 0, std::nullopt ),
           "truncated packet accepted" );

  const auto coalesced = packet + packet;
  const auto second = open_initial_packet( keys->server, InitialSender::Server, coalesced, packet.size(), std::nullopt );
  require( second && second->packet_number == 1 && second->layout.packet_end == coalesced.size(),
           "Initial at a nonzero datagram offset failed" );
  require( !open_initial_packet( keys->server, InitialSender::Server, coalesced, coalesced.size(), std::nullopt ),
           "out-of-range offset accepted" );

  const auto wrapped = seal_initial_packet( keys->server, InitialSender::Server, "", "id", "", 256, 1, payload );
  const auto unwrapped = open_initial_packet( keys->server, InitialSender::Server, wrapped, 0, 255 );
  require( unwrapped && unwrapped->packet_number == 256 && unwrapped->plaintext == payload,
           "truncated packet number was not reconstructed before AEAD" );

  // Make a packet whose reserved bit is set but whose AEAD tag is valid. A
  // receiver must reject it after authentication, not mistake it for damage.
  auto bad_header = build_long_header( LongPacketType::Initial, "", "id", "", 3, 1, payload.size() + 16 );
  bad_header[0] = static_cast<char>( static_cast<uint8_t>( bad_header[0] ) | 0x04 );
  const auto pn_offset = bad_header.size() - 1;
  auto bad_reserved = bad_header + encrypt_initial_payload( keys->server, bad_header, 3, payload );
  const auto sample = header_protection_sample( bad_reserved, pn_offset );
  require( sample.has_value(), "reserved-bit packet missing header sample" );
  const auto mask = initial_header_mask( keys->server.hp, *sample );
  require( mask && apply_header_mask( bad_reserved, pn_offset, *mask ), "could not protect reserved-bit packet" );
  require( !open_initial_packet( keys->server, InitialSender::Server, bad_reserved, 0, std::nullopt ),
           "authenticated nonzero reserved bit accepted" );

  const auto client_with_token = seal_initial_packet( keys->client, InitialSender::Client,
                                                        "id", "other", "token", 5, 1, payload );
  const auto client_opened = open_initial_packet( keys->client, InitialSender::Client,
                                                   client_with_token, 0, std::nullopt );
  require( client_opened && client_opened->layout.token == "token", "client Initial token rejected" );
  require( !open_initial_packet( keys->client, InitialSender::Server,
                                 client_with_token, 0, std::nullopt ), "server Initial token accepted" );
  bool rejected_server_token = false;
  try {
    seal_initial_packet( keys->server, InitialSender::Server, "id", "other", "token", 5, 1, payload );
  } catch ( const std::invalid_argument& ) {
    rejected_server_token = true;
  }
  require( rejected_server_token, "server Initial with token was sealed" );

  const auto far_packet = seal_initial_packet( keys->server, InitialSender::Server,
                                                "", "id", "", 0, 4, payload );
  require( !open_initial_packet( keys->server, InitialSender::Server,
                                 far_packet, 0, max_packet_number - 2 ),
           "unrepresentable restored packet number was accepted or threw" );
}
