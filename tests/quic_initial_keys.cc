#include "quic/header_protection.hh"
#include "quic/initial_keys.hh"

#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( const bool condition, const std::string_view message )
{
  if ( !condition ) {
    throw std::runtime_error( std::string { message } );
  }
}

std::string unhex( const std::string_view hex )
{
  std::string result;
  for ( size_t i = 0; i < hex.size(); i += 2 ) {
    result.push_back( static_cast<char>( std::stoul( std::string { hex.substr( i, 2 ) }, nullptr, 16 ) ) );
  }
  return result;
}

template<size_t N>
std::string bytes( const std::array<uint8_t, N>& value )
{
  return { reinterpret_cast<const char*>( value.data() ), value.size() };
}

int main()
{
  const auto keys = derive_initial_keys( unhex( "8394c8f03e515708" ) );
  require( keys.has_value(), "RFC DCID rejected" );
  require( bytes( keys->initial_secret )
             == unhex( "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44" ),
           "initial secret differs from RFC 9001 A.1" );
  require( bytes( keys->client.secret )
             == unhex( "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" ),
           "client secret differs from RFC 9001 A.1" );
  require( bytes( keys->client.key ) == unhex( "1f369613dd76d5467730efcbe3b1a22d" ),
           "client AEAD key differs from RFC 9001 A.1" );
  require( bytes( keys->client.iv ) == unhex( "fa044b2f42a3fd3b46fb255c" ), "client IV differs from RFC 9001 A.1" );
  require( bytes( keys->client.hp ) == unhex( "9f50449e04a0e810283a1e9933adedd2" ),
           "client HP key differs from RFC 9001 A.1" );
  require( bytes( keys->server.secret )
             == unhex( "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" ),
           "server secret differs from RFC 9001 A.1" );
  require( bytes( keys->server.key ) == unhex( "cf3a5331653c364c88f0f379b6067e37" ),
           "server AEAD key differs from RFC 9001 A.1" );
  require( bytes( keys->server.iv ) == unhex( "0ac1493ca1905853b0bba03e" ), "server IV differs from RFC 9001 A.1" );
  require( bytes( keys->server.hp ) == unhex( "c206b8d9b9f0f37644430b490eeaa314" ),
           "server HP key differs from RFC 9001 A.1" );

  require( derive_initial_keys( "" ).has_value(), "zero-length Retry DCID rejected" );
  require( !derive_initial_keys( std::string( 21, 'x' ) ), "DCID longer than 20 bytes accepted" );
  require( derive_initial_keys( "new-cid" )->initial_secret != keys->initial_secret,
           "Retry DCID did not change Initial keys" );

  const auto sample = unhex( "d1b1c98dd7689fb8ec11d242b123dc9b" );
  const auto mask = initial_header_mask( keys->client.hp, sample );
  require( mask && bytes( *mask ) == unhex( "437b9aec36" ), "AES header mask differs from RFC 9001 A.2" );
  require( !initial_header_mask( keys->client.hp, "short" ), "short header sample accepted" );

  const auto header = unhex( "c300000001088394c8f03e5157080000449e00000002" );
  std::string payload = unhex( "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
                               "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
                               "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
                               "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
                               "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
                               "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
                               "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
                               "75300901100f088394c8f03e51570806048000ffff" );
  require( payload.size() < 1162, "RFC sample payload too long" );
  payload.resize( 1162, '\0' );
  const auto ciphertext = encrypt_initial_payload( keys->client, header, 2, payload );
  require( ciphertext.size() == payload.size() + 16, "AEAD tag length wrong" );
  require( ciphertext.substr( 0, 16 ) == sample, "AEAD ciphertext differs from RFC 9001 A.2" );
  require( ciphertext.substr( ciphertext.size() - 16 ) == unhex( "e221af44860018ab0856972e194cd934" ),
           "AEAD tag differs from RFC 9001 A.2" );
  auto protected_packet = header + ciphertext;
  require( header_protection_sample( protected_packet, 18 ) == sample, "packet sample offset wrong" );
  require( apply_header_mask( protected_packet, 18, *mask ), "header mask application failed" );
  require( protected_packet.substr( 0, header.size() ) == unhex( "c000000001088394c8f03e5157080000449e7b9aec34" ),
           "protected Initial header differs from RFC 9001 A.2" );
  require( remove_header_mask( protected_packet, 18, *mask ), "header mask removal failed" );
  require( protected_packet.substr( 0, header.size() ) == header, "Initial header did not round trip" );
  require( decrypt_initial_payload( keys->client, header, 2, ciphertext ) == payload, "AEAD decryption failed" );
  auto corrupted = ciphertext;
  corrupted.back() ^= 1;
  require( !decrypt_initial_payload( keys->client, header, 2, corrupted ), "tampered tag accepted" );
  require( !decrypt_initial_payload( keys->client, header, 3, ciphertext ), "wrong packet number accepted" );
  require( !decrypt_initial_payload( keys->client, "wrong header", 2, ciphertext ), "wrong AAD accepted" );
  require( !decrypt_initial_payload( keys->client, header, 2, "short" ), "short ciphertext accepted" );

  const auto server_header = unhex( "c1000000010008f067a5502a4262b50040750001" );
  const auto server_payload = unhex( "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
                                     "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
                                     "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
                                     "020304" );
  auto server_packet = server_header + encrypt_initial_payload( keys->server, server_header, 1, server_payload );
  const auto server_sample = header_protection_sample( server_packet, 18 );
  require( server_sample && *server_sample == unhex( "2cd0991cd25b0aac406a5816b6394100" ),
           "server sample differs from RFC 9001 A.3" );
  const auto server_mask = initial_header_mask( keys->server.hp, *server_sample );
  require( server_mask && bytes( *server_mask ) == unhex( "2ec0d8356a" ), "server mask differs from RFC 9001 A.3" );
  require( apply_header_mask( server_packet, 18, *server_mask ), "server header protection failed" );
  require( server_packet
             == unhex( "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
                       "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
                       "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
                       "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
                       "2158407dd074ee" ),
           "server packet differs from RFC 9001 A.3" );
}
