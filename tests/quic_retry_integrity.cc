#include "quic/retry_integrity.hh"

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

int main()
{
  const auto odcid = unhex( "8394c8f03e515708" );
  const auto packet = unhex( "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba" );
  const auto tag = compute_retry_integrity_tag( odcid, std::string_view { packet }.substr( 0, packet.size() - 16 ) );
  require( tag && std::string( reinterpret_cast<const char*>( tag->data() ), tag->size() )
                    == packet.substr( packet.size() - 16 ),
           "Retry tag differs from RFC 9001 A.4" );
  require( verify_retry_integrity( odcid, packet ), "valid RFC Retry rejected" );

  auto modified = packet;
  modified.back() ^= 1;
  require( !verify_retry_integrity( odcid, modified ), "modified tag accepted" );
  modified = packet;
  modified[17] ^= 1; // Token byte, outside the integrity tag.
  require( !verify_retry_integrity( odcid, modified ), "modified Retry token accepted" );
  require( !verify_retry_integrity( "wrongcid", packet ), "wrong original DCID accepted" );
  require( !verify_retry_integrity( std::string( 21, 'x' ), packet ), "oversized original DCID accepted" );
  require( !verify_retry_integrity( odcid, packet.substr( 0, packet.size() - 1 ) ),
           "short Retry accepted" );
  modified = packet;
  modified[4] = 2; // Version no longer QUIC v1.
  require( !verify_retry_integrity( odcid, modified ), "wrong version accepted" );

  modified = packet;
  modified[6] = 21; // SCID length exceeds the QUIC CID limit.
  require( !verify_retry_integrity( odcid, modified ), "malformed SCID length accepted" );

  modified = packet;
  modified[0] = static_cast<char>( 0xf0 ); // Retry unused low bits can vary.
  const auto varied_tag = compute_retry_integrity_tag( odcid, std::string_view { modified }.substr( 0, modified.size() - 16 ) );
  require( varied_tag.has_value(), "valid Retry with different unused bits rejected" );
  modified.replace( modified.size() - 16, 16,
                    reinterpret_cast<const char*>( varied_tag->data() ), varied_tag->size() );
  require( verify_retry_integrity( odcid, modified ), "valid Retry with different unused bits rejected" );

  const auto empty_token = unhex( "ff000000010008f067a5502a4262b5" ) + std::string( 16, '\0' );
  require( !verify_retry_integrity( odcid, empty_token ), "Retry with empty token accepted" );
}
