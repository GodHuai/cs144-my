#include "retry_integrity.hh"

#include "packet_header.hh"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace std;

namespace quic {
namespace {

constexpr array<uint8_t, 16>
  retry_key { 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
constexpr array<uint8_t, 12> retry_nonce { 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

} // namespace

optional<array<uint8_t, 16>> compute_retry_integrity_tag( const string_view original_dcid,
                                                          const string_view retry_without_tag )
{
  if ( original_dcid.size() > 20 || retry_without_tag.size() > numeric_limits<int>::max() - 37 ) {
    return nullopt;
  }
  string check_packet { retry_without_tag };
  check_packet.append( 16, '\0' );
  if ( !parse_retry_packet( check_packet ) ) {
    return nullopt;
  }

  string pseudo_packet;
  pseudo_packet.reserve( 1 + original_dcid.size() + retry_without_tag.size() );
  pseudo_packet.push_back( static_cast<char>( original_dcid.size() ) );
  pseudo_packet.append( original_dcid );
  pseudo_packet.append( retry_without_tag );

  unique_ptr<EVP_CIPHER_CTX, decltype( &EVP_CIPHER_CTX_free )> context { EVP_CIPHER_CTX_new(),
                                                                         &EVP_CIPHER_CTX_free };
  if ( !context
       || EVP_EncryptInit_ex( context.get(), EVP_aes_128_gcm(), nullptr, retry_key.data(), retry_nonce.data() )
            != 1 ) {
    throw runtime_error( "Retry AES-GCM initialization failed" );
  }
  int written = 0;
  uint8_t unused = 0;
  array<uint8_t, 16> tag {};
  if ( EVP_EncryptUpdate( context.get(),
                          nullptr,
                          &written,
                          reinterpret_cast<const unsigned char*>( pseudo_packet.data() ),
                          static_cast<int>( pseudo_packet.size() ) )
         != 1
       || EVP_EncryptFinal_ex( context.get(), &unused, &written ) != 1
       || EVP_CIPHER_CTX_ctrl( context.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data() ) != 1 ) {
    throw runtime_error( "Retry AES-GCM tag calculation failed" );
  }
  return tag;
}

bool verify_retry_integrity( const string_view original_dcid, const string_view retry_packet )
{
  if ( retry_packet.size() < 16 || !parse_retry_packet( retry_packet ) ) {
    return false;
  }
  const auto tag = compute_retry_integrity_tag( original_dcid, retry_packet.substr( 0, retry_packet.size() - 16 ) );
  return tag && CRYPTO_memcmp( tag->data(), retry_packet.data() + retry_packet.size() - 16, tag->size() ) == 0;
}

} // namespace quic
