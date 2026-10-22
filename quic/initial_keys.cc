#include "initial_keys.hh"

#include "varint.hh"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
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

constexpr array<uint8_t, 20> initial_salt { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

array<uint8_t, 32> hmac_sha256( const string_view key, const string_view data )
{
  array<uint8_t, 32> result {};
  unsigned int length = 0;
  if ( HMAC( EVP_sha256(),
             key.data(),
             static_cast<int>( key.size() ),
             reinterpret_cast<const unsigned char*>( data.data() ),
             data.size(),
             result.data(),
             &length )
         == nullptr
       || length != result.size() ) {
    throw runtime_error( "HMAC-SHA256 failed" );
  }
  return result;
}

template<size_t N>
string_view view( const array<uint8_t, N>& bytes )
{
  return { reinterpret_cast<const char*>( bytes.data() ), bytes.size() };
}

template<size_t N>
array<uint8_t, N> expand_label( const array<uint8_t, 32>& secret, const string_view label )
{
  static_assert( N <= 32 ); // HKDF-Expand needs only one SHA-256 block here.
  const string full_label = "tls13 " + string { label };
  if ( full_label.size() > 255 ) {
    throw invalid_argument( "HKDF label too long" );
  }
  string info;
  info.reserve( 2 + 1 + full_label.size() + 1 + 1 );
  info.push_back( 0 );
  info.push_back( static_cast<char>( N ) );
  info.push_back( static_cast<char>( full_label.size() ) );
  info += full_label;
  info.push_back( 0 ); // Zero-length HKDF context.
  info.push_back( 1 ); // First and only HKDF-Expand block counter.

  const auto block = hmac_sha256( view( secret ), info );
  array<uint8_t, N> output {};
  copy_n( block.begin(), N, output.begin() );
  return output;
}

InitialPacketKeys derive_direction( const array<uint8_t, 32>& initial_secret, const string_view label )
{
  const auto traffic_secret = expand_label<32>( initial_secret, label );
  return derive_packet_keys( traffic_secret );
}

} // namespace

PacketProtectionKeys derive_packet_keys( const array<uint8_t, 32>& traffic_secret )
{
  return { traffic_secret,
           expand_label<16>( traffic_secret, "quic key" ),
           expand_label<12>( traffic_secret, "quic iv" ),
           expand_label<16>( traffic_secret, "quic hp" ) };
}

optional<InitialKeys> derive_initial_keys( const string_view dcid )
{
  if ( dcid.size() > 20 ) {
    return nullopt;
  }
  const auto initial_secret = hmac_sha256( view( initial_salt ), dcid );
  return InitialKeys { initial_secret,
                       derive_direction( initial_secret, "client in" ),
                       derive_direction( initial_secret, "server in" ) };
}

namespace {

array<uint8_t, 12> packet_nonce( const InitialPacketKeys& keys, const uint64_t packet_number )
{
  if ( packet_number > max_varint ) {
    throw invalid_argument( "QUIC packet number out of range" );
  }
  auto nonce = keys.iv;
  for ( size_t i = 0; i < 8; ++i ) {
    nonce[11 - i] ^= static_cast<uint8_t>( packet_number >> ( 8 * i ) );
  }
  return nonce;
}

using CipherContext = unique_ptr<EVP_CIPHER_CTX, decltype( &EVP_CIPHER_CTX_free )>;

CipherContext make_cipher_context()
{
  CipherContext context { EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free };
  if ( !context ) {
    throw runtime_error( "OpenSSL cipher context allocation failed" );
  }
  return context;
}

void check_input_size( const string_view header, const string_view payload )
{
  if ( header.size() > numeric_limits<int>::max() || payload.size() > numeric_limits<int>::max() - 16 ) {
    throw invalid_argument( "AEAD input exceeds OpenSSL length limit" );
  }
}

} // namespace

string encrypt_packet_payload( const InitialPacketKeys& keys,
                               const string_view unprotected_header,
                               const uint64_t packet_number,
                               const string_view plaintext )
{
  check_input_size( unprotected_header, plaintext );
  const auto nonce = packet_nonce( keys, packet_number );
  auto context = make_cipher_context();
  if ( EVP_EncryptInit_ex( context.get(), EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data() ) != 1 ) {
    throw runtime_error( "AES-GCM encryption initialization failed" );
  }
  int written = 0;
  if ( EVP_EncryptUpdate( context.get(),
                          nullptr,
                          &written,
                          reinterpret_cast<const unsigned char*>( unprotected_header.data() ),
                          static_cast<int>( unprotected_header.size() ) )
       != 1 ) {
    throw runtime_error( "AES-GCM AAD failed" );
  }
  string result( plaintext.size() + 16, '\0' );
  if ( EVP_EncryptUpdate( context.get(),
                          reinterpret_cast<unsigned char*>( result.data() ),
                          &written,
                          reinterpret_cast<const unsigned char*>( plaintext.data() ),
                          static_cast<int>( plaintext.size() ) )
       != 1 ) {
    throw runtime_error( "AES-GCM encryption failed" );
  }
  int final_written = 0;
  if ( EVP_EncryptFinal_ex(
         context.get(), reinterpret_cast<unsigned char*>( result.data() + written ), &final_written )
         != 1
       || static_cast<size_t>( written + final_written ) != plaintext.size()
       || EVP_CIPHER_CTX_ctrl( context.get(), EVP_CTRL_GCM_GET_TAG, 16, result.data() + plaintext.size() ) != 1 ) {
    throw runtime_error( "AES-GCM finalization failed" );
  }
  return result;
}

optional<string> decrypt_packet_payload( const InitialPacketKeys& keys,
                                         const string_view unprotected_header,
                                         const uint64_t packet_number,
                                         const string_view ciphertext_and_tag )
{
  if ( ciphertext_and_tag.size() < 16 ) {
    return nullopt;
  }
  check_input_size( unprotected_header, ciphertext_and_tag );
  const auto nonce = packet_nonce( keys, packet_number );
  auto context = make_cipher_context();
  if ( EVP_DecryptInit_ex( context.get(), EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data() ) != 1 ) {
    throw runtime_error( "AES-GCM decryption initialization failed" );
  }
  int written = 0;
  if ( EVP_DecryptUpdate( context.get(),
                          nullptr,
                          &written,
                          reinterpret_cast<const unsigned char*>( unprotected_header.data() ),
                          static_cast<int>( unprotected_header.size() ) )
       != 1 ) {
    throw runtime_error( "AES-GCM AAD failed" );
  }
  const size_t ciphertext_length = ciphertext_and_tag.size() - 16;
  array<uint8_t, 16> tag {};
  copy_n( ciphertext_and_tag.data() + ciphertext_length, tag.size(), tag.begin() );
  string plaintext( ciphertext_length, '\0' );
  if ( EVP_DecryptUpdate( context.get(),
                          reinterpret_cast<unsigned char*>( plaintext.data() ),
                          &written,
                          reinterpret_cast<const unsigned char*>( ciphertext_and_tag.data() ),
                          static_cast<int>( ciphertext_length ) )
         != 1
       || EVP_CIPHER_CTX_ctrl( context.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data() ) != 1 ) {
    throw runtime_error( "AES-GCM decryption failed" );
  }
  int final_written = 0;
  if ( EVP_DecryptFinal_ex(
         context.get(), reinterpret_cast<unsigned char*>( plaintext.data() + written ), &final_written )
       != 1 ) {
    return nullopt;
  }
  if ( static_cast<size_t>( written + final_written ) != ciphertext_length ) {
    throw runtime_error( "AES-GCM plaintext length mismatch" );
  }
  return plaintext;
}

optional<array<uint8_t, 5>> packet_header_mask( const array<uint8_t, 16>& hp_key, const string_view sample )
{
  if ( sample.size() != 16 ) {
    return nullopt;
  }
  auto context = make_cipher_context();
  if ( EVP_EncryptInit_ex( context.get(), EVP_aes_128_ecb(), nullptr, hp_key.data(), nullptr ) != 1
       || EVP_CIPHER_CTX_set_padding( context.get(), 0 ) != 1 ) {
    throw runtime_error( "AES header protection initialization failed" );
  }
  array<uint8_t, 16> block {};
  int written = 0;
  int final_written = 0;
  if ( EVP_EncryptUpdate(
         context.get(), block.data(), &written, reinterpret_cast<const unsigned char*>( sample.data() ), 16 )
         != 1
       || EVP_EncryptFinal_ex( context.get(), block.data() + written, &final_written ) != 1
       || written + final_written != 16 ) {
    throw runtime_error( "AES header protection failed" );
  }
  array<uint8_t, 5> mask {};
  copy_n( block.begin(), mask.size(), mask.begin() );
  return mask;
}

// Preserve the original Initial API while sharing one crypto implementation.
string encrypt_initial_payload( const InitialPacketKeys& keys,
                                const string_view header,
                                const uint64_t packet_number,
                                const string_view plaintext )
{
  return encrypt_packet_payload( keys, header, packet_number, plaintext );
}

optional<string> decrypt_initial_payload( const InitialPacketKeys& keys,
                                          const string_view header,
                                          const uint64_t packet_number,
                                          const string_view ciphertext )
{
  return decrypt_packet_payload( keys, header, packet_number, ciphertext );
}

optional<array<uint8_t, 5>> initial_header_mask( const array<uint8_t, 16>& hp_key, const string_view sample )
{
  return packet_header_mask( hp_key, sample );
}

} // namespace quic
