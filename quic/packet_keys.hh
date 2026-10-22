#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

// QUIC v1 TLS_AES_128_GCM_SHA256 keys for one direction at one level/generation.
// Plain value copies are sensitive: callers own their lifetime and cleansing.
struct PacketProtectionKeys
{
  std::array<uint8_t, 32> secret;
  std::array<uint8_t, 16> key;
  std::array<uint8_t, 12> iv;
  std::array<uint8_t, 16> hp;
};

// RFC 9001 section 5.1: expand an already derived TLS traffic secret with
// "quic key", "quic iv", "quic hp". Does not perform Initial HKDF-Extract.
PacketProtectionKeys derive_packet_keys( const std::array<uint8_t, 32>& traffic_secret );

// Stateless AES-128-GCM and AES-ECB HP primitives. The complete unprotected
// header (including truncated PN) is AAD; nonce uses the full reconstructed PN.
std::string encrypt_packet_payload( const PacketProtectionKeys& keys,
                                    std::string_view unprotected_header,
                                    uint64_t packet_number,
                                    std::string_view plaintext );
std::optional<std::string> decrypt_packet_payload( const PacketProtectionKeys& keys,
                                                   std::string_view unprotected_header,
                                                   uint64_t packet_number,
                                                   std::string_view ciphertext_and_tag );
std::optional<std::array<uint8_t, 5>> packet_header_mask( const std::array<uint8_t, 16>& hp_key,
                                                          std::string_view sample );

} // namespace quic
