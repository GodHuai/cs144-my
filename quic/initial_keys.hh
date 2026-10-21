#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

struct InitialPacketKeys
{
  std::array<uint8_t, 32> secret;
  std::array<uint8_t, 16> key;
  std::array<uint8_t, 12> iv;
  std::array<uint8_t, 16> hp;
};

struct InitialKeys
{
  std::array<uint8_t, 32> initial_secret;
  InitialPacketKeys client;
  InitialPacketKeys server;
};

// RFC 9001 section 5.2: dcid is the Destination Connection ID from the
// client's first Initial, or the Retry Source CID after a Retry. Both sides
// derive the same values. These are v1 Initial keys only, not TLS traffic keys.
std::optional<InitialKeys> derive_initial_keys( std::string_view dcid );

// RFC 9001 sections 5.3–5.4: AES-128-GCM protects the payload using the
// unprotected packet header as AAD; AES-ECB produces a five-byte header mask.
std::string encrypt_initial_payload( const InitialPacketKeys& keys,
                                     std::string_view unprotected_header,
                                     uint64_t packet_number,
                                     std::string_view plaintext );
std::optional<std::string> decrypt_initial_payload( const InitialPacketKeys& keys,
                                                    std::string_view unprotected_header,
                                                    uint64_t packet_number,
                                                    std::string_view ciphertext_and_tag );
std::optional<std::array<uint8_t, 5>> initial_header_mask( const std::array<uint8_t, 16>& hp_key,
                                                           std::string_view sample );

} // namespace quic
