#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

enum class LongPacketType : uint8_t
{
  Initial = 0,
  ZeroRtt = 1,
  Handshake = 2
};
enum class PacketKind : uint8_t
{
  Initial,
  ZeroRtt,
  Handshake,
  OneRtt
};

struct PacketLayout
{
  PacketKind kind;
  uint32_t version;
  std::string dcid;
  std::string scid;
  std::string token;
  size_t pn_offset;
  size_t packet_end;
};

// Parse only fields not obscured by QUIC header protection. The packet-number
// length and reserved bits are intentionally not checked here.
std::optional<PacketLayout> parse_protected_packet( std::string_view datagram,
                                                    size_t offset,
                                                    size_t short_dcid_length );

// Return the unprotected header through the packet-number field. The caller
// supplies ciphertext+AEAD-tag length and later applies packet protection.
std::string build_long_header( LongPacketType type,
                               std::string_view dcid,
                               std::string_view scid,
                               std::string_view token,
                               uint64_t packet_number,
                               uint8_t pn_length,
                               size_t protected_payload_length );
std::string build_short_header( std::string_view dcid,
                                uint64_t packet_number,
                                uint8_t pn_length,
                                bool spin,
                                bool key_phase,
                                size_t protected_payload_length );

} // namespace quic
