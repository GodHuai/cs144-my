#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

// Version Negotiation has version 0 and consumes the entire UDP datagram.
// Its connection IDs use 8-bit lengths, independent of QUIC v1's 20-byte limit.
struct VersionNegotiationPacket
{
  std::string dcid;
  std::string scid;
  std::vector<uint32_t> supported_versions;
};

std::optional<VersionNegotiationPacket> parse_version_negotiation( std::string_view datagram );
std::string build_version_negotiation( std::string_view dcid,
                                       std::string_view scid,
                                       const std::vector<uint32_t>& supported_versions,
                                       uint8_t unused_bits = 0x40 );

// Only parses Retry fields. The integrity tag must be verified using RFC 9001
// Section 5.8 and the original destination CID before a client processes it.
struct RetryPacket
{
  std::string dcid;
  std::string scid;
  std::string token;
  std::string integrity_tag;
};

std::optional<RetryPacket> parse_retry_packet( std::string_view datagram );

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
