#pragma once

#include "packet_header.hh"
#include "packet_keys.hh"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

struct OpenedProtectedPacket
{
  PacketLayout layout;
  uint64_t packet_number;
  std::string plaintext;
  bool key_phase;
  bool spin;
};

struct PacketOpenResult
{
  std::optional<OpenedProtectedPacket> packet {};
  // Only authenticated reserved-bit violations produce a transport error.
  // Damage/malformed input produces neither field. No plaintext on error.
  std::optional<uint64_t> transport_error {};
};

// Stateless QUIC v1 AES-128-GCM packet protection. Caller chooses directional,
// level-specific keys, unique full packet numbers and sufficient PADDING for
// the HP sample. No ACK/duplicate/usage-limit/key-lifetime state is maintained.
std::string seal_handshake_packet( const PacketProtectionKeys& keys,
                                   std::string_view dcid,
                                   std::string_view scid,
                                   uint64_t packet_number,
                                   uint8_t packet_number_length,
                                   std::string_view plaintext );
std::string seal_one_rtt_packet( const PacketProtectionKeys& keys,
                                 std::string_view dcid,
                                 uint64_t packet_number,
                                 uint8_t packet_number_length,
                                 std::string_view plaintext,
                                 bool key_phase = false,
                                 bool spin = false );

// PacketLayout offsets are absolute in datagram. Handshake uses its Length;
// 1-RTT consumes the remaining datagram and therefore must be last. CID length
// is connection context, never guessed. largest_received is from that level's
// PN space; caller updates it only on success. Key phase is authenticated
// metadata, not key-update validation or automatic selection of another key.
PacketOpenResult open_handshake_packet( const PacketProtectionKeys& keys,
                                        std::string_view datagram,
                                        size_t offset,
                                        std::optional<uint64_t> largest_received );
PacketOpenResult open_one_rtt_packet( const PacketProtectionKeys& keys,
                                      std::string_view datagram,
                                      size_t offset,
                                      size_t short_dcid_length,
                                      std::optional<uint64_t> largest_received );

} // namespace quic
