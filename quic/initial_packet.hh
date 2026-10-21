#pragma once

#include "initial_keys.hh"
#include "packet_header.hh"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

enum class InitialSender : uint8_t
{
  Client,
  Server
};

struct OpenedInitialPacket
{
  PacketLayout layout;
  uint64_t packet_number;
  std::string plaintext;
};

// Builds one QUIC v1 Initial packet. The caller chooses the correct directional
// Initial keys and provides PADDING frames required by the minimum datagram size.
std::string seal_initial_packet( const InitialPacketKeys& keys,
                                 InitialSender sender,
                                 std::string_view dcid,
                                 std::string_view scid,
                                 std::string_view token,
                                 uint64_t packet_number,
                                 uint8_t packet_number_length,
                                 std::string_view plaintext );

// Opens a single Initial packet at offset in a possibly coalesced datagram.
// Returns no packet on malformed input or authentication failure. largest_received
// comes from the Initial packet-number space; update it only after success.
std::optional<OpenedInitialPacket> open_initial_packet( const InitialPacketKeys& keys,
                                                        InitialSender sender,
                                                        std::string_view datagram,
                                                        size_t offset,
                                                        std::optional<uint64_t> largest_received );

} // namespace quic
