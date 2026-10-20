#pragma once

#include "varint.hh"

#include <cstdint>
#include <optional>
#include <string>

namespace quic {

constexpr uint64_t max_packet_number = max_varint;

// RFC 9000 section 17.1. The caller owns monotonic packet-number allocation.
uint8_t choose_packet_number_length( uint64_t packet_number, std::optional<uint64_t> largest_acked );
std::string encode_packet_number( uint64_t packet_number, uint8_t length );
uint64_t decode_packet_number( uint64_t truncated, uint8_t length, std::optional<uint64_t> largest_received );

} // namespace quic
