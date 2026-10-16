#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

// RFC 9000 section 16: QUIC variable-length integers carry at most 62 bits.
constexpr uint64_t max_varint = ( uint64_t { 1 } << 62 ) - 1;

// Return the shortest valid encoding. Values above max_varint are rejected.
std::string encode_varint( uint64_t value );

// Decode one integer at offset. Non-minimal encodings are valid in QUIC.
// On truncated input, return nullopt without advancing offset.
std::optional<uint64_t> decode_varint( std::string_view input, size_t& offset );

} // namespace quic
