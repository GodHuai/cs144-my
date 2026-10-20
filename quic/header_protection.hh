#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

// RFC 9001 section 5.4.2: sample starts four bytes after the packet-number field begins.
std::optional<std::string_view> header_protection_sample( std::string_view packet, size_t pn_offset );

// The five-byte mask comes from the negotiated AES/ChaCha header-protection algorithm.
// Return false and leave packet unchanged when the packet-number field is truncated.
bool apply_header_mask( std::string& packet, size_t pn_offset, const std::array<uint8_t, 5>& mask );
bool remove_header_mask( std::string& packet, size_t pn_offset, const std::array<uint8_t, 5>& mask );

} // namespace quic
