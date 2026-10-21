#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace quic {

// RFC 9001 section 5.8, QUIC v1 only. retry_without_tag is the complete
// Retry packet through its token, excluding the final 16-byte integrity tag.
std::optional<std::array<uint8_t, 16>> compute_retry_integrity_tag( std::string_view original_dcid,
                                                                    std::string_view retry_without_tag );
bool verify_retry_integrity( std::string_view original_dcid, std::string_view retry_packet );

} // namespace quic
