#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

// RFC 9000 section 18: raw parameter values remain available to TLS and
// future extensions. Unknown IDs are intentionally preserved.
using TransportParameters = std::map<uint64_t, std::string>;

struct TransportParameterContext
{
  bool peer_is_server;
  std::string_view initial_source_connection_id;
  std::optional<std::string_view> original_destination_connection_id;
  std::optional<std::string_view> retry_source_connection_id;
};

// Decode the TLS extension_data, rejecting duplicate IDs and malformed known
// values. Handshake-dependent checks require validate_transport_parameters.
std::optional<TransportParameters> decode_transport_parameters( std::string_view input );

// Encode unique parameters in ID order. Invalid known values are rejected.
std::string encode_transport_parameters( const TransportParameters& parameters );

// Apply RFC 9000 section 7.3 role and connection-ID authentication rules.
// The caller supplies IDs from actual Initial and Retry packet headers.
bool validate_transport_parameters( const TransportParameters& parameters,
                                    const TransportParameterContext& context );

// Read an integer parameter with its RFC default. Unknown/noninteger IDs
// yield nullopt; supplied values must already have passed decoding/validation.
std::optional<uint64_t> transport_parameter_integer( const TransportParameters& parameters, uint64_t id );

} // namespace quic
