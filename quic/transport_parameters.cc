#include "transport_parameters.hh"

#include "varint.hh"

#include <stdexcept>

using namespace std;

namespace quic {
namespace {

bool is_integer_parameter( const uint64_t id )
{
  return id == 0x01 || ( id >= 0x03 && id <= 0x0b ) || id == 0x0e;
}

optional<uint64_t> exact_integer( const string_view value )
{
  size_t offset = 0;
  const auto integer = decode_varint( value, offset );
  if ( !integer || offset != value.size() ) {
    return nullopt;
  }
  return integer;
}

bool valid_value( const uint64_t id, const string_view value )
{
  if ( is_integer_parameter( id ) ) {
    const auto integer = exact_integer( value );
    if ( !integer ) {
      return false;
    }
    switch ( id ) {
      case 0x03:
        return *integer >= 1200;
      case 0x08:
      case 0x09:
        return *integer <= ( uint64_t { 1 } << 60 );
      case 0x0a:
        return *integer <= 20;
      case 0x0b:
        return *integer < ( uint64_t { 1 } << 14 );
      case 0x0e:
        return *integer >= 2;
      default:
        return true;
    }
  }

  switch ( id ) {
    case 0x00:
    case 0x0f:
    case 0x10:
      return value.size() <= 20;
    case 0x02:
      return value.size() == 16;
    case 0x0c:
      return value.empty();
    case 0x0d: {
      // 4+2 bytes IPv4, 16+2 bytes IPv6, one CID length, CID, token.
      if ( value.size() < 42 ) {
        return false;
      }
      const auto cid_length = static_cast<uint8_t>( value[24] );
      return cid_length >= 1 && cid_length <= 20 && value.size() == size_t { 41 } + cid_length;
    }
    default:
      return true; // Unknown or greased parameters have no local semantics.
  }
}

bool valid_values( const TransportParameters& parameters )
{
  for ( const auto& [id, value] : parameters ) {
    if ( id > max_varint || !valid_value( id, value ) ) {
      return false;
    }
  }
  return true;
}

bool matches( const TransportParameters& parameters, const uint64_t id, const string_view expected )
{
  const auto it = parameters.find( id );
  return it != parameters.end() && it->second == expected;
}

} // namespace

optional<TransportParameters> decode_transport_parameters( const string_view input )
{
  TransportParameters result;
  size_t offset = 0;
  while ( offset < input.size() ) {
    const auto id = decode_varint( input, offset );
    const auto length = decode_varint( input, offset );
    if ( !id || !length || *length > input.size() - offset ) {
      return nullopt;
    }
    const string_view value = input.substr( offset, *length );
    if ( !valid_value( *id, value ) || !result.emplace( *id, value ).second ) {
      return nullopt;
    }
    offset += *length;
  }
  return result;
}

string encode_transport_parameters( const TransportParameters& parameters )
{
  if ( !valid_values( parameters ) ) {
    throw invalid_argument( "invalid QUIC transport parameter" );
  }
  string result;
  for ( const auto& [id, value] : parameters ) {
    result += encode_varint( id );
    result += encode_varint( value.size() );
    result += value;
  }
  return result;
}

bool validate_transport_parameters( const TransportParameters& parameters,
                                    const TransportParameterContext& context )
{
  if ( !valid_values( parameters ) || !matches( parameters, 0x0f, context.initial_source_connection_id ) ) {
    return false;
  }
  if ( !context.peer_is_server ) {
    return !parameters.contains( 0x00 ) && !parameters.contains( 0x02 ) && !parameters.contains( 0x0d )
           && !parameters.contains( 0x10 );
  }
  if ( !context.original_destination_connection_id
       || !matches( parameters, 0x00, *context.original_destination_connection_id ) ) {
    return false;
  }
  if ( context.initial_source_connection_id.empty() && parameters.contains( 0x0d ) ) {
    return false;
  }
  if ( context.retry_source_connection_id ) {
    return matches( parameters, 0x10, *context.retry_source_connection_id );
  }
  return !parameters.contains( 0x10 );
}

optional<uint64_t> transport_parameter_integer( const TransportParameters& parameters, const uint64_t id )
{
  if ( !is_integer_parameter( id ) ) {
    return nullopt;
  }
  const auto it = parameters.find( id );
  if ( it != parameters.end() ) {
    return exact_integer( it->second );
  }
  switch ( id ) {
    case 0x03:
      return 65527;
    case 0x0a:
      return 3;
    case 0x0b:
      return 25;
    case 0x0e:
      return 2;
    default:
      return 0;
  }
}

} // namespace quic
