#include "quic/transport_parameters.hh"

#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( bool value, std::string_view message )
{
  if ( !value ) {
    throw std::runtime_error( std::string { message } );
  }
}

std::string bytes( std::initializer_list<unsigned int> values )
{
  std::string result;
  for ( const auto value : values ) {
    result.push_back( static_cast<char>( value ) );
  }
  return result;
}

int main()
{
  // ID 0x0f, one-byte value C1; max_udp_payload_size=1200 (0x44b0).
  const auto client_wire = bytes( { 0x03, 0x02, 0x44, 0xb0, 0x0f, 0x01, 0xc1 } );
  const auto client = decode_transport_parameters( client_wire );
  require( client.has_value(), "valid client parameters rejected" );
  require( client->at( 0x0f ) == bytes( { 0xc1 } ), "source CID was changed" );
  require( transport_parameter_integer( *client, 0x03 ) == 1200, "numeric parameter decoded incorrectly" );
  require( transport_parameter_integer( *client, 0x0a ) == 3, "missing ACK exponent default incorrect" );
  require( transport_parameter_integer( *client, 0x0b ) == 25, "missing max ACK delay default incorrect" );
  require( transport_parameter_integer( *client, 0x0e ) == 2, "missing active CID limit default incorrect" );
  require( transport_parameter_integer( *client, 0x03 ) == 1200, "explicit UDP payload limit lost" );
  require( validate_transport_parameters( *client, { false, bytes( { 0xc1 } ), {}, {} } ),
           "matching client handshake CID rejected" );
  require( !validate_transport_parameters( *client, { false, bytes( { 0xc2 } ), {}, {} } ),
           "mismatched client handshake CID accepted" );
  require( !validate_transport_parameters( {}, { false, {}, {}, {} } ), "missing initial source CID accepted" );
  require( encode_transport_parameters( *client ) == client_wire, "canonical parameter encoding incorrect" );

  const auto nonminimal = decode_transport_parameters( bytes( { 0x0a, 0x02, 0x40, 0x03 } ) );
  require( nonminimal && transport_parameter_integer( *nonminimal, 0x0a ) == 3,
           "nonminimal integer value rejected" );
  require( !decode_transport_parameters( bytes( { 0x0a, 0x01, 0x40 } ) ), "truncated integer accepted" );
  require( !decode_transport_parameters( bytes( { 0x03, 0x02, 0x44 } ) ), "truncated value accepted" );
  require( !decode_transport_parameters( bytes( { 0x0a, 0x00 } ) ), "empty integer accepted" );
  require( !decode_transport_parameters( bytes( { 0x0c, 0x01, 0x00 } ) ), "nonempty migration flag accepted" );
  require( !decode_transport_parameters( bytes( { 0x02, 0x01, 0xff } ) ), "short reset token accepted" );
  require( !decode_transport_parameters( bytes( { 0x0f, 0x15 } ) ), "oversize CID accepted" );
  require( !decode_transport_parameters( bytes( { 0x03, 0x02, 0x44, 0xaf } ) ), "UDP size below 1200 accepted" );
  require( !decode_transport_parameters( bytes( { 0x0a, 0x01, 0x15 } ) ), "ACK exponent over 20 accepted" );
  require( !decode_transport_parameters( bytes( { 0x0b, 0x04, 0x80, 0x00, 0x40, 0x00 } ) ),
           "ACK delay of 2^14 accepted" );
  require( !decode_transport_parameters( bytes( { 0x0e, 0x01, 0x01 } ) ), "CID limit below 2 accepted" );
  require( !decode_transport_parameters( bytes( { 0x0f, 0x00, 0x0f, 0x00 } ) ), "duplicate ID accepted" );
  require( !decode_transport_parameters( bytes( { 0x08, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } ) ),
           "stream count above 2^60 accepted" );

  // Unknown and reserved IDs have no semantic validation and survive roundtrip.
  const auto unknown_wire = bytes( { 0x1b, 0x02, 0x12, 0x34, 0x0f, 0x00 } );
  const auto unknown = decode_transport_parameters( unknown_wire );
  require( unknown && unknown->at( 0x1b ) == bytes( { 0x12, 0x34 } ), "unknown ID discarded" );
  require( validate_transport_parameters( *unknown, { false, {}, {}, {} } ), "unknown ID rejected" );

  TransportParameters server { { 0x00, bytes( { 0xa1 } ) }, { 0x0f, bytes( { 0xb1 } ) } };
  require( validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), {} } ),
           "server CIDs rejected" );
  require( !validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa2 } ), {} } ),
           "wrong original DCID accepted" );
  server.erase( 0x00 );
  require( !validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), {} } ),
           "missing original DCID accepted" );
  server[0x00] = bytes( { 0xa1 } );
  require(
    !validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), bytes( { 0xc1 } ) } ),
    "missing Retry CID accepted" );
  server[0x10] = bytes( { 0xc1 } );
  require(
    validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), bytes( { 0xc1 } ) } ),
    "matching Retry CID rejected" );
  require( !validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), {} } ),
           "unsolicited Retry CID accepted" );
  require( !validate_transport_parameters( server, { false, bytes( { 0xb1 } ), {}, {} } ),
           "server-only parameters accepted from client" );

  std::string preferred( 25, '\0' ); // IPv4+port, IPv6+port, CID length.
  preferred[24] = '\1';
  preferred += bytes( { 0x42 } );
  preferred.append( 16, '\0' );
  server.erase( 0x10 );
  server[0x0d] = preferred;
  require( validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), {} } ),
           "valid preferred address rejected" );
  preferred[24] = '\0';
  server[0x0d] = preferred;
  require( !validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), {} } ),
           "zero-length preferred CID accepted" );
  server[0x0d].pop_back();
  require( !validate_transport_parameters( server, { true, bytes( { 0xb1 } ), bytes( { 0xa1 } ), {} } ),
           "truncated preferred address accepted" );
  server[0x0d] = preferred;
  preferred[24] = '\1';
  server[0x0d] = preferred;
  server[0x0f].clear();
  require( !validate_transport_parameters( server, { true, {}, bytes( { 0xa1 } ), {} } ),
           "preferred address accepted with zero-length server CID" );
  server[0x0f] = bytes( { 0xb1 } );
  std::string preferred_wire = bytes( { 0x0d, 0x2a } ) + preferred;
  require( decode_transport_parameters( preferred_wire ).has_value(), "valid preferred address wire rejected" );
  preferred_wire.pop_back();
  require( !decode_transport_parameters( preferred_wire ), "truncated preferred address wire accepted" );
  preferred[24] = '\0';
  require( !decode_transport_parameters( bytes( { 0x0d, 0x2a } ) + preferred ),
           "zero-length preferred CID on wire accepted" );
  require( decode_transport_parameters( bytes( { 0x0f, 0x00, 0x1b, 0x00 } ) ).has_value(),
           "zero-length CID and unknown value rejected" );
}
