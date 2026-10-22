#include "quic/udp_socket.hh"

#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string_view>
#include <type_traits>

using namespace quic;
namespace {
void require( bool ok, std::string_view message )
{
  if ( !ok )
    throw std::runtime_error( std::string { message } );
}
template<class Exception, class Function>
void rejects( Function fn )
{
  bool rejected = false;
  try {
    fn();
  } catch ( const Exception& ) {
    rejected = true;
  }
  require( rejected, "invalid input was accepted" );
}
UdpDatagram receive( UdpSocket& socket, size_t capacity = 65535 )
{
  pollfd ready { socket.native_handle(), POLLIN, 0 };
  require( poll( &ready, 1, 2000 ) == 1, "loopback datagram timed out" );
  const auto datagram = socket.receive( capacity );
  require( datagram.has_value(), "readable socket returned no datagram" );
  return *datagram;
}
void loopback( std::string_view ip )
{
  const auto bind = UdpEndpoint::numeric( ip, 0 );
  UdpSocket sender { bind }, receiver { bind };
  const auto from = sender.local_endpoint(), to = receiver.local_endpoint();
  require( from.port() != 0 && to.port() != 0 && from != to, "ephemeral bind failed" );
  require( from.ip() == ip && from.family() == bind.family(), "local endpoint changed" );
  require( !receiver.receive(), "empty socket blocked or returned a datagram" );
  require( ( fcntl( sender.native_handle(), F_GETFD ) & FD_CLOEXEC ) != 0, "descriptor is inherited by exec" );
  require( ( fcntl( sender.native_handle(), F_GETFL ) & O_NONBLOCK ) != 0, "descriptor is blocking" );
  for ( uint8_t ecn = 0; ecn < 4; ++ecn ) {
    const std::string payload { "quic\0payload", 12 };
    require( sender.send( to, payload, ecn ), "loopback send would block" );
    const auto datagram = receive( receiver, payload.size() );
    require( datagram.peer == from && datagram.payload == payload && datagram.ecn == ecn,
             "datagram source, bytes or ECN changed" );
    require( receiver.send( datagram.peer, "reply", ecn ), "reply send failed" );
    require( receive( sender ).payload == "reply", "reply was not routed to sender" );
  }
  require( sender.send( to, "" ), "empty datagram send failed" );
  require( receive( receiver ).payload.empty(), "empty datagram was lost" );
  require( !receiver.receive(), "empty datagram was confused with EAGAIN" );
  require( sender.send( to, "oversized" ), "truncation fixture send failed" );
  rejects<std::length_error>( [&] { receive( receiver, 3 ); } );
  require( sender.send( to, "full" ), "post-truncation send failed" );
  require( receive( receiver ).payload == "full", "truncation leaked partial bytes or failed to consume" );
  rejects<std::invalid_argument>( [&] { receiver.receive( 0 ); } );
  rejects<std::invalid_argument>( [&] { receiver.receive( 65536 ); } );
  rejects<std::invalid_argument>( [&] { sender.send( to, "bad", 4 ); } );
  rejects<std::length_error>( [&] { sender.send( to, std::string( 65528, 'x' ) ); } );
  const auto other = UdpEndpoint::numeric( ip == "::1" ? "127.0.0.1" : "::1", to.port() );
  rejects<std::invalid_argument>( [&] { sender.send( other, "bad" ); } );
  require( !receiver.receive(), "rejected send emitted bytes" );
}
}
int main()
{
  static_assert( !std::is_copy_constructible_v<UdpSocket> );
  try {
    rejects<std::invalid_argument>( [] { UdpEndpoint::numeric( "localhost", 1 ); } );
    rejects<std::invalid_argument>( [] { UdpEndpoint::numeric( std::string { "127.0.0.1\0evil", 14 }, 1 ); } );
    rejects<std::invalid_argument>( [] { UdpEndpoint::numeric( "127.0.0.1", 1, 2 ); } );
    require( UdpEndpoint::numeric( "fe80::1", 443, 7 ).scope_id() == 7, "IPv6 scope lost" );
    require( UdpEndpoint::numeric( "fe80::1", 443, 7 ) != UdpEndpoint::numeric( "fe80::1", 443, 8 ),
             "IPv6 endpoint equality ignored scope" );
    loopback( "127.0.0.1" );
    loopback( "::1" );
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
