#include "quic/handshake_connection.hh"
#include "quic/header_protection.hh"
#include "quic/initial_packet.hh"
#include "quic/protected_packet.hh"
#include "quic/varint.hh"
#include <limits>

#include <algorithm>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <vector>

using namespace quic;
namespace {
void require( bool ok, std::string_view text )
{
  if ( !ok )
    throw std::runtime_error( std::string { text } );
}
ConnectionConfig config( bool server )
{
  ConnectionConfig c;
  c.local_cid = server ? "serverid" : "clientid";
  c.initial_dcid = server ? "" : "original";
  c.tls.server = server;
  c.tls.alpn = "minnow-quic";
  c.tls.server_name = "localhost";
  c.tls.ca_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.pem";
  c.tls.certificate_file = c.tls.ca_file;
  c.tls.private_key_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.key";
  return c;
}
const auto client_address = UdpEndpoint::numeric( "127.0.0.1", 11111 );
const auto server_address = UdpEndpoint::numeric( "127.0.0.1", 22222 );
std::vector<UdpDatagram> drain( HandshakeConnection& c )
{
  std::vector<UdpDatagram> result;
  while ( auto datagram = c.poll_transmit() ) {
    require( result.size() < 100, "unbounded output" );
    result.push_back( std::move( *datagram ) );
  }
  return result;
}
ConnectionReceive deliver( HandshakeConnection& to, const UdpDatagram& out, const UdpEndpoint& source )
{
  return to.receive( { source, out.payload, out.ecn } );
}
void transfer( HandshakeConnection& from, HandshakeConnection& to, const UdpEndpoint& source )
{
  for ( const auto& d : drain( from ) )
    require( deliver( to, d, source ) != ConnectionReceive::Failed, "connection flight failed" );
}
std::string initial_packet( std::string plaintext, uint64_t pn = 0, std::string_view dcid = "original" )
{
  plaintext.resize( 1200, '\0' );
  const auto keys = derive_initial_keys( dcid );
  return seal_initial_packet( keys->client, InitialSender::Client, dcid, "clientid", "", pn, 4, plaintext );
}
void peer_close_timer()
{
  uint64_t now = 1000;
  auto cfg = config( true );
  cfg.clock_us = [&] { return now; };
  HandshakeConnection server { cfg, client_address };
  require(
    server.receive(
      { client_address, initial_packet( encode_frame( ConnectionCloseFrame { false, 0x42, 0, "bye" } ) ), 0 } )
      == ConnectionReceive::Processed,
    "peer close rejected" );
  require( server.state() == ConnectionState::Draining, "not draining" );
  const auto due = server.next_timeout_us();
  require( due && *due == now + 2997000, "draining expiry absent" );
  require( !server.poll_transmit(), "draining sent packet" );
  const auto info = server.close_info();
  require( info && !info->application && info->error_code == 0x42 && info->reason == "bye",
           "peer close metadata lost" );
  now = *due - 1;
  server.on_timeout();
  require( server.state() == ConnectionState::Draining, "draining expired early" );
  now = *due;
  server.on_timeout();
  require( server.state() == ConnectionState::Closed && !server.next_timeout_us(), "draining did not expire" );
}
struct Pair
{
  uint64_t now = 1000;
  uint64_t ci {}, si {};
  HandshakeConnection c, s;
  ConnectionConfig cfg( bool server )
  {
    auto x = config( server );
    x.clock_us = [this] { return now; };
    x.tls.local_parameters[1] = encode_varint( server ? si : ci );
    for ( uint64_t id = 4; id <= 7; ++id )
      x.tls.local_parameters[id] = encode_varint( 1024 );
    x.tls.local_parameters[8] = x.tls.local_parameters[9] = encode_varint( 1 );
    return x;
  }
  Pair( uint64_t client_idle = 0, uint64_t server_idle = 0 )
    : ci( client_idle ), si( server_idle ), c( cfg( false ), server_address ), s( cfg( true ), client_address )
  {
    for ( int i = 0; i < 10; ++i ) {
      now += 1000;
      c.on_timeout();
      s.on_timeout();
      transfer( c, s, client_address );
      transfer( s, c, server_address );
    }
    require( c.state() == ConnectionState::Confirmed && s.state() == ConnectionState::Confirmed, "pair setup" );
  }
};
void local_close()
{
  Pair p;
  require( !p.c.close( uint64_t { 1 } << 62, "invalid" ) && !p.c.close( 0, std::string( 257, 'x' ) ),
           "invalid close accepted" );
  require( p.c.send_ping(), "preclose ping" );
  const auto flight = p.c.poll_transmit();
  require( flight.has_value(), "preclose output" );
  const auto stream = p.c.open_stream( false );
  require( stream && p.c.write_stream( *stream, "queued" ) && p.c.stream_send_buffered() > 0,
           "close stream setup" );
  require( p.c.close( 17, "finished" ), "local close rejected" );
  require( p.c.state() == ConnectionState::Closing && !p.c.send_ping() && !p.c.open_stream( false ),
           "closing app operations" );
  require( !p.c.close( 18, "replacement" ), "second close changed reason" );
  const auto due = p.c.next_timeout_us();
  require( due.has_value(), "closing expiry missing" );
  const auto close = p.c.poll_transmit();
  require( close.has_value() && !p.c.poll_transmit(), "close initial output" );
  require( p.c.congestion_stats().bytes_in_flight == 0 && !p.c.peer_parameters() && p.c.stream_send_buffered() == 0
             && p.c.stream_ids().empty(),
           "closing state retained payload/keys" );
  require( p.s.send_ping(), "server ping" );
  const auto ping = p.s.poll_transmit();
  require( ping.has_value(), "server ping output" );
  const auto interval = ( *due - p.now ) / 3;
  p.now += interval - 1;
  deliver( p.c, *ping, server_address );
  require( !p.c.poll_transmit(), "close reply before rate interval" );
  ++p.now;
  p.c.on_timeout();
  require( !p.c.poll_transmit(), "timer spontaneously retransmitted close" );
  p.c.receive( { UdpEndpoint::numeric( "127.0.0.1", 33333 ), ping->payload, 0 } );
  require( !p.c.poll_transmit(), "foreign peer elicited close" );
  auto bad = ping->payload;
  bad[1] ^= 1;
  p.c.receive( { server_address, bad, 0 } );
  require( !p.c.poll_transmit(), "foreign CID elicited close" );
  deliver( p.c, *ping, server_address );
  const auto repeated = p.c.poll_transmit();
  require( repeated && repeated->payload == close->payload && !p.c.poll_transmit(),
           "close response not exact/bounded" );
  require( p.c.next_timeout_us() == due, "incoming packet extended closing" );
  deliver( p.s, *repeated, client_address );
  const auto info = p.s.close_info();
  require( p.s.state() == ConnectionState::Draining && info && info->application && info->error_code == 17
             && info->reason == "finished",
           "protected close not delivered" );
  require( !p.s.poll_transmit(), "draining echo" );
  p.now += interval;
  deliver( p.c, *ping, server_address );
  require( !p.c.poll_transmit(), "close response interval did not double" );
  p.now = *due;
  p.c.on_timeout();
  require( p.c.state() == ConnectionState::Closed && !p.c.poll_transmit() && !p.c.next_timeout_us(),
           "closing did not expire" );
  auto cfg = config( false );
  HandshakeConnection early { cfg, server_address };
  require( !early.close(), "early application close" );
}

void idle_under_amplification_block()
{
  uint64_t now = 1000;
  auto cc = config( false ), sc = config( true );
  cc.clock_us = sc.clock_us = [&] { return now; };
  sc.tls.local_parameters[1] = encode_varint( 1 );
  sc.tls.local_parameters.emplace( 0xface, std::string( 15000, char( 120 ) ) );
  HandshakeConnection c { cc, server_address }, s { sc, client_address };
  transfer( c, s, client_address );
  (void)drain( s );
  require( !s.poll_transmit(), "amplification block setup" );
  const auto due = s.next_timeout_us();
  require( due && *due == now + 2997000, "amplification block suppressed idle timer" );
  now = *due;
  s.on_timeout();
  require( s.state() == ConnectionState::Closed && !s.poll_transmit(), "blocked idle did not expire" );
}
void idle_floor_and_saturation()
{
  uint64_t now = 1000;
  auto cfg = config( false );
  cfg.clock_us = [&] { return now; };
  cfg.tls.local_parameters[1] = encode_varint( 1 );
  HandshakeConnection c { cfg, server_address };
  require( c.next_timeout_us() == now + 2997000, "idle below three PTO floor / prehandoff timer absent" );
  now += 2997000;
  c.on_timeout();
  require( c.state() == ConnectionState::Closed && !c.poll_transmit() && !c.next_timeout_us(),
           "initial idle did not silently close" );
  now = std::numeric_limits<uint64_t>::max() - 100;
  cfg.tls.local_parameters[1] = encode_varint( max_varint );
  HandshakeConnection huge { cfg, server_address };
  require( huge.next_timeout_us() == std::numeric_limits<uint64_t>::max(), "idle timer arithmetic overflow" );
  now = std::numeric_limits<uint64_t>::max();
  huge.on_timeout();
  require( huge.state() == ConnectionState::Closed, "saturated idle expiry" );
}
void idle_negotiation()
{
  for ( const auto& values : { std::pair<uint64_t, uint64_t> { 1000, 2000 }, { 0, 1000 }, { 1000, 0 } } ) {
    Pair p( values.first, values.second );
    const auto due = p.c.next_timeout_us();
    require( due && *due <= p.now + 1000000 && *due > p.now + 900000, "idle minimum/nonzero negotiation" );
    p.now = *due - 1;
    p.c.on_timeout();
    require( p.c.state() == ConnectionState::Confirmed, "idle expired early" );
    p.now = *due;
    require( !p.c.close() && p.c.state() == ConnectionState::Closed && !p.c.poll_transmit(),
             "close revived expired connection" );
  }
  Pair p;
  require( !p.c.next_timeout_us(), "zero/zero idle enabled" );
}
void idle_activity()
{
  Pair p( 1000, 1000 );
  p.now += 100000;
  require( p.c.send_ping(), "idle first ping queue" );
  require( p.c.poll_transmit().has_value(), "idle first ping handoff" );
  const auto first_sent = p.now;
  p.now += 100000;
  require( p.c.send_ping(), "idle second ping queue" );
  require( p.c.poll_transmit().has_value(), "idle second ping handoff" );
  p.now = first_sent + 1000000;
  p.c.on_timeout();
  require( p.c.state() == ConnectionState::Closed, "repeated sends postponed idle" );
  Pair q( 1000, 1000 );
  q.now += 100000;
  require( q.s.send_ping(), "idle receive ping" );
  const auto ping = q.s.poll_transmit();
  require( ping.has_value(), "idle receive output" );
  deliver( q.c, *ping, server_address );
  const auto due = q.c.next_timeout_us();
  require( due == q.now + 1000000, "fresh authenticated packet did not reset idle" );
  // ACK-only output cannot restart timer.
  q.now += 100000;
  require( q.c.poll_transmit().has_value(), "idle ACK handoff" );
  require( q.c.next_timeout_us() == due, "ACK-only reset idle" );
  q.now = *due - 1;
  auto forged = ping->payload;
  forged.back() ^= 1;
  require( q.c.receive( { server_address, forged, 0 } ) == ConnectionReceive::Discarded,
           "forged packet processed" );
  deliver( q.c, *ping, server_address );
  require( q.c.next_timeout_us() == due, "forged/duplicate packet reset idle" );
  q.now = *due;
  require( !q.c.poll_transmit() && q.c.state() == ConnectionState::Closed, "poll revived idle connection" );
}

}
int main()
{
  try {
    peer_close_timer();
    local_close();
    idle_under_amplification_block();
    idle_floor_and_saturation();
    idle_negotiation();
    idle_activity();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
