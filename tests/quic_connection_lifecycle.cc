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
void initial_protocol_close()
{
  uint64_t now = 1000;
  for ( int variant = 0; variant < 6; ++variant ) {
    const auto mode = variant % 3;
    auto cfg = config( true );
    if ( variant >= 3 )
      cfg.local_cid.assign( 20, char( 115 ) );
    cfg.clock_us = [&] { return now; };
    HandshakeConnection server { cfg, client_address };
    const auto plaintext = mode == 0   ? std::string( 1, char( 0x1f ) )
                           : mode == 1 ? encode_frame( AckFrame { 0, { { 0, 0 } }, std::nullopt } )
                                       : encode_frame( HandshakeDoneFrame {} );
    const auto wire = initial_packet( plaintext );
    auto damaged = wire;
    damaged.back() ^= 1;
    require( server.receive( { client_address, damaged, 0 } ) == ConnectionReceive::Discarded
               && !server.poll_transmit() && server.state() == ConnectionState::WaitingInitial,
             "forged Initial caused close" );
    require( server.receive( { client_address, wire, 0 } ) == ConnectionReceive::Failed,
             "protocol error receive status" );
    const auto response = server.poll_transmit();
    require( response.has_value(), "authenticated Initial error produced no close" );
    require( server.state() == ConnectionState::Closing && response->payload.size() == 1200,
             "Initial close state or size" );
    const auto keys = *derive_initial_keys( "original" );
    const auto opened
      = open_initial_packet( keys.server, InitialSender::Server, response->payload, 0, std::nullopt );
    require( opened && opened->layout.dcid == "clientid" && opened->layout.scid == cfg.local_cid,
             "Initial close wrong keys or route" );
    const auto frames = decode_frames( opened->plaintext );
    require( frames && std::holds_alternative<ConnectionCloseFrame>( frames->front() ),
             "Initial close missing frame" );
    const auto& close = std::get<ConnectionCloseFrame>( frames->front() );
    require( !close.application && close.error_code == ( mode == 0 ? 7 : 10 )
               && close.frame_type
                    == ( mode == 0   ? 0
                         : mode == 1 ? 2
                                     : 0x1e ),
             "Initial close wrong diagnostic" );
    const auto due = server.next_timeout_us();
    require( due && !server.poll_transmit(), "Initial close lifecycle missing" );
    server.receive( { client_address, initial_packet( "x", 1 ), 0 } );
    require( server.transport_error() == close.error_code && server.next_timeout_us() == due,
             "error close not sticky" );
    now = *due;
    server.on_timeout();
    require( server.state() == ConnectionState::Closed && !server.poll_transmit(), "error close not reclaimed" );
  }
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
  const auto close_layout = parse_protected_packet( close->payload, 0, 8 );
  require( close_layout && close_layout->kind == PacketKind::OneRtt
             && close_layout->packet_end == close->payload.size(),
           "confirmed app close used retired keys" );
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

std::vector<PacketLayout> layouts( const UdpDatagram& datagram )
{
  std::vector<PacketLayout> out;
  size_t offset = 0;
  while ( offset < datagram.payload.size() ) {
    const auto layout = parse_protected_packet( datagram.payload, offset, 8 );
    require( layout.has_value(), "close coalescing malformed" );
    out.push_back( *layout );
    offset = layout->packet_end;
  }
  return out;
}
std::optional<UdpDatagram> handshake_part( const UdpDatagram& d )
{
  size_t offset = 0;
  for ( const auto& layout : layouts( d ) ) {
    if ( layout.kind == PacketKind::Handshake )
      return UdpDatagram { d.peer, d.payload.substr( offset, layout.packet_end - offset ), 0 };
    offset = layout.packet_end;
  }
  return std::nullopt;
}
void early_application_close()
{
  uint64_t now = 1000;
  auto cc = config( false ), sc = config( true );
  cc.clock_us = sc.clock_us = [&] { return now; };
  HandshakeConnection c { cc, server_address }, s { sc, client_address };
  transfer( c, s, client_address );
  transfer( s, c, server_address );
  require( c.state() == ConnectionState::Established && s.state() == ConnectionState::Handshaking,
           "early close setup" );
  require( c.close( 0x77, "private reason" ), "early close rejected" );
  const auto close = c.poll_transmit();
  require( close.has_value(), "early close absent" );
  const auto fallback = handshake_part( *close );
  require( fallback.has_value(), "early close omitted Handshake fallback" );
  // Drop the other levels: server can decrypt Handshake even without client Finished.
  deliver( s, *fallback, client_address );
  const auto remote = s.close_info();
  require( s.state() == ConnectionState::Draining && remote && !remote->application && remote->error_code == 0x0c
             && remote->frame_type == 0 && remote->reason.empty(),
           "lower level leaked app diagnostic" );
  const auto local = c.close_info();
  require( local && local->application && local->error_code == 0x77 && local->reason == "private reason",
           "fallback overwrote local diagnostic" );
  const auto parts = layouts( *close );
  require( parts.back().kind == PacketKind::OneRtt && close->payload.size() == 1200,
           "early close order/Initial padding" );
}
void server_before_serverhello_error()
{
  uint64_t now = 1000;
  auto cc = config( false ), sc = config( true );
  cc.clock_us = sc.clock_us = [&] { return now; };
  HandshakeConnection c { cc, server_address }, s { sc, client_address };
  transfer( c, s, client_address );
  require( s.receive( { client_address, initial_packet( std::string( 1, char( 0x1f ) ), 100 ), 0 } )
             == ConnectionReceive::Failed,
           "server early error" );
  const auto close = s.poll_transmit();
  require( close.has_value(), "server early close absent" );
  const auto parts = layouts( *close );
  require( parts.front().kind == PacketKind::Initial && handshake_part( *close ) && close->payload.size() == 1200,
           "server early levels/padding" );
  // Client never received ServerHello: only Initial can notify it.
  deliver( c, *close, server_address );
  const auto info = c.close_info();
  require( c.state() == ConnectionState::Draining && info && info->error_code == 7,
           "Initial fallback not usable before ServerHello" );
}
void certificate_error_close()
{
  uint64_t now = 1000;
  auto cc = config( false ), sc = config( true );
  cc.clock_us = sc.clock_us = [&] { return now; };
  cc.tls.server_name = "wrong.example";
  HandshakeConnection c { cc, server_address }, s { sc, client_address };
  transfer( c, s, client_address );
  bool failed = false;
  for ( const auto& datagram : drain( s ) ) {
    if ( deliver( c, datagram, server_address ) == ConnectionReceive::Failed ) {
      failed = true;
      break;
    }
  }
  require( failed && c.transport_error() && *c.transport_error() >= 0x100,
           "certificate rejection did not preserve TLS alert" );
  const auto close = c.poll_transmit();
  require( close.has_value(), "TLS error close absent" );
  const auto fallback = handshake_part( *close );
  require( fallback.has_value(), "TLS failure lost same-advance Handshake write key" );
  deliver( s, *fallback, client_address );
  const auto info = s.close_info();
  require( s.state() == ConnectionState::Draining && info && info->error_code == c.transport_error()
             && !info->application,
           "TLS close decryption or code failed" );
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
    certificate_error_close();
    early_application_close();
    server_before_serverhello_error();
    initial_protocol_close();
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
