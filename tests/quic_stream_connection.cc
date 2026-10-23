#include "quic/handshake_connection.hh"
#include "quic/varint.hh"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace quic;
namespace {
void check( bool ok, const char* why )
{
  if ( !ok )
    throw std::runtime_error( why );
}
const auto ca = UdpEndpoint::numeric( "127.0.0.1", 11111 ), sa = UdpEndpoint::numeric( "127.0.0.1", 22222 );
ConnectionConfig config( bool server, uint64_t& now, uint64_t window )
{
  ConnectionConfig c;
  c.local_cid = server ? "serverid" : "clientid";
  c.initial_dcid = server ? "" : "original";
  c.clock_us = [&now] { return now; };
  c.tls.server = server;
  c.tls.alpn = "minnow-quic";
  c.tls.server_name = "localhost";
  c.tls.ca_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.pem";
  c.tls.certificate_file = c.tls.ca_file;
  c.tls.private_key_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.key";
  for ( uint64_t id = 4; id <= 7; ++id )
    c.tls.local_parameters[id] = encode_varint( window );
  c.tls.local_parameters[8] = c.tls.local_parameters[9] = encode_varint( 4 );
  return c;
}
std::vector<UdpDatagram> drain( HandshakeConnection& c )
{
  std::vector<UdpDatagram> out;
  while ( auto d = c.poll_transmit() ) {
    check( out.size() < 100, "output loop" );
    out.push_back( std::move( *d ) );
  }
  return out;
}
void deliver( HandshakeConnection& to, const UdpDatagram& d, const UdpEndpoint& source )
{
  check( to.receive( { source, d.payload, d.ecn } ) != ConnectionReceive::Failed,
         "protected application flight failed" );
}
struct Pair
{
  uint64_t now = 1000;
  HandshakeConnection c, s;
  explicit Pair( uint64_t window ) : c( config( false, now, window ), sa ), s( config( true, now, window ), ca )
  {
    check( !c.open_stream( false ), "stream opened before handshake" );
    for ( size_t i = 0; i < 10; ++i )
      pump();
    check( c.state() == ConnectionState::Confirmed && s.state() == ConnectionState::Confirmed,
           "handshake not confirmed" );
  }
  void tick()
  {
    now += 1000;
    c.on_timeout();
    s.on_timeout();
  }
  void pump()
  {
    tick();
    for ( const auto& d : drain( c ) )
      deliver( s, d, ca );
    for ( const auto& d : drain( s ) )
      deliver( c, d, sa );
  }
};
void reliable( bool drop )
{
  Pair p( 30000 );
  auto id = p.c.open_stream( false );
  check( id == 0, "bidi open failed" );
  std::string payload;
  for ( size_t i = 0; i < 9000; ++i )
    payload.push_back( static_cast<char>( 'a' + i % 23 ) );
  check( p.c.write_stream( *id, payload, true ), "application write failed" );
  auto first = drain( p.c );
  check( first.size() > 4, "application STREAM output missing" );
  std::reverse( first.begin(), first.end() );
  for ( size_t i = 0; i < first.size(); ++i )
    if ( !drop || i != first.size() - 1 ) {
      deliver( p.s, first[i], ca );
      deliver( p.s, first[i], ca );
    }
  std::string got;
  bool eof = false;
  // Drop the first ACK flight as well; loss recovery must deliver the same logical data once.
  (void)drain( p.s );
  for ( size_t i = 0; i < 4000 && !eof; ++i ) {
    p.pump();
    auto r = p.s.read_stream( 0, 137 );
    got += r.data;
    eof = r.eof;
  }
  check( eof && got == payload, "reorder/loss STREAM bytes or FIN lost" );
  for ( size_t i = 0; i < 50 && p.c.stream_send_buffered(); ++i )
    p.pump();
  check( p.c.stream_send_buffered() == 0, "ACK did not release application buffer" );
  check( p.s.write_stream( 0, "reply", true ), "bidi reply failed" );
  std::string reply;
  bool reply_eof = false;
  for ( size_t i = 0; i < 100 && !reply_eof; ++i ) {
    p.pump();
    auto r = p.c.read_stream( 0, 100 );
    reply += r.data;
    reply_eof = r.eof;
  }
  check( reply == "reply" && reply_eof, "bidi reverse delivery failed" );
  auto uni = p.s.open_stream( true );
  check( uni == 3 && p.s.write_stream( 3, "", true ), "uni empty FIN failed" );
  bool done = false;
  for ( size_t i = 0; i < 100 && !done; ++i ) {
    p.pump();
    done = p.c.read_stream( 3, 1 ).eof;
  }
  check( done && !p.c.write_stream( 3, "bad", false ), "uni direction/EOF wrong" );
}
void tiny_credit_and_cancel()
{
  Pair p( 4 );
  check( p.c.open_stream( false ) == 0 && p.c.write_stream( 0, "abcdefghijkl", true ), "tiny-window write failed" );
  for ( size_t i = 0; i < 20; ++i )
    p.pump();
  check( p.c.stream_send_buffered() == 8, "sender exceeded initial credit" );
  auto r = p.s.read_stream( 0, 2 );
  check( r.data == "ab" && !r.eof, "tiny partial read failed" );
  // Lose both MAX_DATA and MAX_STREAM_DATA; their recovery must reopen the sender.
  (void)drain( p.s );
  std::string got = "ab";
  bool eof = false;
  for ( size_t i = 0; i < 4000 && !eof; ++i ) {
    p.pump();
    r = p.s.read_stream( 0, 2 );
    got += r.data;
    eof = r.eof;
  }
  check( eof && got == "abcdefghijkl", "lost credit update deadlocked sender" );
  check( p.c.open_stream( false ) == 4 && p.c.write_stream( 4, "cancelled", false ), "cancel stream write failed" );
  for ( size_t i = 0; i < 20; ++i )
    p.pump();
  check( p.s.stop_sending( 4, 77 ), "STOP queue failed" );
  bool reset = false;
  for ( size_t i = 0; i < 4000 && !reset; ++i ) {
    p.pump();
    reset = p.s.read_stream( 4, 100 ).reset_error == 77;
  }
  check( reset && !p.c.write_stream( 4, "x", false ), "STOP did not produce RESET" );
  check( p.c.open_stream( true ) == 2 && p.c.write_stream( 2, "unsent", true ) && p.c.reset_stream( 2, 9 ),
         "local reset queue failed" );
  reset = false;
  for ( size_t i = 0; i < 100 && !reset; ++i ) {
    p.pump();
    reset = p.s.read_stream( 2, 100 ).reset_error == 9;
  }
  check( reset, "unsent reset not delivered" );
}
}
int main()
{
  try {
    reliable( false );
    reliable( true );
    tiny_credit_and_cancel();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
