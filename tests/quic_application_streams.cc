#include "quic/application_streams.hh"
#include "quic/varint.hh"
#include <iostream>
#include <stdexcept>
using namespace quic;
namespace {
void check( bool ok, const char* why )
{
  if ( !ok )
    throw std::runtime_error( why );
}
TransportParameters limits( uint64_t data = 24, uint64_t stream = 12, uint64_t count = 4 )
{
  return { { 4, encode_varint( data ) },
           { 5, encode_varint( stream ) },
           { 6, encode_varint( stream ) },
           { 7, encode_varint( stream ) },
           { 8, encode_varint( count ) },
           { 9, encode_varint( count ) } };
}
StreamFrame sf( uint64_t id, uint64_t offset, std::string data, bool fin = false )
{
  return { id, offset, std::move( data ), fin, true, true };
}
void receive_and_final_size()
{
  ApplicationStreams s( true, limits(), limits() );
  check( !s.receive( { sf( 0, 3, "def", true ) } ), "FIN tail rejected" );
  check( s.read( 0, 20 ).data.empty() && !s.read( 0, 20 ).eof, "gap produced EOF" );
  check( !s.receive( { sf( 0, 1, "bcde" ), sf( 0, 0, "abc" ) } ), "overlap rejected" );
  auto r = s.read( 0, 2 );
  check( r.data == "ab" && !r.eof, "ordered partial read broken" );
  r = s.read( 0, 20 );
  check( r.data == "cdef" && r.eof, "tail/EOF lost" );
  check( !s.receive( { sf( 0, 0, "abcdef", true ) } ) && s.read( 0, 20 ).data.empty(), "duplicate redelivered" );
  check( s.receive( { sf( 0, 6, "x" ) } ) == 6, "data beyond final size accepted" );
  check( s.receive( { ResetStreamFrame { 0, 99, 5 } } ) == 6, "RESET changed FIN final size" );
  ApplicationStreams t( true, limits(), limits() );
  check( t.receive( { sf( 0, 0, "ok" ), sf( 4, 12, "x" ) } ) == 3, "stream overflow not rejected" );
  check( t.ids().empty(), "invalid packet partly committed" );
  check( !t.receive( { sf( 0, 11, "x" ), sf( 4, 11, "y" ) } ), "valid sparse frames rejected" );
  check( t.receive( { sf( 8, 0, "z" ) } ) == 3, "aggregate high offsets not charged" );
  check( t.receive( { sf( 0, max_varint, "x" ) } ) == 7, "offset overflow accepted" );
}
void ids_and_reset()
{
  ApplicationStreams c( false, limits(), limits() );
  check( c.open( false ) == 0 && c.open( true ) == 2, "client stream ID wrong" );
  check( c.receive( { sf( 2, 0, "x" ) } ) == 5, "peer wrote local uni stream" );
  check( c.receive( { sf( 4, 0, "x" ) } ) == 5, "peer opened local stream" );
  check( c.receive( { sf( 17, 0, "x" ) } ) == 4, "peer stream limit ignored" );
  check( !c.receive( { MaxStreamDataFrame { 9, 20 } } ), "MAX_STREAM_DATA failed to open peer bidi" );
  check( c.write( 1, "reply", true ), "implicit lower bidi not available" );
  check( !c.receive( { StopSendingFrame { 5, 42 } } ), "STOP failed to open peer bidi" );
  auto f = c.pending();
  check( f && std::holds_alternative<ResetStreamFrame>( *f ), "STOP did not schedule RESET" );
  check( std::get<ResetStreamFrame>( *f ).final_size == 0, "STOP final offset wrong" );
  c.sent( *f );
  check( !c.write( 5, "bad", false ), "reset sender accepted data" );
  ApplicationStreams s( true, limits(), limits() );
  check( !s.receive( { sf( 0, 8, "ab" ), ResetStreamFrame { 0, 99, 12 } } ), "RESET final credit rejected" );
  auto r = s.read( 0, 100 );
  check( r.data.empty() && r.reset_error == 99 && !r.eof, "RESET not exposed" );
  check( !s.receive( { sf( 0, 8, "ab" ), ResetStreamFrame { 0, 100, 12 } } ), "duplicate RESET failed" );
  check( s.read( 0, 100 ).reset_error == 99, "duplicate RESET changed first error" );
  check( s.receive( { sf( 0, 12, "x" ) } ) == 6, "reset final size not enforced" );
  check( !s.receive( { sf( 4, 11, "z" ) } ), "RESET did not release aggregate credit" );
  ApplicationStreams z( false, {}, {} );
  check( !z.open( false ), "default-zero stream limit ignored" );
  check( !z.receive( { MaxStreamsFrame { false, 1 } } ) && z.open( false ) == 0, "MAX_STREAMS ignored" );
  check( z.receive( { MaxStreamsFrame { false, ( uint64_t { 1 } << 60 ) + 1 } } ) == 7,
         "invalid MAX_STREAMS accepted" );
}
void send_and_credit()
{
  ApplicationStreams c( false, limits(), limits( 4, 3, 4 ) );
  check( c.open( false ) == 0 && c.write( 0, "abcdef", true ), "write rejected" );
  auto f = c.pending();
  check( f && std::get<StreamFrame>( *f ).data == "abc" && !std::get<StreamFrame>( *f ).fin,
         "stream credit ignored" );
  check( encode_frame( *c.pending() ) == encode_frame( *f ), "peek consumed bytes" );
  c.sent( *f );
  c.acknowledged( *f );
  check( c.buffered() == 3, "ACK failed to reclaim bytes" );
  c.acknowledged( *f );
  check( c.buffered() == 3, "duplicate ACK freed twice" );
  auto blocked = c.pending();
  check( blocked && std::holds_alternative<StreamDataBlockedFrame>( *blocked ), "stream blocked signal missing" );
  c.sent( *blocked );
  check( !c.receive( { MaxStreamDataFrame { 0, 9 }, MaxDataFrame { 8 }, MaxDataFrame { 2 } } ),
         "MAX update failed" );
  f = c.pending();
  check( f && std::get<StreamFrame>( *f ).offset == 3 && std::get<StreamFrame>( *f ).data == "def"
           && std::get<StreamFrame>( *f ).fin,
         "credit update/FIN lost" );
  c.sent( *f );
  c.acknowledged( *f );
  check( c.buffered() == 0 && !c.write( 0, "x", false ), "FIN state/buffer wrong" );
  ApplicationStreams o( false, limits( 4000, 4000 ), limits( 4000, 4000 ) );
  check( o.open( false ) == 0 && o.write( 0, std::string( 1200, 'x' ), true ), "large write failed" );
  auto first = *o.pending();
  o.sent( first );
  auto second = *o.pending();
  o.sent( second );
  o.acknowledged( second );
  check( o.buffered() == 600, "out-of-order ACK did not release own range" );
  check( o.reset( 0, 8 ), "FIN ACK falsely completed stream with missing prefix" );
  auto reset_frame = o.pending();
  check( reset_frame && std::get<ResetStreamFrame>( *reset_frame ).final_size == 1200,
         "reset after committed FIN changed final size" );
  o.acknowledged( first );
  check( o.buffered() == 0, "prefix ACK did not release" );
  ApplicationStreams b( false, limits(), limits() );
  check( b.open( false ) == 0, "bounded open failed" );
  check( !b.write( 0, std::string( 1048577, 'x' ), false ) && b.buffered() == 0, "send cap not atomic" );
  check( b.write( 0, "abcdef", true ), "unsent FIN write rejected" );
  check( b.reset( 0, 7 ), "reset rejected" );
  f = b.pending();
  check( f && std::get<ResetStreamFrame>( *f ).final_size == 0 && b.buffered() == 0,
         "unsent suffix committed to reset" );
  ApplicationStreams d( false, limits(), limits( 0, 3 ) );
  check( d.open( false ) == 0 && d.write( 0, "x", false ), "zero credit buffer failed" );
  f = d.pending();
  check( f && std::holds_alternative<DataBlockedFrame>( *f ), "connection BLOCKED missing" );
  d.sent( *f );
  check( !d.pending(), "BLOCKED busy loop" );
}
void asymmetric_credit_and_counts()
{
  auto p = limits( 100, 0, 4 );
  p[5] = encode_varint( 3 );
  p[6] = encode_varint( 7 );
  p[7] = encode_varint( 5 );
  ApplicationStreams c( false, p, p ), server( true, p, p );
  check( c.open( false ) == 0 && c.write( 0, "abcdefgh", false ), "asymmetric local bidi failed" );
  auto f = *c.pending();
  check( std::get<StreamFrame>( f ).data == "abcdefg", "bidi_remote TP mapped incorrectly" );
  check( !server.receive( { f } ), "peer-initiated bidi receive limit mapped incorrectly" );
  check( server.write( 0, "reply", false ), "asymmetric reply write failed" );
  auto reply = *server.pending();
  check( std::get<StreamFrame>( reply ).data == "rep", "bidi_local TP mapped incorrectly" );
  check( !c.receive( { reply } ), "local bidi receive limit mapped incorrectly" );
  check( c.open( true ) == 2 && c.write( 2, "123456", false ), "asymmetric uni write failed" );
  c.sent( f );
  auto uni = *c.pending();
  check( std::get<StreamFrame>( uni ).stream_id == 2 && std::get<StreamFrame>( uni ).data == "12345",
         "uni TP mapped incorrectly" );
  check( !server.receive( { uni } ), "uni receive window mapped incorrectly" );
  ApplicationStreams bounded( false, limits( 0, 0, 128 ), limits( 0, 0, 128 ) );
  for ( size_t i = 0; i < 128; ++i )
    check( bounded.open( false ) == 4 * i, "stream count boundary too small" );
  check( !bounded.open( false ), "negotiated stream count exceeded" );
  check( !bounded.receive( { MaxStreamsFrame { false, 200 } } ) && !bounded.open( false ),
         "local metadata cap exceeded" );
}
void aggregate_admission()
{
  ApplicationStreams s( false, limits( 1048576, 1048576 ), limits( 1048576, 1048576 ) );
  check( s.open( false ) == 0 && s.open( false ) == 4, "aggregate streams failed" );
  check( s.write( 0, std::string( 1048576, 'x' ), false ), "full-capacity write rejected" );
  auto first = *s.pending();
  s.sent( first );
  check( !s.write( 4, "x", false ), "queued plus inflight cap exceeded across streams" );
  check( s.reset( 0, 9 ) && s.buffered() == 600, "reset released unacknowledged committed bytes" );
  check( !s.write( 4, std::string( 1047977, 'y' ), false ), "reset bypassed aggregate inflight cap" );
  s.acknowledged( first );
  check( s.buffered() == 0 && s.write( 4, std::string( 1048576, 'z' ), true ),
         "ACK did not reopen bounded admission" );
}
void read_credit()
{
  ApplicationStreams s( true, limits( 4, 4 ), limits() );
  check( !s.receive( { sf( 0, 2, "cd" ), sf( 0, 0, "ab" ) } ), "window exact fit rejected" );
  check( s.read( 0, 2 ).data == "ab", "read failed" );
  bool data = false, stream = false;
  while ( auto f = s.pending() ) {
    if ( auto* m = std::get_if<MaxDataFrame>( &*f ) )
      data = m->maximum_data == 6;
    if ( auto* m = std::get_if<MaxStreamDataFrame>( &*f ) )
      stream = m->maximum_data == 6;
    s.sent( *f );
  }
  check( data && stream, "read credit not advertised" );
  check( !s.receive( { sf( 0, 4, "ef", true ) } ), "read failed to reopen receive window" );
  auto r = s.read( 0, 10 );
  check( r.data == "cdef" && r.eof, "window transfer tail lost" );
  bool threw = false;
  try {
    ApplicationStreams bad( true, limits( 1048577 ), {} );
  } catch ( const std::invalid_argument& ) {
    threw = true;
  }
  check( threw, "unbounded local receive window allowed" );
}
}
int main()
{
  try {
    receive_and_final_size();
    ids_and_reset();
    send_and_credit();
    asymmetric_credit_and_counts();
    aggregate_admission();
    read_credit();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
