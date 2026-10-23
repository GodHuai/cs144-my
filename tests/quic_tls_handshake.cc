#include "quic/tls_handshake.hh"

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace quic;

namespace {
void require( bool ok, std::string_view message )
{
  if ( !ok ) {
    throw std::runtime_error( std::string { message } );
  }
}

TlsConfig config( bool server )
{
  TlsConfig result;
  result.server = server;
  result.alpn = "minnow-quic";
  result.server_name = "localhost";
  result.ca_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.pem";
  result.certificate_file = result.ca_file;
  result.private_key_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/server.key";
  result.local_parameters = { { 0x0f, server ? "server" : "client" } };
  result.peer_initial_source_connection_id = server ? "client" : "server";
  if ( server ) {
    result.local_parameters.emplace( 0x00, "original" );
  } else {
    result.original_destination_connection_id = "original";
  }
  return result;
}

// Retain offsets as a packetizer would, reverse fragments and replay each one.
// Deliver Handshake before Initial to exercise future-level buffering.
void transfer( const TlsHandshake& from, TlsHandshake& to, std::array<uint64_t, 3>& offsets )
{
  const std::array levels { PacketKind::Handshake, PacketKind::Initial, PacketKind::OneRtt };
  for ( size_t i = 0; i < levels.size(); ++i ) {
    std::vector<CryptoFrame> fragments;
    while ( const auto frame = from.outgoing( levels[i], offsets[i], 37 ) ) {
      offsets[i] += frame->data.size();
      fragments.push_back( *frame );
    }
    for ( auto it = fragments.rbegin(); it != fragments.rend(); ++it ) {
      if ( !to.receive( levels[i], *it ) ) {
        return;
      }
      require( to.receive( levels[i], *it ), "identical CRYPTO duplicate rejected" );
    }
  }
}

void run( TlsHandshake& client, TlsHandshake& server )
{
  std::array<uint64_t, 3> client_offsets {}, server_offsets {};
  for ( size_t round = 0; round < 50; ++round ) {
    client.advance();
    transfer( client, server, client_offsets );
    server.advance();
    transfer( server, client, server_offsets );
    if ( client.failed() || server.failed() || ( client.complete() && server.complete() ) ) {
      return;
    }
  }
  throw std::runtime_error( "handshake made no progress" );
}

void success()
{
  TlsHandshake client { config( false ) }, server { config( true ) };
  require( client.advance() == TlsProgress::NeedData, "client skipped peer authentication" );
  require( !client.complete(), "premature completion" );
  run( client, server );
  require( client.complete() && server.complete(), "trusted handshake did not complete" );
  require( client.negotiated_alpn() == "minnow-quic" && server.negotiated_alpn() == "minnow-quic",
           "ALPN not negotiated" );
  require( client.peer_parameters() == config( true ).local_parameters, "server parameters lost" );
  require( server.peer_parameters() == config( false ).local_parameters, "client parameters lost" );
  for ( const auto level : { PacketKind::Handshake, PacketKind::OneRtt } ) {
    require( client.secret( level, true ).has_value(), "client write secret missing" );
    require( client.secret( level, false ).has_value(), "client read secret missing" );
    require( client.secret( level, true ) == server.secret( level, false ), "client write secret differs" );
    require( client.secret( level, false ) == server.secret( level, true ), "server write secret differs" );
    require( client.secret( level, true ) != client.secret( level, false ), "directions share secret" );
  }
  require( !client.secret( PacketKind::Initial, true ) && !client.secret( PacketKind::ZeroRtt, true ),
           "unsupported secret exposed" );
  require( client.advance() == TlsProgress::Complete, "completion not stable" );
}

void connection_context()
{
  auto cc = config( false );
  cc.defer_peer_initial_source_connection_id = true;
  cc.peer_initial_source_connection_id.clear();
  TlsHandshake client { cc }, server { config( true ) };
  require( !client.bind_peer_initial_source_connection_id( std::string( 21, 'x' ) ), "oversize CID bound" );
  client.advance();
  require( client.bind_peer_initial_source_connection_id( "server" ), "actual Initial CID not bound" );
  require( !client.bind_peer_initial_source_connection_id( "other" ), "peer CID rebound" );
  require( !server.bind_peer_initial_source_connection_id( "client" ), "nondeferred CID rebound" );
  run( client, server );
  require( client.complete() && server.complete(), "deferred CID handshake failed" );
  client.discard_keys( PacketKind::Initial );
  require( !client.outgoing( PacketKind::Initial, 0, 100 ), "retired CRYPTO still exposed" );
  client.discard_keys( PacketKind::Handshake );
  require( !client.secret( PacketKind::Handshake, true ) && !client.secret( PacketKind::Handshake, false ),
           "retired Handshake secrets still exposed" );
  require( client.secret( PacketKind::OneRtt, true ).has_value() && client.complete(),
           "retirement lost 1-RTT state" );
  bool rejected = false;
  try {
    client.discard_keys( PacketKind::OneRtt );
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "application keys retired through handshake API" );
  TlsHandshake unbound { cc }, peer { config( true ) };
  run( unbound, peer );
  require( unbound.failed() && unbound.transport_error() == 0x08, "unbound peer parameters accepted" );
  require( !unbound.bind_peer_initial_source_connection_id( "server" ), "failed context allowed binding" );
}

void terminal( TlsHandshake& failed )
{
  require( failed.failed() && !failed.complete(), "failure reported as completion" );
  require( failed.advance() == TlsProgress::Failed, "failure not terminal" );
  require( !failed.receive( PacketKind::Initial, { 0, "x" } ), "failed TLS accepted input" );
  require( !failed.outgoing( PacketKind::Initial, 0, 100 ), "failed TLS still exposes output" );
  require( !failed.secret( PacketKind::Handshake, true ) && !failed.secret( PacketKind::OneRtt, false ),
           "failed TLS exposes secrets" );
  require( failed.negotiated_alpn().empty() && !failed.peer_parameters(), "failed TLS exposes negotiated state" );
}

void write_observer_exception()
{
  bool observed = false;
  TlsHandshake client { config( false ) };
  TlsHandshake server { config( true ), 65536, 65536, [&]( PacketKind kind, const std::array<uint8_t, 32>& ) {
                         require( kind == PacketKind::Handshake, "observer reported unexpected level" );
                         observed = true;
                         throw std::runtime_error( "observer failure" );
                       } };
  run( client, server );
  require( observed, "write observer not invoked" );
  terminal( server );
  require( server.transport_error() == 1, "observer exception not contained" );
}
void failures()
{
  for ( size_t mode = 0; mode < 4; ++mode ) {
    auto cc = config( false );
    auto sc = config( true );
    if ( mode == 0 ) {
      cc.ca_file = std::string { QUIC_TLS_TEST_CERT_DIR } + "/other.pem";
    } else if ( mode == 1 ) {
      cc.server_name = "wrong.example";
    } else if ( mode == 2 ) {
      sc.alpn = "different";
    } else {
      cc.peer_initial_source_connection_id = "wrong";
    }
    TlsHandshake client { cc }, server { sc };
    run( client, server );
    auto& failed = mode == 2 ? server : client;
    terminal( failed );
    const auto error = failed.transport_error();
    require( error.has_value(), "failure lacks QUIC transport error" );
    require( mode == 3 ? *error == 0x08 : *error >= 0x100, "wrong transport error classification" );
  }
  TlsHandshake early { config( false ) };
  require( !early.receive( PacketKind::ZeroRtt, { 0, "x" } ), "0-RTT CRYPTO accepted" );
  terminal( early );
  TlsHandshake receive_limit { config( false ), 4096 };
  require( !receive_limit.receive( PacketKind::Handshake, { 1, std::string( 4097, 'x' ) } ),
           "receive capacity ignored" );
  require( receive_limit.transport_error() == 0x0d, "receive overflow mapping" );
  terminal( receive_limit );
  TlsHandshake send_limit { config( false ), 65536, 1 };
  send_limit.advance();
  require( send_limit.transport_error() == 0x01, "send overflow not terminal" );
  terminal( send_limit );
  TlsHandshake conflict { config( false ) };
  require( conflict.receive( PacketKind::Handshake, { 1, "abc" } ), "buffer failed" );
  require( !conflict.receive( PacketKind::Handshake, { 2, "X" } ), "conflicting overlap accepted" );
  require( conflict.transport_error() == 0x0a, "conflict mapping" );
  terminal( conflict );
}

void incremental()
{
  TlsHandshake client { config( false ) }, server { config( true ) };
  std::array<uint64_t, 2> client_offsets {}, server_offsets {};
  const std::array levels { PacketKind::Initial, PacketKind::Handshake };
  for ( size_t round = 0; round < 50; ++round ) {
    client.advance();
    server.advance();
    for ( size_t i = 0; i < levels.size(); ++i ) {
      while ( const auto frame = client.outgoing( levels[i], client_offsets[i], 13 ) ) {
        client_offsets[i] += frame->data.size();
        require( server.receive( levels[i], *frame ), "incremental server receive failed" );
        require( server.advance() != TlsProgress::Failed, "incremental server TLS failed" );
      }
      while ( const auto frame = server.outgoing( levels[i], server_offsets[i], 13 ) ) {
        server_offsets[i] += frame->data.size();
        require( client.receive( levels[i], *frame ), "incremental client receive failed" );
        require( client.advance() != TlsProgress::Failed, "incremental client TLS failed" );
      }
    }
    if ( client.complete() && server.complete() )
      return;
  }
  throw std::runtime_error( "incremental TLS stalled" );
}

void level_boundaries()
{
  // An old-level gap cannot survive TLS moving to its next read level.
  TlsHandshake client { config( false ) }, server { config( true ) };
  require( server.receive( PacketKind::Initial, { 10000, "extra" } ), "gap setup failed" );
  run( client, server );
  require( server.transport_error() == 0x0a, "old-level buffered data ignored at TLS transition" );
  terminal( server );

  TlsHandshake extra_client { config( false ) }, extra_server { config( true ) };
  extra_client.advance();
  auto hello = extra_client.outgoing( PacketKind::Initial, 0, 65536 );
  require( hello.has_value(), "ClientHello missing" );
  hello->data += "x";
  require( extra_server.receive( PacketKind::Initial, *hello ), "contiguous setup failed" );
  extra_server.advance();
  require( extra_server.transport_error() == 0x0a, "old-level contiguous surplus not rejected" );
  terminal( extra_server );

  // Once complete, old-level retransmissions remain valid, but new bytes do not.
  TlsHandshake next_client { config( false ) }, next_server { config( true ) };
  run( next_client, next_server );
  require( next_client.complete() && next_server.complete(), "boundary handshake failed" );
  for ( const auto level : { PacketKind::Initial, PacketKind::Handshake } ) {
    const auto frame = next_client.outgoing( level, 0, 65536 );
    require( frame.has_value(), "old-level output missing" );
    require( next_server.receive( level, *frame ), "old-level retransmission rejected" );
  }
  require( !next_server.receive( PacketKind::Initial, { 10000, "new" } ), "late old-level bytes accepted" );
  require( next_server.transport_error() == 0x0a, "late old-level error mapping" );
  terminal( next_server );
}

void configuration()
{
  for ( size_t mode = 0; mode < 7; ++mode ) {
    auto cc = config( false );
    if ( mode == 0 )
      cc.server_name.clear();
    if ( mode == 1 )
      cc.ca_file.clear();
    if ( mode == 2 )
      cc.alpn.clear();
    if ( mode == 3 )
      cc.alpn.assign( 256, 'x' );
    if ( mode == 4 )
      cc.server_name = std::string { "local\0host", 10 };
    if ( mode == 5 )
      cc.local_parameters.erase( 0x0f );
    if ( mode == 6 )
      cc.local_parameters.emplace( 0x00, "forbidden-client-parameter" );
    bool rejected = false;
    try {
      TlsHandshake invalid { cc };
    } catch ( const std::invalid_argument& ) {
      rejected = true;
    }
    require( rejected, "unsafe client configuration accepted" );
  }
  auto sc = config( true );
  sc.private_key_file.clear();
  bool rejected = false;
  try {
    TlsHandshake invalid { sc };
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "server without key accepted" );
  // Destroy with a partial TLS record still retained by OpenSSL.
  TlsHandshake partial { config( true ) };
  require( partial.receive( PacketKind::Initial, { 0, std::string { "\x01\x00", 2 } } ), "partial input failed" );
  require( partial.advance() == TlsProgress::NeedData, "partial TLS record treated as fatal" );
}
} // namespace

int main()
{
  try {
    success();
    connection_context();
    write_observer_exception();
    failures();
    configuration();
    level_boundaries();
    incremental();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
