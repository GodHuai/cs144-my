#include "quic/handshake_connection.hh"
#include "quic/header_protection.hh"
#include "quic/initial_packet.hh"
#include "quic/protected_packet.hh"

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
void positive( bool reorder, bool coalesce )
{
  HandshakeConnection client { config( false ), server_address }, server { config( true ), client_address };
  require( client.state() == ConnectionState::Handshaking && server.state() == ConnectionState::WaitingInitial,
           "wrong starting states" );
  require( !client.send_ping() && !server.poll_transmit(), "premature application output" );
  const auto first = drain( client );
  require( !first.empty(), "client did not emit Initial" );
  for ( const auto& d : first ) {
    require( d.payload.size() == 1200, "Initial exceeds a 1200-byte receiver budget" );
    require( deliver( server, d, client_address ) == ConnectionReceive::Processed, "server rejected Initial" );
    require( deliver( server, d, client_address ) == ConnectionReceive::Discarded, "packet duplicate processed" );
  }
  require( server.peer_cid() == "clientid", "server guessed client CID" );
  auto flight = drain( server );
  require( flight.size() >= 2, "server Initial/Handshake flight missing" );
  require( client.peer_cid().empty(), "client guessed server CID" );
  if ( coalesce ) {
    std::string joined;
    for ( const auto& d : flight )
      joined += d.payload;
    require( client.receive( { server_address, joined, 0 } ) == ConnectionReceive::Processed,
             "coalesced flight failed" );
  } else {
    if ( reorder )
      std::reverse( flight.begin(), flight.end() );
    for ( const auto& d : flight )
      require( deliver( client, d, server_address ) != ConnectionReceive::Failed, "server flight failed" );
  }
  require( client.peer_cid() == "serverid", "actual server CID not adopted" );
  require( client.state() == ConnectionState::Established, "client TLS did not establish" );
  require( server.state() == ConnectionState::Handshaking, "server prematurely confirmed" );
  transfer( client, server, client_address );
  require( server.state() == ConnectionState::Confirmed, "server TLS completion did not confirm" );
  require( client.state() == ConnectionState::Established, "client confirmed without HANDSHAKE_DONE" );
  const auto done = drain( server );
  require( done.size() == 1, "HANDSHAKE_DONE output missing or duplicated" );
  auto damaged = done.front();
  damaged.payload.back() ^= 1;
  require( deliver( client, damaged, server_address ) == ConnectionReceive::Discarded,
           "damaged confirmation accepted" );
  require( client.state() == ConnectionState::Established, "damage changed confirmation" );
  require( deliver( client, done.front(), server_address ) == ConnectionReceive::Processed,
           "confirmation rejected" );
  require( client.state() == ConnectionState::Confirmed, "client did not confirm" );
  require( client.negotiated_alpn() == "minnow-quic" && server.negotiated_alpn() == "minnow-quic", "ALPN lost" );
  require( client.peer_parameters()->at( 0x0f ) == "serverid" && server.peer_parameters()->at( 0x0f ) == "clientid",
           "actual CID transport context lost" );
  require( client.send_ping() && server.send_ping(), "established connection cannot queue PING" );
  transfer( client, server, client_address );
  transfer( server, client, server_address );
  // Drain the immediate ACK exchange. ACK-only traffic must reach quiescence.
  for ( size_t round = 0; round < 4; ++round ) {
    transfer( client, server, client_address );
    transfer( server, client, server_address );
  }
  require( client.packets_awaiting_ack( PacketKind::OneRtt ) == 0
             && server.packets_awaiting_ack( PacketKind::OneRtt ) == 0,
           "PING/HANDSHAKE_DONE not acknowledged" );
  require( !client.poll_transmit() && !server.poll_transmit(), "ACK-only feedback loop" );
  require( client.packets_awaiting_ack( PacketKind::Initial ) == 0
             && client.packets_awaiting_ack( PacketKind::Handshake ) == 0,
           "retired packet space retains history" );
  // Initial keys/processing are retired after Handshake milestones.
  require( deliver( server, first.front(), client_address ) == ConnectionReceive::Discarded,
           "retired Initial accepted" );
}
void discarded_inputs()
{
  HandshakeConnection client { config( false ), server_address }, server { config( true ), client_address };
  const auto initial_flight = drain( client );
  auto first = initial_flight.front();
  require( deliver( server, first, server_address ) == ConnectionReceive::Discarded, "wrong source accepted" );
  auto damaged = first;
  damaged.payload.back() ^= 1;
  require( deliver( server, damaged, client_address ) == ConnectionReceive::Discarded, "bad tag accepted" );
  const auto keys = derive_initial_keys( "original" );
  const auto small = seal_initial_packet(
    keys->client, InitialSender::Client, "original", "clientid", "", 1, 4, encode_frame( PingFrame {} ) );
  require( server.receive( { client_address, small, 0 } ) == ConnectionReceive::Discarded,
           "small Initial accepted" );
  require( server.state() == ConnectionState::WaitingInitial && !server.poll_transmit(),
           "discard created server TLS" );
  deliver( server, first, client_address );
  for ( size_t i = 1; i < initial_flight.size(); ++i )
    deliver( server, initial_flight[i], client_address );
  const auto wrong = initial_packet( encode_frame( PingFrame {} ), 1, "wrongcid" );
  require( server.receive( { client_address, wrong, 0 } ) == ConnectionReceive::Discarded, "wrong CID accepted" );
  // Queue pressure before Initial keys become useful cannot create a transport error.
  const auto fake = derive_packet_keys( std::array<uint8_t, 32> {} );
  const auto future = seal_handshake_packet( fake, "clientid", "serverid", 0, 4, std::string( 2000, '\0' ) );
  for ( size_t i = 0; i < 100; ++i )
    require( client.receive( { server_address, future, 0 } ) == ConnectionReceive::Discarded,
             "future packet exposed" );
  require( !client.transport_error() && client.state() == ConnectionState::Handshaking,
           "queue pressure killed TLS" );
  for ( const auto& d : drain( server ) )
    deliver( client, d, server_address );
  require( client.state() == ConnectionState::Established, "queued invalid packets blocked real flight" );
}
void initial_ack_exchange()
{
  HandshakeConnection server { config( true ), client_address };
  const auto ping = initial_packet( encode_frame( PingFrame {} ), 2 );
  require( server.receive( { client_address, ping, 0 } ) == ConnectionReceive::Processed, "Initial PING rejected" );
  const auto output = server.poll_transmit();
  require( output && output->payload.size() == 1200, "Initial ACK size" );
  const auto keys = derive_initial_keys( "original" );
  const auto opened = open_initial_packet( keys->server, InitialSender::Server, output->payload, 0, std::nullopt );
  require( opened.has_value(), "Initial ACK authentication" );
  const auto frames = decode_frames( opened->plaintext );
  require( frames && std::holds_alternative<AckFrame>( frames->front() ), "ACK frame missing" );
  const auto& ack = std::get<AckFrame>( frames->front() );
  require( ack.ranges.size() == 1 && ack.ranges.front().smallest == 2 && ack.ranges.front().largest == 2
             && ack.ack_delay == 0,
           "wrong ACK range" );
  require( server.packets_awaiting_ack( PacketKind::Initial ) == 0 && !server.poll_transmit(), "ACK elicited ACK" );
  require( server.receive( { client_address, ping, 0 } ) == ConnectionReceive::Discarded
             && server.poll_transmit().has_value(),
           "authenticated duplicate not re-ACKed" );
  auto damaged = ping;
  damaged.back() ^= 1;
  server.receive( { client_address, damaged, 0 } );
  require( !server.poll_transmit(), "unauthenticated packet scheduled ACK" );
  // Initial protection continues to use the original DCID, not the routed CID.
  std::string payload = encode_frame( AckFrame { 0, { { 0, 1 } }, std::nullopt } );
  payload.resize( 1200, '\0' );
  const auto wire
    = seal_initial_packet( keys->client, InitialSender::Client, "serverid", "clientid", "", 3, 4, payload );
  require( server.receive( { client_address, wire, 0 } ) == ConnectionReceive::Processed && !server.poll_transmit(),
           "ACK-only input created feedback" );
}
void errors_and_close()
{
  for ( const auto mode : { 0, 1, 2, 3 } ) {
    HandshakeConnection server { config( true ), client_address };
    std::string plaintext;
    if ( mode == 0 )
      plaintext = std::string( 1, '\x1f' );
    if ( mode == 1 )
      plaintext = encode_frame( CryptoFrame { 0, "invalid TLS" } ) + encode_frame( HandshakeDoneFrame {} );
    if ( mode == 2 )
      plaintext = encode_frame( AckFrame { 0, { { 0, 0 } }, std::nullopt } );
    if ( mode == 3 )
      plaintext = encode_frame( CryptoFrame { 0, "invalid TLS" } )
                  + encode_frame( ConnectionCloseFrame { false, 0x42, 0, "bye" } );
    const auto result = server.receive( { client_address, initial_packet( plaintext ), 0 } );
    if ( mode == 3 ) {
      require( result == ConnectionReceive::Processed && server.state() == ConnectionState::Draining,
               "peer close was not terminal before TLS dispatch" );
    } else {
      require( result == ConnectionReceive::Failed && server.state() == ConnectionState::Failed,
               "invalid authenticated packet did not fail" );
      require( server.transport_error() == ( mode == 0 ? 0x07 : 0x0a ), "wrong error or non-atomic preflight" );
    }
    const auto error = server.transport_error();
    require( !server.poll_transmit() && !server.send_ping() && !server.peer_parameters(),
             "terminal output/state leaked" );
    server.receive( { client_address, initial_packet( "x", 2 ), 0 } );
    require( server.transport_error() == error, "terminal error changed" );
  }
}
void amplification_pause()
{
  auto sc = config( true );
  sc.tls.local_parameters.emplace( 0xface, std::string( 15000, 'x' ) );
  HandshakeConnection client { config( false ), server_address }, server { sc, client_address };
  const auto first = drain( client );
  size_t received_bytes = 0;
  for ( const auto& d : first ) {
    received_bytes += d.payload.size();
    deliver( server, d, client_address );
  }
  auto flight = drain( server );
  size_t sent_bytes = 0;
  for ( const auto& d : flight ) {
    sent_bytes += d.payload.size();
    deliver( client, d, server_address );
  }
  require( sent_bytes <= received_bytes * 3, "connection exceeded prevalidation cap" );
  require( client.state() == ConnectionState::Handshaking && !server.poll_transmit(),
           "large flight did not pause" );
  require( !server.poll_transmit(), "blocked polling consumed budget or created output" );
  // New UDP bytes may increase the cap even if the protected packet is a duplicate.
  for ( const auto& d : first )
    deliver( server, d, client_address );
  flight = drain( server );
  require( !flight.empty(), "credited bytes did not resume prepared packet" );
  for ( const auto& d : flight )
    deliver( client, d, server_address );
  // Re-ACKing the duplicate Initial also consumes 1200 amplification bytes.
  // Keep crediting actual arrivals until the complete large TLS flight fits.
  for ( size_t round = 0; round < 8 && client.state() == ConnectionState::Handshaking; ++round ) {
    for ( const auto& d : first ) {
      received_bytes += d.payload.size();
      deliver( server, d, client_address );
    }
    for ( const auto& d : drain( server ) ) {
      sent_bytes += d.payload.size();
      require( deliver( client, d, server_address ) != ConnectionReceive::Failed, "resumed packet failed" );
    }
  }
  require( client.state() == ConnectionState::Established, "resumed flight lost TLS bytes or PN state" );
  transfer( client, server, client_address );
  transfer( server, client, server_address );
  require( client.state() == ConnectionState::Confirmed && server.state() == ConnectionState::Confirmed,
           "amplification pause did not recover" );
}

void external_server_context( size_t mode )
{
  HandshakeConnection client { config( false ), server_address };
  auto sc = config( true ).tls;
  sc.local_parameters = { { 0x0f, mode == 0 ? "impostor" : "serverid" }, { 0x00, "original" } };
  sc.peer_initial_source_connection_id = "clientid";
  TlsHandshake server { sc };
  const auto keys = *derive_initial_keys( "original" );
  for ( const auto& d : drain( client ) ) {
    const auto opened = open_initial_packet( keys.client, InitialSender::Client, d.payload, 0, std::nullopt );
    require( opened.has_value(), "test client Initial failed" );
    const auto frames = decode_frames( opened->plaintext );
    require( frames.has_value(), "test client frames failed" );
    for ( const auto& f : *frames )
      if ( const auto* crypto = std::get_if<CryptoFrame>( &f ) )
        server.receive( PacketKind::Initial, *crypto );
    require( server.advance() != TlsProgress::Failed, "test server TLS failed" );
  }
  for ( const auto level : { PacketKind::Initial, PacketKind::Handshake } ) {
    uint64_t offset = 0, pn = 0;
    while ( const auto f = server.outgoing( level, offset, 600 ) ) {
      auto plaintext = encode_frame( *f );
      std::string wire;
      if ( level == PacketKind::Initial ) {
        plaintext.resize( 1200, '\0' );
        wire = seal_initial_packet(
          keys.server, InitialSender::Server, "clientid", "serverid", "", pn++, 4, plaintext );
      } else {
        const auto secret = server.secret( level, true );
        require( secret.has_value(), "test Handshake secret unavailable" );
        wire = seal_handshake_packet( derive_packet_keys( *secret ), "clientid", "serverid", pn++, 4, plaintext );
      }
      client.receive( { server_address, wire, 0 } );
      offset += f->data.size();
    }
  }
  if ( mode != 0 ) {
    require( client.state() == ConnectionState::Established, "external server flight did not establish" );
    const auto secret = server.secret( PacketKind::OneRtt, true );
    require( secret.has_value(), "external server application secret missing" );
    const auto payload = mode == 1 ? encode_frame( PingFrame {} ) : encode_frame( CryptoFrame { 0, "ticket" } );
    const auto wire = seal_one_rtt_packet( derive_packet_keys( *secret ), "clientid", 0, 4, payload, mode == 1 );
    client.receive( { server_address, wire, 0 } );
  }
  require( client.state() == ConnectionState::Failed && client.transport_error() == ( mode == 0 ? 0x08 : 0x01 ),
           "CID mismatch or unsupported application crypto was silently accepted" );
  require( !client.poll_transmit() && !client.peer_parameters(), "failed CID validation exposed state" );
}

void authenticated_initial_error()
{
  const auto keys = *derive_initial_keys( "original" );
  const std::string payload( 1200, '\0' );
  auto header = build_long_header( LongPacketType::Initial, "original", "clientid", "", 0, 4, payload.size() + 16 );
  header[0] = static_cast<char>( static_cast<uint8_t>( header[0] ) | 0x04 );
  const auto pn_offset = header.size() - 4;
  auto wire = header + encrypt_initial_payload( keys.client, header, 0, payload );
  const auto sample = header_protection_sample( wire, pn_offset );
  require( sample.has_value(), "reserved-bit fixture sample failed" );
  const auto mask = initial_header_mask( keys.client.hp, *sample );
  require( mask && apply_header_mask( wire, pn_offset, *mask ), "reserved-bit fixture HP failed" );
  HandshakeConnection server { config( true ), client_address };
  auto damaged = wire;
  damaged.back() ^= 1;
  require( server.receive( { client_address, damaged, 0 } ) == ConnectionReceive::Discarded
             && server.state() == ConnectionState::WaitingInitial,
           "unauthenticated reserved bits caused an error" );
  require( server.receive( { client_address, wire, 0 } ) == ConnectionReceive::Failed
             && server.transport_error() == 0x0a,
           "authenticated Initial reserved bits silently discarded" );
  require( server.receive( { client_address, initial_packet( "x", 1 ), 0 } ) == ConnectionReceive::Failed
             && server.transport_error() == 0x0a && !server.poll_transmit(),
           "reserved-bit error not sticky" );
}

void minimum_receiver( size_t cid_size )
{
  auto cc = config( false ), sc = config( true );
  cc.local_cid.assign( cid_size, 'c' );
  cc.initial_dcid.assign( cid_size, 'o' );
  sc.local_cid.assign( cid_size, 's' );
  HandshakeConnection client { cc, server_address }, server { sc, client_address };
  const auto bounded_transfer
    = []( HandshakeConnection& from, HandshakeConnection& to, const UdpEndpoint& source ) {
        for ( const auto& d : drain( from ) ) {
          require( d.payload.size() <= 1200, "minimum-size receiver drops emitted datagram" );
          const auto layout = parse_protected_packet( d.payload, 0, 0 );
          if ( layout && layout->kind == PacketKind::Initial )
            require( d.payload.size() == 1200, "Initial does not exactly fill minimum datagram" );
          require( deliver( to, d, source ) != ConnectionReceive::Failed, "minimum receiver handshake failed" );
        }
      };
  for ( size_t round = 0; round < 20 && client.state() != ConnectionState::Confirmed; ++round ) {
    bounded_transfer( client, server, client_address );
    bounded_transfer( server, client, server_address );
  }
  require( client.state() == ConnectionState::Confirmed && server.state() == ConnectionState::Confirmed,
           "minimum-size receiver handshake stalled" );
}

void invalid_config()
{
  for ( size_t mode = 0; mode < 3; ++mode ) {
    auto c = config( false );
    if ( mode == 0 )
      c.local_cid = "short";
    if ( mode == 1 )
      c.initial_dcid.assign( 21, 'x' );
    if ( mode == 2 ) {
      c.tls.server = true;
    }
    bool rejected = false;
    try {
      HandshakeConnection invalid { c, server_address };
    } catch ( const std::invalid_argument& ) {
      rejected = true;
    }
    require( rejected, "invalid connection configuration accepted" );
  }
}

void udp( std::string_view ip )
{
  UdpSocket cs { UdpEndpoint::numeric( ip, 0 ) }, ss { UdpEndpoint::numeric( ip, 0 ) };
  HandshakeConnection client { config( false ), ss.local_endpoint() },
    server { config( true ), cs.local_endpoint() };
  const auto pump = []( HandshakeConnection& from, UdpSocket& source, HandshakeConnection& to, UdpSocket& target ) {
    for ( const auto& d : drain( from ) ) {
      require( source.send( d.peer, d.payload, d.ecn.value_or( 0 ) ), "UDP send blocked" );
      pollfd ready { target.native_handle(), POLLIN, 0 };
      require( poll( &ready, 1, 2000 ) == 1, "connection UDP timeout" );
      const auto received = target.receive();
      require( received && to.receive( *received ) != ConnectionReceive::Failed, "connection UDP receive failed" );
    }
  };
  for ( size_t round = 0; round < 20 && client.state() != ConnectionState::Confirmed; ++round ) {
    pump( client, cs, server, ss );
    pump( server, ss, client, cs );
  }
  require( client.state() == ConnectionState::Confirmed && server.state() == ConnectionState::Confirmed,
           "production engine UDP handshake stalled" );
  require( client.send_ping() && server.send_ping(), "UDP PING queue failed" );
  pump( client, cs, server, ss );
  pump( server, ss, client, cs );
}
}
int main()
{
  try {
    authenticated_initial_error();
    initial_ack_exchange();
    minimum_receiver( 8 );
    minimum_receiver( 20 );
    positive( false, false );
    positive( true, false );
    positive( false, true );
    discarded_inputs();
    errors_and_close();
    amplification_pause();
    for ( size_t mode = 0; mode < 3; ++mode )
      external_server_context( mode );
    invalid_config();
    udp( "127.0.0.1" );
    udp( "::1" );
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
