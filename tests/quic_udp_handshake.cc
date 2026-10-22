#include "quic/anti_amplification.hh"
#include "quic/initial_packet.hh"
#include "quic/packet_number_space.hh"
#include "quic/protected_packet.hh"
#include "quic/tls_handshake.hh"
#include "quic/udp_socket.hh"

#include <array>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string_view>

using namespace quic;
namespace {
void require( bool ok, std::string_view message )
{
  if ( !ok )
    throw std::runtime_error( std::string { message } );
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
  if ( server )
    result.local_parameters.emplace( 0x00, "original" );
  else
    result.original_destination_connection_id = "original";
  return result;
}
// Integration harness only: fixed CIDs and peer address, no loss/recovery,
// application streams, listener, timer or general connection state machine.
struct Endpoint
{
  bool server;
  UdpSocket socket;
  TlsHandshake tls;
  PacketNumberSpaces numbers {};
  AntiAmplificationBudget budget;
  std::array<uint64_t, 2> offsets {};
  size_t received_initials {}, received_handshakes {}, received_application {};
  bool confirmed {};
  Endpoint( bool is_server, std::string_view ip )
    : server( is_server )
    , socket( UdpEndpoint::numeric( ip, 0 ) )
    , tls( config( is_server ) )
    , budget( is_server ? AmplificationRole::Responder : AmplificationRole::Initiator )
  {}
};
UdpDatagram exchange( Endpoint& from, Endpoint& to, const std::string& wire )
{
  require( from.budget.record_sent( wire.size() ), "server exceeded amplification budget" );
  require( from.socket.send( to.socket.local_endpoint(), wire, 2 ), "UDP would block" );
  pollfd ready { to.socket.native_handle(), POLLIN, 0 };
  require( poll( &ready, 1, 2000 ) == 1, "UDP handshake datagram timed out" );
  auto datagram = to.socket.receive();
  require( datagram && datagram->peer == from.socket.local_endpoint(), "UDP handshake source changed" );
  require( datagram->ecn == 2 && datagram->payload == wire, "UDP handshake bytes/ECN changed" );
  to.budget.record_received( datagram->payload.size() );
  return std::move( *datagram );
}
void transmit_crypto( Endpoint& from, Endpoint& to, const InitialKeys& initial )
{
  const std::array levels { PacketKind::Initial, PacketKind::Handshake };
  for ( size_t level = 0; level < levels.size(); ++level ) {
    const auto kind = levels[level];
    while ( const auto crypto = from.tls.outgoing( kind, from.offsets[level], 257 ) ) {
      auto plaintext = encode_frame( *crypto );
      const auto number = from.numbers.allocate( kind );
      require( number.has_value(), "packet number exhausted" );
      const auto& initial_key = from.server ? initial.server : initial.client;
      std::string wire;
      if ( kind == PacketKind::Initial ) {
        plaintext.resize( 1200, '\0' );
        wire = seal_initial_packet( initial_key,
                                    from.server ? InitialSender::Server : InitialSender::Client,
                                    from.server ? "client" : "original",
                                    from.server ? "server" : "client",
                                    "",
                                    *number,
                                    2,
                                    plaintext );
      } else {
        const auto secret = from.tls.secret( kind, true );
        require( secret.has_value(), "Handshake write keys unavailable" );
        wire = seal_handshake_packet( derive_packet_keys( *secret ),
                                      from.server ? "client" : "server",
                                      from.server ? "server" : "client",
                                      *number,
                                      2,
                                      plaintext );
      }
      const auto received = exchange( from, to, wire );
      uint64_t packet_number = 0;
      std::string authenticated;
      const auto largest = to.numbers.largest_received( kind );
      if ( kind == PacketKind::Initial ) {
        require( received.payload.size() >= 1200, "Initial datagram below QUIC minimum" );
        const auto opened = open_initial_packet(
          initial_key, from.server ? InitialSender::Server : InitialSender::Client, received.payload, 0, largest );
        require( opened.has_value(), "UDP Initial authentication failed" );
        require( opened->layout.dcid == ( to.server ? "original" : "client" )
                   && opened->layout.scid == ( from.server ? "server" : "client" ),
                 "Initial CID mismatch" );
        packet_number = opened->packet_number;
        authenticated = opened->plaintext;
        ++to.received_initials;
      } else {
        const auto secret = to.tls.secret( kind, false );
        require( secret.has_value(), "Handshake read keys unavailable" );
        const auto opened = open_handshake_packet( derive_packet_keys( *secret ), received.payload, 0, largest );
        require( opened.packet.has_value(), "UDP Handshake authentication failed" );
        require( opened.packet->layout.dcid == ( to.server ? "server" : "client" ), "Handshake CID mismatch" );
        packet_number = opened.packet->packet_number;
        authenticated = opened.packet->plaintext;
        // RFC 9000 8.1: successfully processing a Handshake packet validates
        // the client's address. Never lift the cap on unauthenticated traffic.
        if ( to.server )
          to.budget.validate_address();
        ++to.received_handshakes;
      }
      const auto frames = decode_frames( authenticated );
      require( frames && frames_allowed_in_packet( *frames, kind ), "illegal authenticated frames" );
      require( to.numbers.record_authenticated( kind, packet_number ), "unexpected duplicate PN" );
      for ( const auto& frame : *frames ) {
        if ( const auto* fragment = std::get_if<CryptoFrame>( &frame ) )
          require( to.tls.receive( kind, *fragment ), "UDP CRYPTO rejected" );
      }
      require( to.tls.advance() != TlsProgress::Failed, "UDP TLS handshake failed" );
      from.offsets[level] += crypto->data.size();
    }
  }
}
void control_packet( Endpoint& from, Endpoint& to, bool handshake_done )
{
  const auto write = from.tls.secret( PacketKind::OneRtt, true );
  const auto read = to.tls.secret( PacketKind::OneRtt, false );
  require( write && read, "1-RTT keys unavailable after TLS completion" );
  const Frame frame = handshake_done ? Frame { HandshakeDoneFrame {} } : Frame { PingFrame {} };
  auto payload = encode_frame( frame );
  payload.resize( 3, '\0' );
  const auto number = from.numbers.allocate( PacketKind::OneRtt );
  require( number.has_value(), "application PN exhausted" );
  const auto wire
    = seal_one_rtt_packet( derive_packet_keys( *write ), from.server ? "client" : "server", *number, 2, payload );
  const auto received = exchange( from, to, wire );
  const auto largest = to.numbers.largest_received( PacketKind::OneRtt );
  // Damage must not create a state transition or expose HANDSHAKE_DONE.
  auto damaged = received.payload;
  damaged.back() ^= 1;
  const auto rejected = open_one_rtt_packet( derive_packet_keys( *read ), damaged, 0, 6, largest );
  require( !rejected.packet && !rejected.transport_error, "unauthenticated control frame exposed" );
  const auto opened = open_one_rtt_packet( derive_packet_keys( *read ), received.payload, 0, 6, largest );
  require( opened.packet && opened.packet->layout.dcid == ( to.server ? "server" : "client" ),
           "UDP 1-RTT authentication/routing failed" );
  const auto frames = decode_frames( opened.packet->plaintext );
  require( frames && frames_allowed_in_packet( *frames, PacketKind::OneRtt ) && !frames->empty(),
           "invalid UDP 1-RTT frames" );
  require( to.numbers.record_authenticated( PacketKind::OneRtt, opened.packet->packet_number ),
           "duplicate control PN" );
  require( !to.numbers.record_authenticated( PacketKind::OneRtt, opened.packet->packet_number ),
           "application duplicate was accepted twice" );
  if ( handshake_done ) {
    require( from.server && !to.server && std::holds_alternative<HandshakeDoneFrame>( frames->front() ),
             "HANDSHAKE_DONE direction or contents invalid" );
    to.confirmed = true;
  } else {
    require( std::holds_alternative<PingFrame>( frames->front() ), "1-RTT PING changed" );
  }
  ++to.received_application;
}
void loopback( std::string_view ip )
{
  Endpoint client { false, ip }, server { true, ip };
  const auto initial = derive_initial_keys( "original" );
  require( initial.has_value(), "Initial derivation failed" );
  require( server.budget.remaining_bytes() == 0 && !server.budget.address_validated(),
           "responder started without amplification cap" );
  for ( size_t round = 0; round < 50 && !( client.tls.complete() && server.tls.complete() ); ++round ) {
    require( client.tls.advance() != TlsProgress::Failed, "client TLS start failed" );
    transmit_crypto( client, server, *initial );
    transmit_crypto( server, client, *initial );
  }
  require( client.tls.complete() && server.tls.complete(), "real UDP TLS handshake stalled" );
  require( client.tls.negotiated_alpn() == "minnow-quic" && server.tls.negotiated_alpn() == "minnow-quic",
           "UDP TLS ALPN negotiation failed" );
  require( client.tls.peer_parameters() == std::optional { config( true ).local_parameters }
             && server.tls.peer_parameters() == std::optional { config( false ).local_parameters },
           "UDP peer transport parameters changed" );
  require( client.received_initials && server.received_initials && client.received_handshakes
             && server.received_handshakes,
           "handshake skipped a packet number space" );
  require( server.budget.address_validated() && !server.budget.remaining_bytes(),
           "authenticated client Handshake did not validate address" );
  require( !client.confirmed, "TLS completion incorrectly implied client QUIC confirmation" );
  control_packet( server, client, true );
  control_packet( client, server, false );
  control_packet( server, client, false );
  require( client.confirmed && client.received_application == 2 && server.received_application == 1,
           "UDP 1-RTT confirmation/control exchange failed" );
  require( !client.socket.receive() && !server.socket.receive(), "handshake left queued UDP datagrams" );
}
}
int main()
{
  try {
    loopback( "127.0.0.1" );
    loopback( "::1" );
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
