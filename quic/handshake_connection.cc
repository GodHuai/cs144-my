#include "handshake_connection.hh"

#include "anti_amplification.hh"
#include "initial_packet.hh"
#include "packet_number_space.hh"
#include "protected_packet.hh"

#include <array>
#include <deque>
#include <openssl/crypto.h>
#include <stdexcept>
#include <utility>

namespace quic {
namespace {
size_t index( PacketKind kind )
{
  return static_cast<size_t>( packet_number_space( kind ) );
}
bool terminal( ConnectionState state )
{
  return state == ConnectionState::Failed || state == ConnectionState::Draining;
}
}
struct HandshakeConnection::Impl
{
  ConnectionConfig config;
  UdpEndpoint peer;
  ConnectionState state;
  std::optional<uint64_t> error {};
  std::optional<std::string> peer_id {};
  std::string original {};
  std::optional<InitialKeys> initial {};
  std::unique_ptr<TlsHandshake> tls {};
  PacketNumberSpaces numbers {};
  AntiAmplificationBudget budget;
  std::array<uint64_t, 2> offsets {};
  std::array<std::optional<uint64_t>, 3> sent_largest {};
  bool initial_retired {}, handshake_retired {}, done_pending {}, ping_pending {};
  std::deque<std::string> pending {};
  size_t pending_bytes {};
  struct Prepared
  {
    PacketKind kind;
    uint64_t number;
    std::string wire;
    size_t crypto_length;
    bool done;
  };
  std::optional<Prepared> prepared {};

  void clear_initial()
  {
    if ( initial ) {
      OPENSSL_cleanse( &*initial, sizeof( *initial ) );
      initial.reset();
    }
    initial_retired = true;
    if ( tls )
      tls->discard_keys( PacketKind::Initial );
    if ( prepared && prepared->kind == PacketKind::Initial )
      prepared.reset();
  }
  void stop( ConnectionState target, std::optional<uint64_t> code = std::nullopt )
  {
    if ( terminal( state ) )
      return;
    state = target;
    error = code;
    clear_initial();
    tls.reset();
    pending.clear();
    pending_bytes = 0;
    prepared.reset();
    done_pending = ping_pending = false;
  }
  void advance()
  {
    if ( tls->advance() == TlsProgress::Failed ) {
      stop( ConnectionState::Failed, tls->transport_error().value_or( 0x01 ) );
    } else if ( tls->complete() && state == ConnectionState::Handshaking ) {
      state = config.tls.server ? ConnectionState::Confirmed : ConnectionState::Established;
      if ( config.tls.server ) {
        done_pending = true;
        handshake_retired = true;
        tls->discard_keys( PacketKind::Handshake );
      }
    }
  }
  Impl( ConnectionConfig cfg, UdpEndpoint address )
    : config( std::move( cfg ) )
    , peer( address )
    , state( config.tls.server ? ConnectionState::WaitingInitial : ConnectionState::Handshaking )
    , budget( config.tls.server ? AmplificationRole::Responder : AmplificationRole::Initiator )
  {
    if ( config.local_cid.size() < 8 || config.local_cid.size() > 20
         || ( !config.tls.server && ( config.initial_dcid.size() < 8 || config.initial_dcid.size() > 20 ) )
         || ( config.tls.server && !config.initial_dcid.empty() ) )
      throw std::invalid_argument( "invalid connection CIDs" );
    config.tls.local_parameters[0x0f] = config.local_cid;
    config.tls.retry_source_connection_id.reset();
    config.tls.local_parameters.erase( 0x10 );
    if ( !config.tls.server ) {
      original = config.initial_dcid;
      initial = derive_initial_keys( original );
      config.tls.original_destination_connection_id = original;
      config.tls.peer_initial_source_connection_id.clear();
      config.tls.defer_peer_initial_source_connection_id = true;
      tls = std::make_unique<TlsHandshake>( config.tls );
      advance();
    }
  }
  ~Impl() { clear_initial(); }

  bool routes( const PacketLayout& layout ) const
  {
    if ( state == ConnectionState::WaitingInitial )
      return layout.kind == PacketKind::Initial && layout.dcid.size() >= 8;
    if ( layout.dcid != config.local_cid
         && !( config.tls.server && layout.kind == PacketKind::Initial && layout.dcid == original ) )
      return false;
    return layout.kind == PacketKind::OneRtt || !peer_id || layout.scid == *peer_id;
  }
  void buffer( std::string_view wire )
  {
    if ( pending.size() < 64 && wire.size() <= 65536 - pending_bytes ) {
      pending.emplace_back( wire );
      pending_bytes += wire.size();
    }
  }
  // Validate every frame before dispatching any CRYPTO, close or confirmation.
  bool preflight( const std::vector<Frame>& frames, PacketKind kind )
  {
    if ( frames.empty() || !frames_allowed_in_packet( frames, kind ) ) {
      stop( ConnectionState::Failed, 0x0a );
      return false;
    }
    for ( const auto& frame : frames ) {
      if ( kind == PacketKind::OneRtt && std::holds_alternative<CryptoFrame>( frame ) ) {
        stop( ConnectionState::Failed, 0x01 ); // Post-handshake TLS is not implemented yet.
        return false;
      }
      if ( std::holds_alternative<HandshakeDoneFrame>( frame )
           && ( config.tls.server || !tls || !tls->complete() ) ) {
        stop( ConnectionState::Failed, 0x0a );
        return false;
      }
      if ( const auto* ack = std::get_if<AckFrame>( &frame ) ) {
        if ( !sent_largest[index( kind )] || ack->ranges.front().largest > *sent_largest[index( kind )] ) {
          stop( ConnectionState::Failed, 0x0a );
          return false;
        }
      } else if ( !std::holds_alternative<PaddingFrame>( frame ) && !std::holds_alternative<PingFrame>( frame )
                  && !std::holds_alternative<CryptoFrame>( frame )
                  && !std::holds_alternative<HandshakeDoneFrame>( frame )
                  && !std::holds_alternative<ConnectionCloseFrame>( frame ) ) {
        stop( ConnectionState::Failed, 0x01 ); // Unsupported local feature, not a peer violation.
        return false;
      }
    }
    return true;
  }
  ConnectionReceive packet( std::string_view wire, bool may_buffer )
  {
    const auto layout = parse_protected_packet( wire, 0, config.local_cid.size() );
    if ( !layout || !routes( *layout ) || layout->kind == PacketKind::ZeroRtt )
      return ConnectionReceive::Discarded;
    const auto kind = layout->kind;
    if ( ( kind == PacketKind::Initial && initial_retired )
         || ( kind == PacketKind::Handshake && handshake_retired ) )
      return ConnectionReceive::Discarded;
    const auto largest = numbers.largest_received( kind );
    std::string plaintext;
    uint64_t number = 0;
    std::optional<InitialKeys> first_keys {};
    if ( kind == PacketKind::Initial ) {
      if ( !initial )
        first_keys = derive_initial_keys( layout->dcid );
      const auto& keys = initial ? *initial : *first_keys;
      const auto opened
        = open_initial_packet_detailed( config.tls.server ? keys.client : keys.server,
                                        config.tls.server ? InitialSender::Client : InitialSender::Server,
                                        wire,
                                        0,
                                        largest );
      if ( opened.transport_error ) {
        stop( ConnectionState::Failed, opened.transport_error );
        return ConnectionReceive::Failed;
      }
      if ( !opened.packet )
        return ConnectionReceive::Discarded;
      number = opened.packet->packet_number;
      plaintext = opened.packet->plaintext;
    } else {
      const auto secret = tls ? tls->secret( kind, false ) : std::nullopt;
      if ( !secret || ( kind == PacketKind::OneRtt && !tls->complete() ) ) {
        if ( may_buffer )
          buffer( wire );
        return ConnectionReceive::Discarded;
      }
      const auto keys = derive_packet_keys( *secret );
      const auto opened = kind == PacketKind::Handshake
                            ? open_handshake_packet( keys, wire, 0, largest )
                            : open_one_rtt_packet( keys, wire, 0, config.local_cid.size(), largest );
      if ( opened.transport_error ) {
        stop( ConnectionState::Failed, opened.transport_error );
        return ConnectionReceive::Failed;
      }
      if ( !opened.packet )
        return ConnectionReceive::Discarded;
      if ( opened.packet->key_phase ) {
        stop( ConnectionState::Failed, 0x01 ); // Key updates require the future recovery/key lifecycle layer.
        return ConnectionReceive::Failed;
      }
      number = opened.packet->packet_number;
      plaintext = opened.packet->plaintext;
    }
    // Duplicate detection precedes semantic dispatch (including late TLS data).
    if ( !numbers.record_authenticated( kind, number ) )
      return ConnectionReceive::Discarded;
    const auto new_largest = *numbers.largest_received( kind );
    if ( new_largest >= 4096 )
      numbers.retire_received_below( kind, new_largest - 4095 );
    const auto frames = decode_frames( plaintext );
    if ( !frames ) {
      stop( ConnectionState::Failed, 0x07 );
      return ConnectionReceive::Failed;
    }
    if ( !preflight( *frames, kind ) )
      return ConnectionReceive::Failed;
    for ( const auto& frame : *frames ) {
      if ( std::holds_alternative<ConnectionCloseFrame>( frame ) ) {
        stop( ConnectionState::Draining );
        return ConnectionReceive::Processed;
      }
    }
    if ( !peer_id && kind == PacketKind::Initial ) {
      peer_id = layout->scid;
      if ( config.tls.server ) {
        original = layout->dcid;
        initial = std::move( first_keys );
        config.tls.local_parameters[0x00] = original;
        config.tls.peer_initial_source_connection_id = *peer_id;
        config.tls.defer_peer_initial_source_connection_id = false;
        tls = std::make_unique<TlsHandshake>( config.tls );
        state = ConnectionState::Handshaking;
      } else if ( !tls->bind_peer_initial_source_connection_id( *peer_id ) ) {
        stop( ConnectionState::Failed, 0x01 );
        return ConnectionReceive::Failed;
      }
    }
    if ( config.tls.server && kind == PacketKind::Handshake ) {
      budget.validate_address();
      clear_initial();
    }
    for ( const auto& frame : *frames ) {
      if ( const auto* crypto = std::get_if<CryptoFrame>( &frame ) ) {
        if ( !tls->receive( kind, *crypto ) ) {
          stop( ConnectionState::Failed, tls->transport_error().value_or( 0x01 ) );
          return ConnectionReceive::Failed;
        }
      } else if ( std::holds_alternative<HandshakeDoneFrame>( frame ) ) {
        state = ConnectionState::Confirmed;
        handshake_retired = true;
        tls->discard_keys( PacketKind::Handshake );
      }
    }
    advance();
    return state == ConnectionState::Failed ? ConnectionReceive::Failed : ConnectionReceive::Processed;
  }
  void replay()
  {
    // A successful pass may reveal keys for a packet encountered earlier.
    bool progress = true;
    while ( progress && !pending.empty() && !terminal( state ) ) {
      progress = false;
      auto saved = std::move( pending );
      pending.clear();
      pending_bytes = 0;
      for ( const auto& wire : saved ) {
        const auto layout = parse_protected_packet( wire, 0, config.local_cid.size() );
        if ( !layout || ( layout->kind == PacketKind::Handshake && handshake_retired ) )
          continue;
        const auto secret = tls ? tls->secret( layout->kind, false ) : std::nullopt;
        if ( !secret || ( layout->kind == PacketKind::OneRtt && !tls->complete() ) ) {
          buffer( wire );
        } else {
          progress = packet( wire, false ) == ConnectionReceive::Processed || progress;
        }
        if ( terminal( state ) )
          break;
      }
    }
  }
  std::optional<UdpDatagram> transmit()
  {
    if ( terminal( state ) || !tls )
      return std::nullopt;
    if ( !prepared ) {
      std::optional<CryptoFrame> crypto {};
      PacketKind kind = PacketKind::OneRtt;
      for ( const auto level : { PacketKind::Initial, PacketKind::Handshake } ) {
        if ( ( level == PacketKind::Initial && initial_retired )
             || ( level == PacketKind::Handshake && handshake_retired ) )
          continue;
        crypto = tls->outgoing( level, offsets[index( level )], 600 );
        if ( crypto ) {
          kind = level;
          break;
        }
      }
      if ( !crypto && !done_pending && !ping_pending )
        return std::nullopt;
      const auto number = numbers.allocate( kind );
      if ( !number ) {
        stop( ConnectionState::Failed, 0x01 );
        return std::nullopt;
      }
      auto payload = crypto
                       ? encode_frame( *crypto )
                       : ( done_pending ? encode_frame( HandshakeDoneFrame {} ) : encode_frame( PingFrame {} ) );
      std::string wire;
      if ( kind == PacketKind::Initial ) {
        // Size the final protected UDP payload, including the two-byte Length,
        // full header, packet number and AEAD tag. Our <=600-byte CRYPTO
        // fragments always leave room for padding even with 20-byte CIDs.
        const auto header = build_long_header(
          LongPacketType::Initial, peer_id.value_or( original ), config.local_cid, "", *number, 4, 1200 );
        payload.resize( 1200 - header.size() - 16, '\0' );
        wire = seal_initial_packet( config.tls.server ? initial->server : initial->client,
                                    config.tls.server ? InitialSender::Server : InitialSender::Client,
                                    peer_id.value_or( original ),
                                    config.local_cid,
                                    "",
                                    *number,
                                    4,
                                    payload );
      } else {
        const auto secret = tls->secret( kind, true );
        if ( !secret ) {
          stop( ConnectionState::Failed, 0x01 );
          return std::nullopt;
        }
        const auto keys = derive_packet_keys( *secret );
        wire = kind == PacketKind::Handshake
                 ? seal_handshake_packet( keys, *peer_id, config.local_cid, *number, 4, payload )
                 : seal_one_rtt_packet( keys, *peer_id, *number, 4, payload );
      }
      prepared
        = Prepared { kind, *number, std::move( wire ), crypto ? crypto->data.size() : 0, !crypto && done_pending };
    }
    if ( !budget.record_sent( prepared->wire.size() ) )
      return std::nullopt;
    auto output = std::move( *prepared );
    prepared.reset();
    sent_largest[index( output.kind )] = output.number;
    if ( output.crypto_length )
      offsets[index( output.kind )] += output.crypto_length;
    else if ( output.done )
      done_pending = false;
    else
      ping_pending = false;
    if ( !config.tls.server && output.kind == PacketKind::Handshake )
      clear_initial();
    return UdpDatagram { peer, std::move( output.wire ), 0 };
  }
};
HandshakeConnection::HandshakeConnection( ConnectionConfig config, UdpEndpoint peer )
  : impl_( std::make_unique<Impl>( std::move( config ), peer ) )
{}
HandshakeConnection::~HandshakeConnection() = default;
ConnectionReceive HandshakeConnection::receive( const UdpDatagram& datagram )
{
  auto& self = *impl_;
  if ( terminal( self.state ) )
    return self.state == ConnectionState::Failed ? ConnectionReceive::Failed : ConnectionReceive::Discarded;
  if ( datagram.peer != self.peer )
    return ConnectionReceive::Discarded;
  const auto first = parse_protected_packet( datagram.payload, 0, self.config.local_cid.size() );
  if ( !first || !self.routes( *first ) )
    return ConnectionReceive::Discarded;
  if ( self.config.tls.server && datagram.payload.size() < 1200 && first->kind == PacketKind::Initial )
    return ConnectionReceive::Discarded;
  self.budget.record_received( datagram.payload.size() );
  bool processed = false;
  try {
    size_t offset = 0;
    while ( offset < datagram.payload.size() ) {
      const auto layout = parse_protected_packet( datagram.payload, offset, self.config.local_cid.size() );
      if ( !layout )
        break;
      if ( !( self.config.tls.server && layout->kind == PacketKind::Initial && datagram.payload.size() < 1200 ) ) {
        const auto result = self.packet(
          std::string_view { datagram.payload }.substr( offset, layout->packet_end - offset ), true );
        processed = processed || result == ConnectionReceive::Processed;
      }
      if ( terminal( self.state ) )
        break;
      offset = layout->packet_end;
    }
    if ( !terminal( self.state ) )
      self.replay();
  } catch ( ... ) {
    self.stop( ConnectionState::Failed, 0x01 );
  }
  if ( self.state == ConnectionState::Failed )
    return ConnectionReceive::Failed;
  return processed ? ConnectionReceive::Processed : ConnectionReceive::Discarded;
}
std::optional<UdpDatagram> HandshakeConnection::poll_transmit()
{
  try {
    return impl_->transmit();
  } catch ( ... ) {
    impl_->stop( ConnectionState::Failed, 0x01 );
    return std::nullopt;
  }
}
bool HandshakeConnection::send_ping()
{
  if ( impl_->state != ConnectionState::Established && impl_->state != ConnectionState::Confirmed )
    return false;
  impl_->ping_pending = true;
  return true;
}
ConnectionState HandshakeConnection::state() const
{
  return impl_->state;
}
std::optional<uint64_t> HandshakeConnection::transport_error() const
{
  return impl_->error;
}
std::string HandshakeConnection::peer_cid() const
{
  return impl_->peer_id.value_or( "" );
}
std::optional<TransportParameters> HandshakeConnection::peer_parameters() const
{
  return impl_->tls ? impl_->tls->peer_parameters() : std::nullopt;
}
std::string HandshakeConnection::negotiated_alpn() const
{
  return impl_->tls ? impl_->tls->negotiated_alpn() : "";
}
} // namespace quic
