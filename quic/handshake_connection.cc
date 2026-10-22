#include "handshake_connection.hh"

#include "acknowledgments.hh"
#include "anti_amplification.hh"
#include "initial_packet.hh"
#include "pacer.hh"
#include "packet_number_space.hh"
#include "packet_recovery.hh"
#include "protected_packet.hh"
#include <algorithm>
#include <chrono>

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
uint64_t default_now_us()
{
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::steady_clock::now().time_since_epoch() )
      .count() );
}
bool ack_eliciting( const Frame& frame )
{
  return !std::holds_alternative<PaddingFrame>( frame ) && !std::holds_alternative<AckFrame>( frame )
         && !std::holds_alternative<ConnectionCloseFrame>( frame );
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
  PacketAcknowledgments acks {};
  PacketRecovery recovery {};
  PacketPacer pacer {};
  std::optional<uint64_t> pacing_wakeup {};
  uint64_t last_clock {};
  bool peer_validated {}, amplification_blocked {};
  bool initial_retired {}, handshake_retired {}, done_pending {}, ping_pending {};
  std::deque<std::string> pending {};
  size_t pending_bytes {};

  uint64_t now_us()
  {
    const auto now = config.clock_us ? config.clock_us() : default_now_us();
    if ( now < last_clock )
      throw std::logic_error( "QUIC clock moved backwards" );
    last_clock = now;
    return now;
  }
  RecoveryContext recovery_context() const
  {
    RecoveryContext c;
    c.confirmed = state == ConnectionState::Confirmed;
    // Recovery asks whether the peer has validated us. Our own validation of
    // its address is a separate anti-amplification decision.
    c.peer_validated = config.tls.server || c.confirmed || peer_validated;
    if ( tls ) {
      if ( auto params = tls->peer_parameters() ) {
        c.max_ack_delay_ms = static_cast<double>( transport_parameter_integer( *params, 0x0b ).value_or( 25 ) );
        c.ack_delay_exponent = static_cast<uint8_t>( transport_parameter_integer( *params, 0x0a ).value_or( 3 ) );
      }
      if ( !config.tls.server && !c.peer_validated ) {
        if ( !handshake_retired && tls->secret( PacketKind::Handshake, true ) )
          c.validation_probe_space = PacketKind::Handshake;
        else if ( !initial_retired )
          c.validation_probe_space = PacketKind::Initial;
      }
    }
    return c;
  }
  void release_records( PacketKind kind, const std::vector<uint64_t>& numbers_to_release )
  {
    for ( const auto number : numbers_to_release )
      acks.release( kind, number );
  }
  void clear_initial()
  {
    if ( initial_retired )
      return;
    if ( initial ) {
      OPENSSL_cleanse( &*initial, sizeof( *initial ) );
      initial.reset();
    }
    initial_retired = true;
    acks.discard( PacketKind::Initial );
    recovery.discard( PacketKind::Initial );
    if ( tls )
      tls->discard_keys( PacketKind::Initial );
  }
  void clear_handshake()
  {
    if ( handshake_retired )
      return;
    handshake_retired = true;
    acks.discard( PacketKind::Handshake );
    recovery.discard( PacketKind::Handshake );
    tls->discard_keys( PacketKind::Handshake );
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
    done_pending = ping_pending = false;
    acks.discard( PacketKind::Handshake );
    recovery.discard( PacketKind::Handshake );
    acks.discard( PacketKind::OneRtt );
    recovery.discard( PacketKind::OneRtt );
  }
  void advance()
  {
    if ( tls->advance() == TlsProgress::Failed ) {
      stop( ConnectionState::Failed, tls->transport_error().value_or( 0x01 ) );
    } else if ( tls->complete() && state == ConnectionState::Handshaking ) {
      state = config.tls.server ? ConnectionState::Confirmed : ConnectionState::Established;
      if ( config.tls.server ) {
        done_pending = true;
        clear_handshake();
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
        if ( !acks.valid_ack( kind, *ack ) ) {
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
    const bool fresh = numbers.record_authenticated( kind, number );
    const auto new_largest = *numbers.largest_received( kind );
    if ( new_largest >= 4096 )
      numbers.retire_received_below( kind, new_largest - 4095 );
    const auto frames = decode_frames( plaintext );
    if ( !fresh ) {
      if ( frames ) {
        bool eliciting = false;
        for ( const auto& frame : *frames )
          eliciting = eliciting || ack_eliciting( frame );
        acks.received( kind, number, eliciting, now_us() );
      }
      return ConnectionReceive::Discarded;
    }
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
    bool eliciting = false;
    for ( const auto& frame : *frames )
      eliciting = eliciting || ack_eliciting( frame );
    acks.received( kind, number, eliciting, now_us() );
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
      if ( const auto* ack = std::get_if<AckFrame>( &frame ) ) {
        if ( kind == PacketKind::Handshake || kind == PacketKind::OneRtt )
          peer_validated = true;
        acks.apply_ack( kind, *ack );
        release_records( kind, recovery.acknowledged( kind, *ack, now_us(), recovery_context() ) );
      } else if ( const auto* crypto = std::get_if<CryptoFrame>( &frame ) ) {
        if ( !tls->receive( kind, *crypto ) ) {
          stop( ConnectionState::Failed, tls->transport_error().value_or( 0x01 ) );
          return ConnectionReceive::Failed;
        }
      } else if ( std::holds_alternative<HandshakeDoneFrame>( frame ) ) {
        state = ConnectionState::Confirmed;
        clear_handshake();
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
    pacing_wakeup.reset();
    if ( terminal( state ) || !tls )
      return std::nullopt;
    const auto exponent
      = static_cast<uint8_t>( transport_parameter_integer( config.tls.local_parameters, 0x0a ).value_or( 3 ) );
    for ( const auto kind : { PacketKind::Initial, PacketKind::Handshake, PacketKind::OneRtt } ) {
      if ( ( kind == PacketKind::Initial && initial_retired )
           || ( kind == PacketKind::Handshake && handshake_retired )
           || ( kind == PacketKind::OneRtt && !tls->complete() ) )
        continue;
      auto ack = acks.pending_ack( kind, now_us(), exponent );
      std::optional<RecoverySend> retry;
      std::optional<CryptoFrame> crypto;
      bool done = false, ping = false;
      if ( acks.can_send( kind ) ) {
        retry = recovery.pending( kind ); // Peek; a blocked poll must not consume work.
        if ( !retry && kind != PacketKind::OneRtt )
          crypto = tls->outgoing( kind, offsets[index( kind )], ack ? 400 : 600 );
        else if ( !retry && kind == PacketKind::OneRtt ) {
          done = done_pending;
          ping = !done && ping_pending;
        }
      }
      if ( !retry && !crypto && !ack && !done && !ping )
        continue;
      const auto make_payload = [&] {
        std::string payload;
        if ( ack )
          payload += encode_frame( ack->frame );
        if ( retry )
          payload += encode_frame( retry->data->frame );
        else if ( crypto )
          payload += encode_frame( *crypto );
        else if ( done )
          payload += encode_frame( HandshakeDoneFrame {} );
        else if ( ping )
          payload += encode_frame( PingFrame {} );
        return payload;
      };
      auto payload = make_payload();
      const auto wire_size = [&] {
        if ( kind == PacketKind::Initial )
          return size_t { 1200 };
        const auto header
          = kind == PacketKind::Handshake
              ? build_long_header(
                  LongPacketType::Handshake, *peer_id, config.local_cid, "", 0, 4, payload.size() + 16 )
              : build_short_header( *peer_id, 0, 4, false, false, payload.size() + 16 );
        return header.size() + payload.size() + 16;
      };
      bool eliciting = retry || crypto || done || ping;
      if ( !recovery.can_send(
             kind, wire_size(), eliciting, kind == PacketKind::Initial, retry && retry->probe ) ) {
        // ACKs must still flow while fresh data or a normal retransmit is blocked.
        if ( !ack )
          continue;
        retry.reset();
        crypto.reset();
        done = ping = eliciting = false;
        payload = make_payload();
        if ( !recovery.can_send( kind, wire_size(), false, kind == PacketKind::Initial ) )
          continue;
      }
      auto bytes = wire_size();
      if ( const auto remaining = budget.remaining_bytes(); remaining && bytes > *remaining ) {
        amplification_blocked = true;
        return std::nullopt;
      }
      const auto now = now_us();
      const auto window = recovery.congestion_stats().window;
      const auto rtt_us = recovery.rtt().smoothed_ms() * 1000;
      const auto paced = [&]() -> bool {
        if ( !eliciting && kind != PacketKind::Initial )
          return false;
        if ( retry && retry->probe )
          return false;
        const auto due = pacer.deadline( now, bytes, window, rtt_us );
        if ( !due )
          return false;
        pacing_wakeup = pacing_wakeup ? std::min( *pacing_wakeup, *due ) : *due;
        return true;
      };
      if ( paced() ) {
        if ( !ack )
          continue;
        retry.reset();
        crypto.reset();
        done = ping = eliciting = false;
        payload = make_payload();
        bytes = wire_size();
        if ( !recovery.can_send( kind, bytes, false, kind == PacketKind::Initial ) || paced() )
          continue;
      }
      const auto number = numbers.allocate( kind );
      if ( !number ) {
        stop( ConnectionState::Failed, 0x01 );
        return std::nullopt;
      }
      std::string wire;
      if ( kind == PacketKind::Initial ) {
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
      if ( wire.size() != bytes || !budget.record_sent( bytes ) )
        throw std::logic_error( "QUIC planned packet size mismatch" );
      amplification_blocked = false;
      std::shared_ptr<RecoveryData> data;
      if ( retry ) {
        const auto consumed = recovery.take_pending( kind );
        if ( !consumed || consumed->data != retry->data )
          throw std::logic_error( "QUIC recovery selection changed" );
        data = retry->data;
      } else if ( crypto )
        data = std::make_shared<RecoveryData>( *crypto );
      else if ( done )
        data = std::make_shared<RecoveryData>( HandshakeDoneFrame {} );
      else if ( ping )
        data = std::make_shared<RecoveryData>( PingFrame {} );
      acks.sent( kind, *number, eliciting );
      recovery.sent( kind, *number, now, data, bytes, kind == PacketKind::Initial );
      if ( eliciting || kind == PacketKind::Initial )
        pacer.sent( now, bytes, window, rtt_us );
      if ( ack )
        acks.ack_sent( kind, ack->generation );
      if ( crypto )
        offsets[index( kind )] += crypto->data.size();
      else if ( done )
        done_pending = false;
      else if ( ping )
        ping_pending = false;
      if ( !config.tls.server && kind == PacketKind::Handshake )
        clear_initial();
      return UdpDatagram { peer, std::move( wire ), 0 };
    }
    return std::nullopt;
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
  self.amplification_blocked = false;
  self.pacing_wakeup.reset();
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
std::optional<uint64_t> HandshakeConnection::next_timeout_us() const
{
  const auto& self = *impl_;
  if ( terminal( self.state ) || !self.tls || self.amplification_blocked )
    return std::nullopt;
  const auto loss = self.recovery.deadline( self.recovery_context() );
  if ( loss && self.pacing_wakeup )
    return std::min( *loss, *self.pacing_wakeup );
  return loss ? loss : self.pacing_wakeup;
}
void HandshakeConnection::on_timeout()
{
  auto& self = *impl_;
  if ( terminal( self.state ) || !self.tls || self.amplification_blocked )
    return;
  try {
    const auto now = self.now_us();
    if ( self.pacing_wakeup && *self.pacing_wakeup <= now )
      self.pacing_wakeup.reset();
    const auto events = self.recovery.timeout( now, self.recovery_context() );
    self.release_records( PacketKind::Initial, events[0] );
    self.release_records( PacketKind::Handshake, events[1] );
    self.release_records( PacketKind::OneRtt, events[2] );
  } catch ( ... ) {
    self.stop( ConnectionState::Failed, 0x01 );
  }
}
RttEstimator HandshakeConnection::rtt_estimate() const
{
  return impl_->recovery.rtt();
}
CongestionStats HandshakeConnection::congestion_stats() const
{
  return impl_->recovery.congestion_stats();
}
size_t HandshakeConnection::packets_awaiting_ack( PacketKind kind ) const
{
  return impl_->acks.outstanding( kind );
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
