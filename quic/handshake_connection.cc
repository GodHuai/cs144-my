#include "handshake_connection.hh"

#include "acknowledgments.hh"
#include "anti_amplification.hh"
#include "initial_packet.hh"
#include "pacer.hh"
#include "packet_number_space.hh"
#include "packet_recovery.hh"
#include "protected_packet.hh"
#include "varint.hh"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

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
  return state == ConnectionState::Failed || state == ConnectionState::Draining || state == ConnectionState::Closing
         || state == ConnectionState::Closed;
}
uint64_t add_time( uint64_t base, uint64_t interval )
{
  return base + std::min( interval, std::numeric_limits<uint64_t>::max() - base );
}
struct WriteSecrets
{
  std::array<std::optional<std::array<uint8_t, 32>>, 2> keys {};
  void clear( size_t slot ) noexcept
  {
    if ( keys[slot] ) {
      OPENSSL_cleanse( keys[slot]->data(), keys[slot]->size() );
      keys[slot].reset();
    }
  }
  void clear() noexcept
  {
    clear( 0 );
    clear( 1 );
  }
  ~WriteSecrets() { clear(); }
};
struct PacketKeysGuard
{
  PacketProtectionKeys value;
  ~PacketKeysGuard() { OPENSSL_cleanse( &value, sizeof( value ) ); }
};

}
struct HandshakeConnection::Impl
{
  ConnectionConfig config;
  UdpEndpoint peer;
  ConnectionState state;
  std::optional<uint64_t> error {};
  std::optional<ConnectionCloseFrame> closing_info {};
  std::optional<PacketLayout> authenticated_route {};
  std::optional<uint64_t> end_deadline {};
  std::string close_wire {};
  uint64_t attributed_received {}, close_sent {}, close_response_after {}, close_interval {};
  bool close_pending {};
  uint64_t last_activity {};
  bool idle_send_reset = true;

  std::optional<std::string> peer_id {};
  std::string original {};
  std::optional<InitialKeys> initial {};
  WriteSecrets write_secrets {}; // Outlives TLS, including constructor unwind.
  std::unique_ptr<TlsHandshake> tls {};
  PacketNumberSpaces numbers {};
  AntiAmplificationBudget budget;
  std::array<uint64_t, 2> offsets {};
  PacketAcknowledgments acks {};
  PacketRecovery recovery {};
  PacketPacer pacer {};
  std::unique_ptr<ApplicationStreams> streams {};
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
  uint64_t base_pto_us() const
  {
    const auto context = recovery_context();
    const double ms
      = recovery.rtt().pto_ms( context.confirmed, context.confirmed, context.max_ack_delay_ms ).value();
    const auto us = std::ceil( ms * 1000 );
    return us >= static_cast<double>( std::numeric_limits<uint64_t>::max() ) ? std::numeric_limits<uint64_t>::max()
                                                                             : static_cast<uint64_t>( us );
  }
  uint64_t three_pto_us() const
  {
    const auto pto = base_pto_us();
    return pto > std::numeric_limits<uint64_t>::max() / 3 ? std::numeric_limits<uint64_t>::max() : 3 * pto;
  }
  std::optional<uint64_t> idle_deadline() const
  {
    if ( terminal( state ) )
      return std::nullopt;
    auto ms = transport_parameter_integer( config.tls.local_parameters, 0x01 ).value_or( 0 );
    if ( tls ) {
      if ( const auto parameters = tls->peer_parameters() ) {
        const auto peer_ms = transport_parameter_integer( *parameters, 0x01 ).value_or( 0 );
        if ( peer_ms && ( !ms || peer_ms < ms ) )
          ms = peer_ms;
      }
    }
    if ( !ms )
      return std::nullopt;
    const auto us
      = ms > std::numeric_limits<uint64_t>::max() / 1000 ? std::numeric_limits<uint64_t>::max() : ms * 1000;
    return add_time( last_activity, std::max( us, three_pto_us() ) );
  }
  bool expire( uint64_t now )
  {
    if ( end_deadline && now >= *end_deadline ) {
      state = ConnectionState::Closed;
      end_deadline.reset();
      close_wire.clear();
      close_pending = false;
      return true;
    }
    if ( const auto idle = idle_deadline(); idle && now >= *idle ) {
      stop( ConnectionState::Closed );
      return true;
    }
    return state == ConnectionState::Closed;
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
    write_secrets.clear( 0 );
    acks.discard( PacketKind::Handshake );
    recovery.discard( PacketKind::Handshake );
    tls->discard_keys( PacketKind::Handshake );
  }
  void stop( ConnectionState target, std::optional<uint64_t> code = std::nullopt )
  {
    if ( terminal( state ) )
      return;
    if ( target == ConnectionState::Draining || target == ConnectionState::Closing )
      end_deadline = add_time( now_us(), three_pto_us() );
    state = target;
    error = code;
    pacing_wakeup.reset();
    clear_initial();
    tls.reset();
    write_secrets.clear();
    streams.reset();
    pending.clear();
    pending_bytes = 0;
    done_pending = ping_pending = false;
    acks.discard( PacketKind::Handshake );
    recovery.discard( PacketKind::Handshake );
    acks.discard( PacketKind::OneRtt );
    recovery.discard( PacketKind::OneRtt );
  }
  std::unique_ptr<TlsHandshake> make_tls()
  {
    return std::make_unique<TlsHandshake>(
      config.tls, 65536, 65536, [this]( PacketKind kind, const std::array<uint8_t, 32>& secret ) {
        if ( kind == PacketKind::Handshake && handshake_retired )
          return;
        const size_t slot = kind == PacketKind::Handshake ? 0 : 1;
        write_secrets.clear( slot );
        write_secrets.keys[slot] = secret;
      } );
  }
  bool begin_close( ConnectionCloseFrame frame, std::optional<uint64_t> code = std::nullopt )
  {
    const bool confirmed = state == ConnectionState::Confirmed;
    const bool use_initial = !confirmed && !initial_retired && initial;
    const bool use_handshake = !confirmed && !handshake_retired && write_secrets.keys[0];
    const bool use_application = write_secrets.keys[1].has_value();
    if ( !use_initial && !use_handshake && !use_application )
      return false;
    std::string suffix;
    const auto destination = peer_id.value_or( original );
    auto lower = frame;
    if ( lower.application )
      lower = ConnectionCloseFrame { false, 0x0c, 0, "" };
    for ( const auto kind : { PacketKind::Handshake, PacketKind::OneRtt } ) {
      if ( kind == PacketKind::Handshake ? !use_handshake : !use_application )
        continue;
      const auto number = numbers.allocate( kind );
      if ( !number )
        return false; // Exhaustion forbids ALL further packets, even lower levels.
      PacketKeysGuard keys { derive_packet_keys( *write_secrets.keys[kind == PacketKind::Handshake ? 0 : 1] ) };
      const auto payload = encode_frame( kind == PacketKind::Handshake ? lower : frame );
      suffix += kind == PacketKind::Handshake
                  ? seal_handshake_packet( keys.value, destination, config.local_cid, *number, 4, payload )
                  : seal_one_rtt_packet( keys.value, destination, *number, 4, payload );
    }
    std::string wire;
    if ( use_initial ) {
      const auto number = numbers.allocate( PacketKind::Initial );
      if ( !number )
        return false;
      const auto initial_bytes = 1200 - suffix.size();
      auto payload = encode_frame( lower );
      const auto header = build_long_header(
        LongPacketType::Initial, destination, config.local_cid, "", *number, 4, initial_bytes );
      if ( initial_bytes < header.size() + 16 + payload.size() )
        return false;
      payload.resize( initial_bytes - header.size() - 16, char( 0 ) );
      wire = seal_initial_packet( config.tls.server ? initial->server : initial->client,
                                  config.tls.server ? InitialSender::Server : InitialSender::Client,
                                  destination,
                                  config.local_cid,
                                  "",
                                  *number,
                                  4,
                                  payload );
    }
    wire += suffix;
    if ( wire.empty() || wire.size() > 1200 || ( use_initial && wire.size() != 1200 ) )
      throw std::logic_error( "QUIC close packet size mismatch" );
    closing_info = std::move( frame );
    close_wire = std::move( wire );
    close_interval = base_pto_us();
    close_response_after = add_time( last_clock, close_interval );
    close_pending = true;
    stop( ConnectionState::Closing, code );
    return true;
  }
  void fail( uint64_t code, uint64_t frame_type = 0 )
  {
    if ( terminal( state ) )
      return;
    try {
      if ( !peer_id && authenticated_route && authenticated_route->kind == PacketKind::Initial ) {
        peer_id = authenticated_route->scid;
        if ( config.tls.server ) {
          original = authenticated_route->dcid;
          initial = derive_initial_keys( original );
        }
      }
      if ( begin_close( ConnectionCloseFrame { false, code, frame_type, "" }, code ) )
        return;
    } catch ( ... ) {
      // Local inability to seal must never recurse through protocol close.
    }
    close_wire.clear();
    close_pending = false;
    stop( ConnectionState::Failed, code );
  }
  void advance()
  {
    if ( tls->advance() == TlsProgress::Failed ) {
      fail( tls->transport_error().value_or( 0x01 ), 0x06 );
    } else if ( tls->complete() && state == ConnectionState::Handshaking ) {
      state = config.tls.server ? ConnectionState::Confirmed : ConnectionState::Established;
      if ( config.tls.server ) {
        done_pending = true;
        clear_handshake();
      }
    }
    if ( tls && tls->complete() && !streams )
      streams = std::make_unique<ApplicationStreams>(
        config.tls.server, config.tls.local_parameters, *tls->peer_parameters() );
  }
  Impl( ConnectionConfig cfg, UdpEndpoint address )
    : config( std::move( cfg ) )
    , peer( address )
    , state( config.tls.server ? ConnectionState::WaitingInitial : ConnectionState::Handshaking )
    , budget( config.tls.server ? AmplificationRole::Responder : AmplificationRole::Initiator )
  {
    last_activity = now_us();
    ApplicationStreams::validate_local( config.tls.local_parameters );
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
      tls = make_tls();
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
    if ( frames.empty() ) {
      fail( 0x0a );
      return false;
    }
    for ( const auto& frame : frames ) {
      if ( !frame_allowed_in_packet( frame, kind ) ) {
        fail( 0x0a, static_cast<uint8_t>( encode_frame( frame ).front() ) );
        return false;
      }
      if ( kind == PacketKind::OneRtt && std::holds_alternative<CryptoFrame>( frame ) ) {
        fail( 0x01, 0x06 ); // Post-handshake TLS is not implemented yet.
        return false;
      }
      if ( std::holds_alternative<HandshakeDoneFrame>( frame )
           && ( config.tls.server || !tls || !tls->complete() ) ) {
        fail( 0x0a, 0x1e );
        return false;
      }
      if ( const auto* ack = std::get_if<AckFrame>( &frame ) ) {
        if ( !acks.valid_ack( kind, *ack ) ) {
          fail( 0x0a, std::holds_alternative<AckFrame>( frame ) && std::get<AckFrame>( frame ).ecn ? 3 : 2 );
          return false;
        }
      } else if ( !std::holds_alternative<PaddingFrame>( frame ) && !std::holds_alternative<PingFrame>( frame )
                  && !std::holds_alternative<CryptoFrame>( frame )
                  && !std::holds_alternative<HandshakeDoneFrame>( frame )
                  && !std::holds_alternative<ConnectionCloseFrame>( frame )
                  && !( kind == PacketKind::OneRtt && streams && ApplicationStreams::handles( frame ) ) ) {
        fail( 0x01,
              static_cast<uint8_t>(
                encode_frame( frame ).front() ) ); // Unsupported local feature, not a peer violation.
        return false;
      }
    }
    if ( streams && kind == PacketKind::OneRtt ) {
      if ( auto code = streams->receive( frames ) ) {
        fail( *code );
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
        authenticated_route = *layout;
        fail( *opened.transport_error );
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
        authenticated_route = *layout;
        fail( *opened.transport_error );
        return ConnectionReceive::Failed;
      }
      if ( !opened.packet )
        return ConnectionReceive::Discarded;
      if ( opened.packet->key_phase ) {
        fail( 0x01 ); // Key updates require the future recovery/key lifecycle layer.
        return ConnectionReceive::Failed;
      }
      number = opened.packet->packet_number;
      plaintext = opened.packet->plaintext;
    }
    if ( !peer_id && kind == PacketKind::Initial )
      authenticated_route = *layout;
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
      fail( 0x07 );
      return ConnectionReceive::Failed;
    }
    if ( !preflight( *frames, kind ) )
      return ConnectionReceive::Failed;
    last_activity = now_us();
    idle_send_reset = true;
    for ( const auto& frame : *frames ) {
      if ( const auto* close = std::get_if<ConnectionCloseFrame>( &frame ) ) {
        closing_info = *close;
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
        tls = make_tls();
        state = ConnectionState::Handshaking;
      } else if ( !tls->bind_peer_initial_source_connection_id( *peer_id ) ) {
        fail( 0x01 );
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
        release_records(
          kind, recovery.acknowledged( kind, *ack, now_us(), recovery_context(), [this]( const Frame& delivered ) {
            if ( streams )
              streams->acknowledged( delivered );
          } ) );
      } else if ( const auto* crypto = std::get_if<CryptoFrame>( &frame ) ) {
        if ( !tls->receive( kind, *crypto ) ) {
          fail( tls->transport_error().value_or( 0x01 ), 0x06 );
          return ConnectionReceive::Failed;
        }
      } else if ( std::holds_alternative<HandshakeDoneFrame>( frame ) ) {
        state = ConnectionState::Confirmed;
        clear_handshake();
      }
    }
    advance();
    return error ? ConnectionReceive::Failed : ConnectionReceive::Processed;
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
    const auto tick = now_us();
    if ( expire( tick ) )
      return std::nullopt;
    if ( state == ConnectionState::Closing ) {
      const auto cap = attributed_received > std::numeric_limits<uint64_t>::max() / 3
                         ? std::numeric_limits<uint64_t>::max()
                         : 3 * attributed_received;
      if ( !close_pending || close_wire.size() > cap - std::min( cap, close_sent )
           || !budget.record_sent( close_wire.size() ) )
        return std::nullopt;
      close_sent = add_time( close_sent, close_wire.size() );
      close_pending = false;
      close_response_after = add_time( tick, close_interval );
      close_interval = add_time( close_interval, close_interval );
      return UdpDatagram { peer, close_wire, 0 };
    }
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
      std::optional<Frame> app;
      bool done = false, ping = false;
      if ( acks.can_send( kind ) ) {
        retry = recovery.pending( kind ); // Peek; a blocked poll must not consume work.
        if ( !retry && kind != PacketKind::OneRtt )
          crypto = tls->outgoing( kind, offsets[index( kind )], ack ? 400 : 600 );
        else if ( !retry && kind == PacketKind::OneRtt ) {
          done = done_pending;
          ping = !done && ping_pending;
          if ( !done && !ping && streams )
            app = streams->pending();
        }
      }
      if ( !retry && !crypto && !ack && !done && !ping && !app )
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
        else if ( app )
          payload += encode_frame( *app );
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
      bool eliciting = retry || crypto || done || ping || app;
      if ( !recovery.can_send(
             kind, wire_size(), eliciting, kind == PacketKind::Initial, retry && retry->probe ) ) {
        // ACKs must still flow while fresh data or a normal retransmit is blocked.
        if ( !ack )
          continue;
        retry.reset();
        crypto.reset();
        app.reset();
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
        app.reset();
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
      else if ( app )
        data = std::make_shared<RecoveryData>( *app );
      acks.sent( kind, *number, eliciting );
      recovery.sent( kind, *number, now, data, bytes, kind == PacketKind::Initial );
      if ( eliciting && idle_send_reset ) {
        last_activity = now;
        idle_send_reset = false;
      }
      if ( eliciting || kind == PacketKind::Initial )
        pacer.sent( now, bytes, window, rtt_us );
      if ( app )
        streams->sent( *app );
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
  try {
    if ( self.expire( self.now_us() ) )
      return ConnectionReceive::Discarded;
  } catch ( ... ) {
    self.stop( ConnectionState::Failed, 0x01 );
    return ConnectionReceive::Failed;
  }
  if ( terminal( self.state ) && self.state != ConnectionState::Closing )
    return self.state == ConnectionState::Failed ? ConnectionReceive::Failed : ConnectionReceive::Discarded;
  if ( datagram.peer != self.peer )
    return ConnectionReceive::Discarded;
  const auto first = parse_protected_packet( datagram.payload, 0, self.config.local_cid.size() );
  if ( !first || !self.routes( *first ) )
    return ConnectionReceive::Discarded;
  if ( self.config.tls.server && datagram.payload.size() < 1200 && first->kind == PacketKind::Initial )
    return ConnectionReceive::Discarded;
  self.budget.record_received( datagram.payload.size() );
  self.attributed_received = add_time( self.attributed_received, datagram.payload.size() );
  if ( self.state == ConnectionState::Closing ) {
    if ( self.last_clock >= self.close_response_after )
      self.close_pending = true;
    return self.error ? ConnectionReceive::Failed : ConnectionReceive::Discarded;
  }
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
  if ( self.state == ConnectionState::Failed || ( self.state == ConnectionState::Closing && self.error ) )
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
  if ( self.end_deadline )
    return self.end_deadline;
  auto result = self.idle_deadline();
  if ( terminal( self.state ) || !self.tls || self.amplification_blocked )
    return result;
  for ( const auto deadline : { self.recovery.deadline( self.recovery_context() ), self.pacing_wakeup } ) {
    if ( deadline )
      result = result ? std::min( *result, *deadline ) : deadline;
  }
  return result;
}
void HandshakeConnection::on_timeout()
{
  auto& self = *impl_;
  try {
    const auto now = self.now_us();
    if ( self.expire( now ) || terminal( self.state ) || !self.tls || self.amplification_blocked )
      return;
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
bool HandshakeConnection::close( uint64_t application_error, std::string_view reason )
{
  auto& self = *impl_;
  try {
    if ( self.expire( self.now_us() )
         || ( self.state != ConnectionState::Established && self.state != ConnectionState::Confirmed )
         || application_error > max_varint || reason.size() > 256 )
      return false;
    if ( self.begin_close(
           ConnectionCloseFrame { true, application_error, std::nullopt, std::string { reason } } ) )
      return true;
    self.stop( ConnectionState::Failed, 0x01 );
    return false;
  } catch ( ... ) {
    self.stop( ConnectionState::Failed, 0x01 );
    return false;
  }
}
bool HandshakeConnection::send_ping()
{
  if ( impl_->state != ConnectionState::Established && impl_->state != ConnectionState::Confirmed )
    return false;
  impl_->ping_pending = true;
  return true;
}
std::optional<uint64_t> HandshakeConnection::open_stream( bool unidirectional )
{
  return impl_->streams ? impl_->streams->open( unidirectional ) : std::nullopt;
}
bool HandshakeConnection::write_stream( uint64_t id, std::string_view data, bool fin )
{
  return impl_->streams && impl_->streams->write( id, data, fin );
}
StreamRead HandshakeConnection::read_stream( uint64_t id, size_t maximum )
{
  return impl_->streams ? impl_->streams->read( id, maximum ) : StreamRead {};
}
std::vector<uint64_t> HandshakeConnection::stream_ids() const
{
  return impl_->streams ? impl_->streams->ids() : std::vector<uint64_t> {};
}
bool HandshakeConnection::reset_stream( uint64_t id, uint64_t error )
{
  return impl_->streams && impl_->streams->reset( id, error );
}
bool HandshakeConnection::stop_sending( uint64_t id, uint64_t error )
{
  return impl_->streams && impl_->streams->stop( id, error );
}
size_t HandshakeConnection::stream_send_buffered() const
{
  return impl_->streams ? impl_->streams->buffered() : 0;
}
ConnectionState HandshakeConnection::state() const
{
  return impl_->state;
}
std::optional<ConnectionCloseFrame> HandshakeConnection::close_info() const
{
  return impl_->closing_info;
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
