#include "packet_recovery.hh"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace quic {
namespace {
uint64_t add( uint64_t a, uint64_t b )
{
  return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}
uint64_t microseconds( double ms )
{
  const auto us = std::ceil( ms * 1000 );
  return us >= static_cast<double>( UINT64_MAX ) ? UINT64_MAX : static_cast<uint64_t>( us );
}
constexpr std::array<PacketKind, 3> kinds { PacketKind::Initial, PacketKind::Handshake, PacketKind::OneRtt };
}
PacketRecovery::Space& PacketRecovery::space( PacketKind kind )
{
  return spaces_.at( static_cast<size_t>( packet_number_space( kind ) ) );
}
const PacketRecovery::Space& PacketRecovery::space( PacketKind kind ) const
{
  return spaces_.at( static_cast<size_t>( packet_number_space( kind ) ) );
}
void PacketRecovery::remember( Space& s, uint64_t pn, Record record )
{
  s.recent.insert_or_assign( pn, std::move( record ) );
  while ( s.recent.size() > 4096 )
    s.recent.erase( s.recent.begin() );
}
void PacketRecovery::enqueue( Space& s, const std::shared_ptr<RecoveryData>& data, bool probe )
{
  if ( data->acknowledged || data->queued )
    return;
  // Remove cancelled entries before enforcing the same bounded queue capacity.
  std::erase_if( s.pending, []( const auto& p ) { return p.data->acknowledged; } );
  if ( s.pending.size() >= 4096 )
    throw std::length_error( "QUIC recovery queue full" );
  data->queued = true;
  s.pending.push_back( { data, probe } );
}
void PacketRecovery::sent( PacketKind kind,
                           uint64_t pn,
                           uint64_t now,
                           std::shared_ptr<RecoveryData> data,
                           uint64_t bytes,
                           bool padded )
{
  auto& s = space( kind );
  if ( s.active.contains( pn ) || s.recent.contains( pn ) || pn >= max_packet_number )
    throw std::logic_error( "invalid recovery send record" );
  if ( bytes && ( data || padded ) ) {
    if ( s.flight.size() >= 4096 )
      throw std::length_error( "QUIC physical flight history full" );
    congestion_.sent( bytes );
    s.flight.emplace( pn, Space::Flight { now, bytes, bool( data ) } );
  }
  if ( data && data->acknowledged ) {
    data->queued = false;
    remember( s, pn, { now, std::move( data ) } );
  } else if ( data ) {
    if ( s.active.size() >= 4096 )
      throw std::length_error( "QUIC recovery history full" );
    data->queued = false;
    s.active.emplace( pn, Record { now, std::move( data ) } );
    s.last_sent = now;
    validation_anchor_ = now;
  } else
    remember( s, pn, { now, nullptr } );
}
uint64_t PacketRecovery::loss_delay() const
{
  return std::max<uint64_t>( 1000, microseconds( 1.125 * std::max( rtt_.latest_ms(), rtt_.smoothed_ms() ) ) );
}
std::optional<uint64_t> PacketRecovery::loss_time( const Space& s ) const
{
  std::optional<uint64_t> result;
  if ( !s.largest_acked )
    return result;
  for ( const auto& [pn, record] : s.active ) {
    if ( pn >= *s.largest_acked )
      break;
    const auto due = add( record.time, loss_delay() );
    result = result ? std::min( *result, due ) : due;
  }
  for ( const auto& [pn, flight] : s.flight ) {
    if ( pn >= *s.largest_acked )
      break;
    const auto due = add( flight.time, loss_delay() );
    result = result ? std::min( *result, due ) : due;
  }
  return result;
}
void PacketRecovery::detect_lost( Space& s, uint64_t now, std::vector<uint64_t>& released )
{
  if ( !s.largest_acked )
    return;
  for ( auto i = s.flight.begin(); i != s.flight.end() && i->first < *s.largest_acked; ) {
    if ( *s.largest_acked - i->first >= 3 || add( i->second.time, loss_delay() ) <= now ) {
      congestion_.lost( i->second.bytes, i->second.time, now );
      i = s.flight.erase( i );
    } else
      ++i;
  }
  for ( auto i = s.active.begin(); i != s.active.end() && i->first < *s.largest_acked; ) {
    if ( *s.largest_acked - i->first >= 3 || add( i->second.time, loss_delay() ) <= now ) {
      enqueue( s, i->second.data, false );
      released.push_back( i->first );
      remember( s, i->first, i->second );
      i = s.active.erase( i );
    } else
      ++i;
  }
}
std::vector<uint64_t> PacketRecovery::acknowledged( PacketKind kind,
                                                    const AckFrame& ack,
                                                    uint64_t now,
                                                    const RecoveryContext& c,
                                                    const std::function<void( const Frame& )>& delivered )
{
  if ( ack.ranges.empty() || c.ack_delay_exponent > 20 || !std::isfinite( c.max_ack_delay_ms )
       || c.max_ack_delay_ms < 0 )
    throw std::invalid_argument( "invalid recovery ACK context" );
  auto& s = space( kind );
  const auto largest = ack.ranges.front().largest;
  std::optional<uint64_t> largest_time;
  if ( auto i = s.active.find( largest ); i != s.active.end() )
    largest_time = i->second.time;
  else if ( auto j = s.recent.find( largest ); j != s.recent.end() )
    largest_time = j->second.time;
  const auto stats = congestion_.stats();
  const bool limited = stats.bytes_in_flight < stats.window && stats.window - stats.bytes_in_flight >= 1200;
  std::vector<Space::Flight> newly_acked_flight;
  bool new_eliciting = false, any_new = false;
  std::vector<uint64_t> released;
  std::vector<uint64_t> reset_delivered;
  for ( const auto& range : ack.ranges ) {
    if ( range.smallest > range.largest )
      throw std::invalid_argument( "invalid recovery ACK range" );
    auto physical = s.flight.lower_bound( range.smallest );
    while ( physical != s.flight.end() && physical->first <= range.largest ) {
      newly_acked_flight.push_back( physical->second );
      any_new = true;
      physical = s.flight.erase( physical );
    }
    for ( auto* records : { &s.active, &s.recent } ) {
      auto i = records->lower_bound( range.smallest );
      while ( i != records->end() && i->first <= range.largest ) {
        any_new = true;
        if ( i->second.data ) {
          new_eliciting = true;
          if ( !i->second.data->acknowledged ) {
            if ( const auto* reset = std::get_if<ResetStreamFrame>( &i->second.data->frame ) )
              reset_delivered.push_back( reset->stream_id );
            if ( delivered )
              delivered( i->second.data->frame );
          }
          i->second.data->acknowledged = true;
        }
        if ( records == &s.active )
          released.push_back( i->first );
        i = records->erase( i );
      }
    }
  }
  if ( largest_time && new_eliciting ) {
    const double sample_ms = static_cast<double>( now > *largest_time ? now - *largest_time : 1 ) / 1000;
    const double delay = packet_number_space( kind ) == PacketNumberSpaceId::Application
                           ? std::ldexp( static_cast<double>( ack.ack_delay ), c.ack_delay_exponent ) / 1000
                           : 0;
    rtt_.observe( sample_ms, delay, c.confirmed, c.max_ack_delay_ms );
  }
  if ( any_new ) {
    s.largest_acked = std::max( s.largest_acked.value_or( largest ), largest );
    validation_anchor_ = now;
    if ( c.peer_validated )
      pto_count_ = 0;
  }
  // RESET delivery obsoletes old STREAM payloads, without acknowledging their physical flight.
  const auto cancel = [&]( const std::shared_ptr<RecoveryData>& data ) {
    if ( !data )
      return;
    if ( const auto* stream = std::get_if<StreamFrame>( &data->frame );
         stream
         && std::find( reset_delivered.begin(), reset_delivered.end(), stream->stream_id )
              != reset_delivered.end() )
      data->acknowledged = true;
  };
  if ( !reset_delivered.empty() ) {
    for ( auto* records : { &s.active, &s.recent } )
      for ( auto& [pn, record] : *records ) {
        (void)pn;
        cancel( record.data );
      }
    for ( auto& pending : s.pending )
      cancel( pending.data );
  }
  // Acknowledgment of any transmission delivers its shared logical frame.
  for ( auto i = s.active.begin(); i != s.active.end(); ) {
    if ( i->second.data->acknowledged ) {
      released.push_back( i->first );
      remember( s, i->first, i->second );
      i = s.active.erase( i );
    } else
      ++i;
  }
  detect_lost( s, now, released );
  for ( const auto& flight : newly_acked_flight )
    congestion_.acknowledged( flight.bytes, flight.time, limited );
  return released;
}
std::optional<std::pair<uint64_t, PacketKind>> PacketRecovery::pto( const RecoveryContext& c ) const
{
  if ( auto p = pending_probe_.lock(); p && p->queued && !p->acknowledged )
    return std::nullopt;
  if ( !std::isfinite( c.max_ack_delay_ms ) || c.max_ack_delay_ms < 0 )
    throw std::invalid_argument( "invalid max ACK delay" );
  std::optional<std::pair<uint64_t, PacketKind>> result;
  bool any_active = false;
  for ( auto kind : kinds ) {
    const auto& s = space( kind );
    const bool physical_eliciting
      = std::any_of( s.flight.begin(), s.flight.end(), []( const auto& entry ) { return entry.second.eliciting; } );
    if ( s.active.empty() && !physical_eliciting )
      continue;
    any_active = true;
    auto period = rtt_.pto_ms( kind == PacketKind::OneRtt, c.confirmed, c.max_ack_delay_ms );
    if ( !period )
      continue;
    uint64_t duration = microseconds( *period );
    duration = duration > ( UINT64_MAX >> pto_count_ ) ? UINT64_MAX : duration << pto_count_;
    const auto due = add( s.last_sent, duration );
    if ( !result || due < result->first )
      result = { due, kind };
  }
  if ( !any_active && !c.peer_validated && c.validation_probe_space && validation_anchor_ ) {
    uint64_t duration = microseconds( *rtt_.pto_ms( false, false, 0 ) );
    duration = duration > ( UINT64_MAX >> pto_count_ ) ? UINT64_MAX : duration << pto_count_;
    result = { add( *validation_anchor_, duration ), *c.validation_probe_space };
  }
  return result;
}
std::optional<uint64_t> PacketRecovery::deadline( const RecoveryContext& c ) const
{
  std::optional<uint64_t> due;
  for ( const auto& s : spaces_ )
    if ( auto t = loss_time( s ) )
      due = due ? std::min( *due, *t ) : *t;
  if ( due )
    return due;
  if ( auto p = pto( c ) )
    return p->first;
  return std::nullopt;
}
PacketRecovery::Events PacketRecovery::timeout( uint64_t now, const RecoveryContext& c )
{
  Events events;
  const auto scheduled = deadline( c );
  if ( !scheduled || *scheduled > now )
    return events;
  bool loss_due = false;
  for ( size_t i = 0; i < spaces_.size(); ++i ) {
    if ( auto t = loss_time( spaces_[i] ); t && *t <= now ) {
      detect_lost( spaces_[i], now, events[i] );
      loss_due = true;
    }
  }
  if ( loss_due )
    return events;
  const auto due = pto( c );
  if ( !due || due->first > now )
    return events;
  auto& s = space( due->second );
  std::shared_ptr<RecoveryData> data;
  for ( const auto& [pn, record] : s.active ) {
    (void)pn;
    if ( !record.data->acknowledged && !record.data->queued ) {
      data = record.data;
      break;
    }
  }
  if ( !data )
    data = std::make_shared<RecoveryData>( PingFrame {} );
  enqueue( s, data, true );
  pending_probe_ = data;
  pto_count_ = std::min( pto_count_ + 1, 63U );
  return events;
}
bool PacketRecovery::can_send( PacketKind kind, uint64_t bytes, bool eliciting, bool padded, bool probe ) const
{
  if ( !eliciting && !padded )
    return true;
  return space( kind ).flight.size() < 4096 && congestion_.can_send( bytes, probe );
}
std::optional<RecoverySend> PacketRecovery::pending( PacketKind kind )
{
  auto& s = space( kind );
  std::erase_if( s.pending, []( const auto& p ) {
    if ( !p.data->acknowledged )
      return false;
    p.data->queued = false;
    return true;
  } );
  // PTO work must not sit behind congestion-blocked retransmissions.
  const auto probe = std::find_if( s.pending.begin(), s.pending.end(), []( const auto& p ) { return p.probe; } );
  if ( probe != s.pending.end() && probe != s.pending.begin() )
    std::rotate( s.pending.begin(), probe, std::next( probe ) );
  return s.pending.empty() ? std::nullopt : std::optional<RecoverySend> { s.pending.front() };
}
std::optional<RecoverySend> PacketRecovery::take_pending( PacketKind kind )
{
  (void)pending( kind );
  auto& s = space( kind );
  while ( !s.pending.empty() ) {
    auto out = std::move( s.pending.front() );
    s.pending.pop_front();
    if ( !out.data->acknowledged )
      return out;
    out.data->queued = false;
  }
  return std::nullopt;
}
void PacketRecovery::discard( PacketKind kind )
{
  auto& s = space( kind );
  for ( auto* records : { &s.active, &s.recent } )
    for ( auto& [pn, record] : *records ) {
      (void)pn;
      if ( record.data )
        record.data->queued = false;
    }
  for ( auto& p : s.pending )
    p.data->queued = false;
  for ( const auto& [pn, flight] : s.flight ) {
    (void)pn;
    congestion_.discard( flight.bytes );
  }
  s = Space {};
  if ( kind == PacketKind::Initial || kind == PacketKind::Handshake )
    pto_count_ = 0;
}
} // namespace quic
