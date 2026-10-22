#include "acknowledgments.hh"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace quic {
PacketAcknowledgments::State& PacketAcknowledgments::state( PacketKind kind )
{
  return spaces_.at( static_cast<size_t>( packet_number_space( kind ) ) );
}
const PacketAcknowledgments::State& PacketAcknowledgments::state( PacketKind kind ) const
{
  return spaces_.at( static_cast<size_t>( packet_number_space( kind ) ) );
}
bool PacketAcknowledgments::received( PacketKind kind, uint64_t number, bool eliciting, uint64_t now )
{
  auto& s = state( kind );
  if ( number > max_packet_number || ( s.largest && *s.largest >= 4096 && number < *s.largest - 4095 ) )
    return false;
  auto after = s.received.upper_bound( number );
  auto before = after == s.received.begin() ? s.received.end() : std::prev( after );
  const bool fresh = before == s.received.end() || before->second < number;
  if ( fresh ) {
    const bool left = before != s.received.end() && before->second + 1 == number;
    const bool right = after != s.received.end() && number + 1 == after->first;
    if ( left && right ) {
      before->second = after->second;
      s.received.erase( after );
    } else if ( left )
      before->second = number;
    else if ( right ) {
      const auto last = after->second;
      s.received.erase( after );
      s.received.emplace( number, last );
    } else
      s.received.emplace( number, number );
    if ( !s.largest || number > *s.largest ) {
      s.largest = number;
      s.largest_time = now;
    }
    const auto minimum = *s.largest >= 4096 ? *s.largest - 4095 : 0;
    while ( !s.received.empty() && s.received.begin()->second < minimum )
      s.received.erase( s.received.begin() );
    if ( !s.received.empty() && s.received.begin()->first < minimum ) {
      const auto last = s.received.begin()->second;
      s.received.erase( s.received.begin() );
      s.received.emplace( minimum, last );
    }
  }
  // Even a non-eliciting fresh arrival changes a prepared ACK's range snapshot.
  if ( fresh || eliciting )
    ++s.generation;
  s.pending = s.pending || eliciting;
  return fresh;
}
std::optional<PacketAcknowledgments::PendingAck> PacketAcknowledgments::pending_ack( PacketKind kind,
                                                                                     uint64_t now,
                                                                                     uint8_t exponent ) const
{
  if ( exponent > 20 )
    throw std::invalid_argument( "ACK delay exponent exceeds 20" );
  const auto& s = state( kind );
  if ( !s.pending || s.received.empty() )
    return std::nullopt;
  AckFrame ack { 0, {}, std::nullopt };
  if ( packet_number_space( kind ) == PacketNumberSpaceId::Application )
    ack.ack_delay = std::min( max_packet_number, ( now >= s.largest_time ? now - s.largest_time : 0 ) >> exponent );
  for ( auto i = s.received.rbegin(); i != s.received.rend() && ack.ranges.size() < 32; ++i )
    ack.ranges.push_back( { i->first, i->second } );
  return PendingAck { std::move( ack ), s.generation };
}
void PacketAcknowledgments::ack_sent( PacketKind kind, uint64_t generation )
{
  auto& s = state( kind );
  if ( generation == s.generation )
    s.pending = false;
}
bool PacketAcknowledgments::can_send( PacketKind kind ) const
{
  return state( kind ).outstanding.size() < 4096;
}
void PacketAcknowledgments::sent( PacketKind kind, uint64_t number, bool eliciting )
{
  auto& s = state( kind );
  if ( number != s.next_sent || number >= max_packet_number || ( eliciting && !can_send( kind ) ) )
    throw std::logic_error( "nonconsecutive or over-capacity QUIC send history" );
  if ( eliciting )
    s.outstanding.insert( number );
  ++s.next_sent;
}
bool PacketAcknowledgments::valid_ack( PacketKind kind, const AckFrame& ack ) const
{
  const auto& s = state( kind );
  if ( ack.ranges.empty() )
    return false;
  uint64_t previous = 0;
  bool first = true;
  for ( const auto& r : ack.ranges ) {
    if ( r.smallest > r.largest || r.largest >= s.next_sent
         || ( !first && ( previous < 2 || r.largest > previous - 2 ) ) )
      return false;
    previous = r.smallest;
    first = false;
  }
  return true;
}
void PacketAcknowledgments::apply_ack( PacketKind kind, const AckFrame& ack )
{
  if ( !valid_ack( kind, ack ) )
    throw std::invalid_argument( "ACK acknowledges an unsent packet" );
  auto& s = state( kind );
  for ( const auto& r : ack.ranges )
    s.outstanding.erase( s.outstanding.lower_bound( r.smallest ), s.outstanding.upper_bound( r.largest ) );
}
void PacketAcknowledgments::release( PacketKind kind, uint64_t number )
{
  state( kind ).outstanding.erase( number );
}
size_t PacketAcknowledgments::outstanding( PacketKind kind ) const
{
  return state( kind ).outstanding.size();
}
void PacketAcknowledgments::discard( PacketKind kind )
{
  state( kind ) = State {};
}
} // namespace quic
