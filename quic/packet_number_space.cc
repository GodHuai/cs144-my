#include "packet_number_space.hh"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace quic {

PacketNumberSpaceId packet_number_space( const PacketKind kind )
{
  switch ( kind ) {
    case PacketKind::Initial:
      return PacketNumberSpaceId::Initial;
    case PacketKind::Handshake:
      return PacketNumberSpaceId::Handshake;
    case PacketKind::ZeroRtt:
    case PacketKind::OneRtt:
      return PacketNumberSpaceId::Application;
  }
  throw std::invalid_argument( "invalid QUIC packet kind" );
}

PacketNumberSpaces::State::State()
  : next_send( 0 ), min_acceptable( 0 ), largest_received( std::nullopt ), received_ranges()
{}

PacketNumberSpaces::PacketNumberSpaces() : states_ {} {}

PacketNumberSpaces::State& PacketNumberSpaces::state( const PacketKind kind )
{
  return states_.at( static_cast<size_t>( packet_number_space( kind ) ) );
}

const PacketNumberSpaces::State& PacketNumberSpaces::state( const PacketKind kind ) const
{
  return states_.at( static_cast<size_t>( packet_number_space( kind ) ) );
}

std::optional<uint64_t> PacketNumberSpaces::allocate( const PacketKind kind )
{
  auto& current = state( kind );
  if ( current.next_send >= max_packet_number ) {
    return std::nullopt;
  }
  return current.next_send++;
}

bool PacketNumberSpaces::record_authenticated( const PacketKind kind, const uint64_t number )
{
  auto& current = state( kind );
  if ( number > max_packet_number || number < current.min_acceptable ) {
    return false;
  }

  auto after = current.received_ranges.upper_bound( number );
  const auto before = after == current.received_ranges.begin() ? current.received_ranges.end() : std::prev( after );
  if ( before != current.received_ranges.end() && before->second >= number ) {
    return false;
  }
  const bool join_before = before != current.received_ranges.end() && before->second + 1 == number;
  const bool join_after = after != current.received_ranges.end() && number + 1 == after->first;
  if ( join_before && join_after ) {
    before->second = after->second;
    current.received_ranges.erase( after );
  } else if ( join_before ) {
    before->second = number;
  } else if ( join_after ) {
    const uint64_t last = after->second;
    current.received_ranges.erase( after );
    current.received_ranges.emplace( number, last );
  } else {
    current.received_ranges.emplace( number, number );
  }
  current.largest_received = std::max( current.largest_received.value_or( number ), number );
  return true;
}

std::optional<uint64_t> PacketNumberSpaces::largest_received( const PacketKind kind ) const
{
  return state( kind ).largest_received;
}

void PacketNumberSpaces::retire_received_below( const PacketKind kind, const uint64_t minimum )
{
  if ( minimum > max_packet_number + 1 ) {
    throw std::out_of_range( "packet-number retirement exceeds 62 bits" );
  }
  auto& current = state( kind );
  if ( minimum <= current.min_acceptable ) {
    return;
  }
  current.min_acceptable = minimum;
  auto first = current.received_ranges.begin();
  while ( first != current.received_ranges.end() && first->second < minimum ) {
    first = current.received_ranges.erase( first );
  }
  if ( first != current.received_ranges.end() && first->first < minimum ) {
    const uint64_t last = first->second;
    current.received_ranges.erase( first );
    current.received_ranges.emplace( minimum, last );
  }
}

} // namespace quic
