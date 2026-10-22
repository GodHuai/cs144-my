#include "crypto_streams.hh"

#include "varint.hh"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace quic {
namespace {
std::optional<size_t> level_index( const PacketKind kind )
{
  switch ( kind ) {
    case PacketKind::Initial:
      return 0;
    case PacketKind::Handshake:
      return 1;
    case PacketKind::OneRtt:
      return 2;
    case PacketKind::ZeroRtt:
      return std::nullopt;
  }
  return std::nullopt;
}
} // namespace

CryptoStreams::CryptoStreams( const size_t receive_capacity, const size_t send_capacity )
  : receive_capacity_( receive_capacity ), send_capacity_( send_capacity )
{
  if ( receive_capacity < 4096 ) {
    throw std::invalid_argument( "CRYPTO receive capacity must be at least 4096 bytes" );
  }
}

CryptoStreams::State* CryptoStreams::state( const PacketKind kind )
{
  const auto index = level_index( kind );
  return index ? &states_[*index] : nullptr;
}

const CryptoStreams::State* CryptoStreams::state( const PacketKind kind ) const
{
  const auto index = level_index( kind );
  return index ? &states_[*index] : nullptr;
}

std::optional<CryptoReceiveError> CryptoStreams::receive( const PacketKind kind, const CryptoFrame& input )
{
  auto* current = state( kind );
  if ( !current ) {
    return CryptoReceiveError::ProtocolViolation;
  }
  if ( current->discarded ) {
    return std::nullopt;
  }
  if ( input.offset > max_varint || input.data.size() > max_varint - input.offset ) {
    return CryptoReceiveError::FrameEncodingError;
  }
  const uint64_t end = input.offset + input.data.size();
  if ( input.data.empty() || end <= current->read_offset ) {
    return std::nullopt;
  }
  const uint64_t begin = std::max( input.offset, current->read_offset );
  const std::string_view data = std::string_view { input.data }.substr( begin - input.offset );
  auto& pending = current->pending;
  auto first = pending.lower_bound( begin );
  if ( first != pending.begin() ) {
    const auto previous = std::prev( first );
    if ( previous->first + previous->second.size() >= begin ) {
      first = previous;
    }
  }

  // Validate every overlap and count only novel bytes before any mutation.
  size_t novel = data.size();
  for ( auto it = first; it != pending.end() && it->first < end; ++it ) {
    const uint64_t overlap_begin = std::max( begin, it->first );
    const uint64_t overlap_end = std::min( end, it->first + it->second.size() );
    if ( overlap_end > overlap_begin ) {
      const size_t length = overlap_end - overlap_begin;
      if ( data.substr( overlap_begin - begin, length )
           != std::string_view { it->second }.substr( overlap_begin - it->first, length ) ) {
        return CryptoReceiveError::ProtocolViolation;
      }
      novel -= length;
    }
  }
  if ( novel > receive_capacity_ - current->buffered ) {
    return CryptoReceiveError::BufferExceeded;
  }
  if ( novel == 0 ) {
    return std::nullopt;
  }

  uint64_t merged_begin = begin;
  uint64_t merged_end = end;
  auto last = first;
  while ( last != pending.end() && last->first <= merged_end ) {
    merged_begin = std::min( merged_begin, last->first );
    merged_end = std::max( merged_end, last->first + last->second.size() );
    ++last;
  }
  // Only touching intervals are merged: this allocation contains no sparse gap.
  std::string merged( merged_end - merged_begin, '\0' );
  for ( auto it = first; it != last; ++it ) {
    merged.replace( it->first - merged_begin, it->second.size(), it->second );
  }
  merged.replace( begin - merged_begin, data.size(), data );
  if ( first == last ) {
    pending.emplace( merged_begin, std::move( merged ) );
  } else {
    // Reuse a map node so no allocation can fail after old intervals are erased.
    auto node = pending.extract( first++ );
    pending.erase( first, last );
    node.key() = merged_begin;
    node.mapped() = std::move( merged );
    pending.insert( std::move( node ) );
  }
  current->buffered += novel;
  return std::nullopt;
}

std::string CryptoStreams::take_contiguous( const PacketKind kind )
{
  auto* current = state( kind );
  if ( !current || current->pending.empty() || current->pending.begin()->first != current->read_offset ) {
    return {};
  }
  auto first = current->pending.begin();
  std::string data = std::move( first->second );
  current->pending.erase( first );
  current->buffered -= data.size();
  current->read_offset += data.size();
  return data;
}

size_t CryptoStreams::bytes_buffered( const PacketKind kind ) const
{
  const auto* current = state( kind );
  return current ? current->buffered : 0;
}

uint64_t CryptoStreams::read_offset( const PacketKind kind ) const
{
  const auto* current = state( kind );
  return current ? current->read_offset : 0;
}

bool CryptoStreams::append( const PacketKind kind, const std::string_view data )
{
  auto* current = state( kind );
  if ( !current || current->discarded || data.size() > send_capacity_ - current->outgoing.size()
       || data.size() > max_varint - current->outgoing.size() ) {
    return false;
  }
  current->outgoing.append( data );
  return true;
}

std::optional<CryptoFrame> CryptoStreams::frame( const PacketKind kind,
                                                 const uint64_t offset,
                                                 const size_t max_data ) const
{
  const auto* current = state( kind );
  if ( !current || current->discarded || max_data == 0 || offset >= current->outgoing.size() ) {
    return std::nullopt;
  }
  return CryptoFrame {
    offset, current->outgoing.substr( offset, std::min( max_data, current->outgoing.size() - offset ) ) };
}

void CryptoStreams::discard( const PacketKind kind )
{
  auto* current = state( kind );
  if ( current ) {
    // Moving an empty small string into an existing string may retain its
    // allocation. Swap with a temporary to release outgoing heap storage now.
    std::string {}.swap( current->outgoing );
    *current = State {};
    current->discarded = true;
  }
}

} // namespace quic
