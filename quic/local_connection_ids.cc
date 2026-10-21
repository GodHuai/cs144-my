#include "local_connection_ids.hh"

#include "varint.hh"

#include <stdexcept>
#include <utility>

using namespace std;

namespace quic {

LocalConnectionIds::LocalConnectionIds( string initial_source_cid,
                                        const uint64_t peer_active_limit,
                                        const size_t total_issue_limit )
  : peer_active_limit_( peer_active_limit ), total_issue_limit_( total_issue_limit )
{
  if ( initial_source_cid.size() > 20 || peer_active_limit_ < 2 || peer_active_limit_ > max_varint
       || total_issue_limit_ == 0 ) {
    throw invalid_argument( "invalid local CID configuration" );
  }
  entries_.emplace( 0, Entry { std::move( initial_source_cid ), nullopt, false, true } );
}

bool LocalConnectionIds::can_add( const string_view cid, const array<uint8_t, 16>& token ) const
{
  if ( entries_.at( 0 ).cid.empty() || cid.empty() || cid.size() > 20 || active_count() >= peer_active_limit_
       || entries_.size() >= total_issue_limit_ || entries_.rbegin()->first >= max_varint ) {
    return false;
  }
  for ( const auto& [sequence, entry] : entries_ ) {
    (void)sequence;
    if ( entry.cid == cid || entry.token == token ) {
      return false;
    }
  }
  return true;
}

bool LocalConnectionIds::reserve_preferred_address( string cid, const array<uint8_t, 16> token )
{
  if ( entries_.size() != 1 || !can_add( cid, token ) ) {
    return false;
  }
  entries_.emplace( 1, Entry { std::move( cid ), token, false, false } );
  return true;
}

optional<NewConnectionIdFrame> LocalConnectionIds::issue( string cid, const array<uint8_t, 16> token )
{
  if ( !can_add( cid, token ) ) {
    return nullopt;
  }
  const uint64_t sequence = entries_.rbegin()->first + 1;
  entries_.emplace( sequence, Entry { cid, token, false, false } );
  return NewConnectionIdFrame { sequence, 0, std::move( cid ), token };
}

bool LocalConnectionIds::mark_sent( const uint64_t sequence )
{
  const auto it = entries_.find( sequence );
  if ( it == entries_.end() || it->second.retired ) {
    return false;
  }
  it->second.sent = true;
  return true;
}

LocalRetireResult LocalConnectionIds::on_retire( const RetireConnectionIdFrame& frame,
                                                 const string_view packet_dcid )
{
  if ( entries_.at( 0 ).cid.empty() || frame.sequence > entries_.rbegin()->first ) {
    return LocalRetireResult::ProtocolViolation;
  }
  auto& entry = entries_.at( frame.sequence );
  if ( !entry.sent || entry.cid == packet_dcid ) {
    return LocalRetireResult::ProtocolViolation;
  }
  if ( entry.retired ) {
    return LocalRetireResult::Duplicate;
  }
  entry.retired = true;
  replacement_requested_ = true;
  return LocalRetireResult::Retired;
}

optional<uint64_t> LocalConnectionIds::lookup( const string_view cid ) const
{
  for ( const auto& [sequence, entry] : entries_ ) {
    if ( !entry.retired && entry.cid == cid ) {
      return sequence;
    }
  }
  return nullopt;
}

size_t LocalConnectionIds::active_count() const
{
  size_t count = 0;
  for ( const auto& [sequence, entry] : entries_ ) {
    (void)sequence;
    count += !entry.retired;
  }
  return count;
}

bool LocalConnectionIds::needs_replacement() const
{
  return replacement_requested_ && active_count() < peer_active_limit_;
}

} // namespace quic
