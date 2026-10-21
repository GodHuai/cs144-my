#include "peer_connection_ids.hh"

#include "varint.hh"

#include <algorithm>
#include <stdexcept>
#include <utility>

using namespace std;

namespace quic {

PeerConnectionIds::PeerConnectionIds( string initial_peer_scid,
                                      const uint64_t advertised_active_limit,
                                      const size_t history_limit )
  : active_limit_( advertised_active_limit )
  , history_limit_( history_limit )
  , pending_limit_( 2 * advertised_active_limit )
{
  if ( initial_peer_scid.size() > 20 || active_limit_ < 2 || active_limit_ > max_varint
       || active_limit_ > history_limit_ / 2 ) {
    throw invalid_argument( "invalid initial peer CID or active CID limit" );
  }
  entries_.emplace( 0, Entry { std::move( initial_peer_scid ), nullopt, nullopt } );
}

CidAcceptResult PeerConnectionIds::add_preferred_address( string cid, const array<uint8_t, 16> reset_token )
{
  if ( entries_.at( 0 ).cid.empty() || cid.empty() || cid.size() > 20 ) {
    return CidAcceptResult::ProtocolViolation;
  }
  const auto existing = entries_.find( 1 );
  if ( existing != entries_.end() ) {
    return preferred_address_present_ && existing->second.cid == cid && existing->second.reset_token == reset_token
             ? CidAcceptResult::Duplicate
             : CidAcceptResult::ProtocolViolation;
  }
  for ( const auto& [sequence, entry] : entries_ ) {
    (void)sequence;
    if ( entry.cid == cid ) {
      return CidAcceptResult::ProtocolViolation;
    }
  }
  if ( active_count() >= active_limit_ ) {
    return CidAcceptResult::ConnectionIdLimitError;
  }
  if ( entries_.size() >= history_limit_ ) {
    return CidAcceptResult::ResourceLimitError;
  }
  entries_.emplace( 1, Entry { std::move( cid ), reset_token, nullopt } );
  preferred_address_present_ = true;
  return CidAcceptResult::Accepted;
}

void PeerConnectionIds::apply_retire_prior_to( const uint64_t threshold )
{
  if ( threshold <= retire_prior_to_ ) {
    return;
  }
  retire_prior_to_ = threshold;
  for ( auto& [sequence, entry] : entries_ ) {
    if ( sequence < threshold && !entry.retirement_queued ) {
      pending_retirements_.insert( sequence );
      entry.retirement_queued = true;
    }
  }
}

CidAcceptResult PeerConnectionIds::on_new_id( const NewConnectionIdFrame& frame )
{
  if ( frame.sequence > max_varint || frame.retire_prior_to > frame.sequence || frame.cid.empty()
       || frame.cid.size() > 20 ) {
    return CidAcceptResult::FrameEncodingError;
  }
  if ( entries_.at( 0 ).cid.empty() || frame.sequence == 0
       || ( preferred_address_present_ && frame.sequence == 1 ) ) {
    return CidAcceptResult::ProtocolViolation;
  }

  const auto existing = entries_.find( frame.sequence );
  if ( existing != entries_.end() ) {
    if ( existing->second.cid != frame.cid || existing->second.reset_token != frame.reset_token ) {
      return CidAcceptResult::ProtocolViolation;
    }
  } else {
    for ( const auto& [sequence, entry] : entries_ ) {
      (void)sequence;
      if ( entry.cid == frame.cid ) {
        return CidAcceptResult::ProtocolViolation;
      }
    }
  }

  const uint64_t threshold = max( retire_prior_to_, frame.retire_prior_to );
  size_t prospective_active = 0;
  size_t prospective_pending = pending_retirements_.size();
  for ( const auto& [sequence, entry] : entries_ ) {
    prospective_active += sequence >= threshold && !entry.locally_retired;
    prospective_pending += sequence < threshold && !entry.retirement_queued;
  }
  if ( existing == entries_.end() && frame.sequence >= threshold ) {
    ++prospective_active;
  }
  if ( existing == entries_.end() && frame.sequence < threshold ) {
    ++prospective_pending;
  }
  if ( prospective_active > active_limit_ || prospective_pending > pending_limit_ ) {
    return CidAcceptResult::ConnectionIdLimitError;
  }
  if ( existing == entries_.end() && entries_.size() >= history_limit_ ) {
    return CidAcceptResult::ResourceLimitError;
  }

  if ( existing == entries_.end() ) {
    entries_.emplace( frame.sequence, Entry { frame.cid, frame.reset_token, nullopt } );
  }
  apply_retire_prior_to( threshold );
  if ( frame.sequence < retire_prior_to_ && !entries_.at( frame.sequence ).retirement_queued ) {
    pending_retirements_.insert( frame.sequence );
    entries_.at( frame.sequence ).retirement_queued = true;
  }
  return existing == entries_.end() ? CidAcceptResult::Accepted : CidAcceptResult::Duplicate;
}

optional<PeerConnectionIdChoice> PeerConnectionIds::select_for_path( const string_view path_key )
{
  if ( entries_.at( 0 ).cid.empty() ) {
    return PeerConnectionIdChoice { 0, {}, nullopt };
  }
  if ( path_key.empty() ) {
    return nullopt;
  }
  for ( auto& [sequence, entry] : entries_ ) {
    if ( sequence >= retire_prior_to_ && !entry.locally_retired && entry.bound_path == path_key ) {
      return PeerConnectionIdChoice { sequence, entry.cid, entry.reset_token };
    }
  }
  for ( auto& [sequence, entry] : entries_ ) {
    if ( sequence >= retire_prior_to_ && !entry.locally_retired && !entry.bound_path ) {
      entry.bound_path = string { path_key };
      return PeerConnectionIdChoice { sequence, entry.cid, entry.reset_token };
    }
  }
  return nullopt;
}

CidRetireResult PeerConnectionIds::retire_path( const string_view path_key )
{
  if ( path_key.empty() || entries_.at( 0 ).cid.empty() ) {
    return CidRetireResult::NoPath;
  }
  for ( auto& [sequence, entry] : entries_ ) {
    if ( entry.bound_path == path_key && sequence >= retire_prior_to_ && !entry.locally_retired ) {
      if ( !entry.retirement_queued && pending_retirements_.size() >= pending_limit_ ) {
        return CidRetireResult::ConnectionIdLimitError;
      }
      entry.locally_retired = true;
      if ( !entry.retirement_queued ) {
        entry.retirement_queued = true;
        pending_retirements_.insert( sequence );
      }
      return CidRetireResult::Retired;
    }
  }
  return CidRetireResult::NoPath;
}

vector<RetireConnectionIdFrame> PeerConnectionIds::pending_retirements() const
{
  vector<RetireConnectionIdFrame> result;
  result.reserve( pending_retirements_.size() );
  for ( const uint64_t sequence : pending_retirements_ ) {
    result.push_back( RetireConnectionIdFrame { sequence } );
  }
  return result;
}

bool PeerConnectionIds::acknowledge_retirement( const uint64_t sequence )
{
  return pending_retirements_.erase( sequence ) == 1;
}

size_t PeerConnectionIds::active_count() const
{
  size_t count = 0;
  for ( auto it = entries_.lower_bound( retire_prior_to_ ); it != entries_.end(); ++it ) {
    count += !it->second.locally_retired;
  }
  return count;
}

} // namespace quic
