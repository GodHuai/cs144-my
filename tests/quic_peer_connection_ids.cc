#include "quic/peer_connection_ids.hh"

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( bool condition, std::string_view message )
{
  if ( !condition ) {
    throw std::runtime_error( std::string { message } );
  }
}

int main()
{
  const std::array<uint8_t, 16> token1 { 1 };
  const std::array<uint8_t, 16> token2 { 2 };
  const std::array<uint8_t, 16> token3 { 3 };

  PeerConnectionIds ids { "initial", 2 };
  const auto first = ids.select_for_path( "local-a/remote-a" );
  require( first && first->sequence == 0 && first->cid == "initial", "initial peer CID missing" );
  require( ids.select_for_path( "local-a/remote-a" )->sequence == 0, "same path changed CID" );
  require( !ids.select_for_path( "local-b/remote-b" ), "initial CID reused on a second path" );

  const NewConnectionIdFrame next { 1, 0, "next", token1 };
  require( ids.on_new_id( next ) == CidAcceptResult::Accepted, "new CID rejected" );
  require( ids.on_new_id( next ) == CidAcceptResult::Duplicate, "identical NEW_CONNECTION_ID rejected" );
  const auto second = ids.select_for_path( "local-b/remote-b" );
  require( second && second->sequence == 1 && second->cid == "next" && second->reset_token == token1,
           "new CID was not assigned to second path" );
  require( !ids.select_for_path( "local-c/remote-c" ), "CID reused after pool exhausted" );

  require( ids.on_new_id( { 2, 0, "third", token2 } ) == CidAcceptResult::ConnectionIdLimitError,
           "active CID limit exceeded" );
  require( ids.active_count() == 2 && ids.pending_retirements().empty(), "rejected frame mutated pool" );
  require( ids.on_new_id( { 2, 3, "third", token2 } ) == CidAcceptResult::FrameEncodingError,
           "Retire Prior To above sequence accepted" );
  require( ids.on_new_id( { 1, 0, "different", token1 } ) == CidAcceptResult::ProtocolViolation,
           "sequence reused for another CID" );
  require( ids.on_new_id( { 2, 0, "next", token2 } ) == CidAcceptResult::ProtocolViolation,
           "CID reused with another sequence" );
  require( ids.on_new_id( { 1, 0, "next", token2 } ) == CidAcceptResult::ProtocolViolation,
           "CID reused with different reset token" );

  require( ids.on_new_id( { 2, 1, "third", token2 } ) == CidAcceptResult::Accepted,
           "retire-and-replace exceeded active limit" );
  require( ids.active_count() == 2, "retirement did not free active slot" );
  require( ids.pending_retirements().size() == 1 && ids.pending_retirements()[0].sequence == 0,
           "retired initial CID not queued" );
  require( ids.select_for_path( "local-a/remote-a" )->sequence == 2, "path did not replace retired CID" );
  require( ids.acknowledge_retirement( 0 ), "retirement ACK rejected" );
  require( ids.pending_retirements().empty(), "acked retirement stayed pending" );
  require( ids.on_new_id( { 2, 1, "third", token2 } ) == CidAcceptResult::Duplicate,
           "duplicate replacement rejected" );
  require( ids.pending_retirements().empty(), "acked retirement was queued again" );

  require( ids.on_new_id( { 5, 4, "fifth", token3 } ) == CidAcceptResult::Accepted,
           "higher Retire Prior To rejected" );
  require( ids.retire_prior_to() == 4 && ids.active_count() == 1, "retirement threshold not applied" );
  require( ids.on_new_id( { 3, 0, "late", token1 } ) == CidAcceptResult::Accepted,
           "late lower-sequence CID rejected" );
  bool queued_late = false;
  for ( const auto& retirement : ids.pending_retirements() ) {
    queued_late |= retirement.sequence == 3;
  }
  require( queued_late, "late ID below prior retirement threshold not retired" );
  require( ids.on_new_id( { 5, 1, "fifth", token3 } ) == CidAcceptResult::Duplicate,
           "lower Retire Prior To changed state" );
  require( ids.retire_prior_to() == 4, "retirement threshold regressed" );

  PeerConnectionIds preferred { "server-initial", 2 };
  require( preferred.add_preferred_address( "preferred", token1 ) == CidAcceptResult::Accepted,
           "preferred address CID rejected" );
  require( preferred.select_for_path( "original" )->sequence == 0, "preferred CID used for initial path" );
  require( preferred.select_for_path( "new" )->sequence == 1, "preferred CID unavailable for migration" );
  require( preferred.on_new_id( { 2, 2, "replacement", token2 } ) == CidAcceptResult::Accepted,
           "preferred CID not retired by threshold" );

  PeerConnectionIds zero { "", 2 };
  require( zero.select_for_path( "first" )->cid.empty() && zero.select_for_path( "second" )->cid.empty(),
           "zero-length CID not usable on both paths" );
  require( zero.on_new_id( next ) == CidAcceptResult::ProtocolViolation,
           "NEW_CONNECTION_ID accepted after zero-length CID" );

  PeerConnectionIds migrating { "initial", 2 };
  require( migrating.select_for_path( "old" )->sequence == 0, "old path not bound" );
  require( migrating.on_new_id( next ) == CidAcceptResult::Accepted, "migration ID rejected" );
  require( migrating.select_for_path( "second" )->sequence == 1, "second path not bound" );
  require( migrating.retire_path( "old" ) == CidRetireResult::Retired, "old path CID not retired" );
  require( migrating.retire_path( "old" ) == CidRetireResult::NoPath, "old path retired twice" );
  require( migrating.active_count() == 1 && migrating.pending_retirements().size() == 1,
           "local retirement state incorrect" );
  require( migrating.on_new_id( { 2, 0, "new", token2 } ) == CidAcceptResult::Accepted,
           "replacement for locally retired ID rejected" );
  require( migrating.select_for_path( "third" )->sequence == 2, "new path did not get replacement ID" );
  require( migrating.on_new_id( next ) == CidAcceptResult::Duplicate, "old ID duplicate rejected" );
  require( migrating.pending_retirements().size() == 1, "local retirement queued twice" );

  PeerConnectionIds bounded { "initial", 2, 4 };
  require( bounded.on_new_id( { 1, 1, "one", token1 } ) == CidAcceptResult::Accepted,
           "first bounded rotation rejected" );
  require( bounded.on_new_id( { 2, 2, "two", token2 } ) == CidAcceptResult::Accepted,
           "second bounded rotation rejected" );
  require( bounded.on_new_id( { 3, 3, "three", token3 } ) == CidAcceptResult::Accepted,
           "third bounded rotation rejected" );
  require( bounded.on_new_id( { 4, 4, "four", token1 } ) == CidAcceptResult::ResourceLimitError,
           "history limit ignored" );
  require( bounded.active_count() == 1 && bounded.retire_prior_to() == 3, "history limit changed state" );

  PeerConnectionIds pending { "initial", 2, 8 };
  for ( uint64_t sequence = 1; sequence <= 4; ++sequence ) {
    require( pending.on_new_id( { sequence, sequence, "cid" + std::to_string( sequence ), token1 } )
               == CidAcceptResult::Accepted,
             "pending retirement setup failed" );
  }
  require( pending.pending_retirements().size() == 4, "pending retirement setup count wrong" );
  require( pending.on_new_id( { 5, 5, "cid5", token2 } ) == CidAcceptResult::ConnectionIdLimitError,
           "pending retirement limit ignored" );
  require( pending.retire_prior_to() == 4 && pending.active_count() == 1,
           "pending retirement limit changed state" );
}
