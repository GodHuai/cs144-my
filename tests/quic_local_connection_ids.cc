#include "quic/local_connection_ids.hh"

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( const bool condition, const std::string_view message )
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

  LocalConnectionIds ids { "initial", 2 };
  require( ids.active_count() == 1 && ids.lookup( "initial" ) == 0, "initial CID missing" );
  require( !ids.needs_replacement(), "initial CID should not imply replacement request" );
  const auto one = ids.issue( "one", token1 );
  require( one && one->sequence == 1 && one->retire_prior_to == 0 && one->cid == "one",
           "first issued frame wrong" );
  require( !ids.issue( "two", token2 ), "peer active limit exceeded" );
  require( !ids.issue( "one", token2 ), "CID duplicate accepted" );
  require( !ids.issue( "two", token1 ), "reset token duplicate accepted" );
  require( ids.on_retire( { 1 }, "initial" ) == LocalRetireResult::ProtocolViolation,
           "unsent CID retirement accepted" );
  require( ids.mark_sent( 1 ), "sent CID was not marked" );
  require( ids.on_retire( { 1 }, "one" ) == LocalRetireResult::ProtocolViolation, "retired packet's own DCID" );
  require( ids.on_retire( { 2 }, "initial" ) == LocalRetireResult::ProtocolViolation, "future sequence retired" );
  require( ids.active_count() == 2, "invalid retirement changed state" );
  require( ids.on_retire( { 1 }, "initial" ) == LocalRetireResult::Retired, "issued CID not retired" );
  require( !ids.lookup( "one" ) && ids.active_count() == 1, "retired CID still routable" );
  require( ids.needs_replacement(), "retirement did not request replacement" );
  require( ids.on_retire( { 1 }, "initial" ) == LocalRetireResult::Duplicate, "duplicate retirement rejected" );
  const auto two = ids.issue( "two", token2 );
  require( two && two->sequence == 2 && ids.active_count() == 2, "replacement sequence wrong" );
  require( ids.mark_sent( 2 ), "replacement not marked sent" );
  require( !ids.needs_replacement(), "replacement request not cleared" );
  require( ids.on_retire( { 0 }, "two" ) == LocalRetireResult::Retired, "initial CID not retired" );
  require( !ids.lookup( "initial" ) && ids.lookup( "two" ) == 2, "routing table wrong after initial retirement" );

  LocalConnectionIds preferred { "initial", 2 };
  require( preferred.reserve_preferred_address( "preferred", token1 ), "preferred address rejected" );
  require( preferred.lookup( "preferred" ) == 1 && preferred.active_count() == 2,
           "preferred address sequence wrong" );
  require( preferred.on_retire( { 1 }, "initial" ) == LocalRetireResult::ProtocolViolation,
           "unsent preferred address retired" );
  require( preferred.mark_sent( 1 ), "preferred address not marked sent" );
  require( !preferred.issue( "ordinary", token2 ), "preferred address ignored peer limit" );
  require( preferred.on_retire( { 1 }, "initial" ) == LocalRetireResult::Retired,
           "preferred address could not retire" );
  require( preferred.issue( "ordinary", token2 )->sequence == 2, "ordinary sequence after preferred wrong" );

  LocalConnectionIds zero { "", 2 };
  require( zero.lookup( "" ) == 0, "zero-length initial CID missing" );
  require( !zero.issue( "one", token1 ), "issued after zero-length CID" );
  require( !zero.reserve_preferred_address( "preferred", token2 ), "preferred CID after zero-length CID" );
  require( zero.on_retire( { 0 }, "" ) == LocalRetireResult::ProtocolViolation,
           "retirement accepted after zero-length CID" );

  LocalConnectionIds bounded { "initial", 10, 3 };
  require( bounded.issue( "one", token1 ).has_value(), "bounded first issue failed" );
  require( bounded.mark_sent( 1 ), "bounded first issue not sent" );
  require( bounded.on_retire( { 1 }, "initial" ) == LocalRetireResult::Retired, "bounded retire failed" );
  require( bounded.issue( "two", token2 ).has_value(), "bounded second issue failed" );
  require( bounded.mark_sent( 2 ), "bounded second issue not sent" );
  require( bounded.on_retire( { 2 }, "initial" ) == LocalRetireResult::Retired, "bounded second retire failed" );
  require( !bounded.issue( "three", token3 ), "total issue limit ignored" );
}
