#include "quic/anti_amplification.hh"

#include <cstdint>
#include <limits>
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
  AntiAmplificationBudget path { AmplificationRole::Responder };
  require( path.remaining_bytes() == 0, "new unvalidated path has send credit" );
  require( !path.record_sent( 1 ), "sent without receiving from new address" );
  path.record_received( 400 );
  require( path.remaining_bytes() == 1200, "three-times receive credit incorrect" );
  require( path.record_sent( 1200 ), "exact budget rejected" );
  require( path.remaining_bytes() == 0, "spent budget remains available" );
  require( !path.record_sent( 1 ), "over-budget send accepted" );
  require( path.record_sent( 0 ), "zero-byte send rejected" );
  path.record_received( 100 );
  require( path.remaining_bytes() == 300, "later datagram did not replenish credit" );
  require( path.record_sent( 299 ), "partial send rejected" );
  require( !path.record_sent( 2 ), "partial send exceeded budget" );
  require( path.remaining_bytes() == 1, "rejected send consumed credit" );

  AntiAmplificationBudget another_path { AmplificationRole::Responder };
  require( another_path.remaining_bytes() == 0, "new address inherited old path's credit" );
  path.validate_address();
  require( path.address_validated(), "address validation not recorded" );
  require( !path.remaining_bytes().has_value(), "validated address still has a send cap" );
  require( path.record_sent( std::numeric_limits<uint64_t>::max() ), "validated address send rejected" );
  require( !another_path.record_sent( 1 ), "other address became validated" );

  AntiAmplificationBudget huge { AmplificationRole::Responder };
  const uint64_t large_receive = std::numeric_limits<uint64_t>::max() / 3 + 1;
  huge.record_received( large_receive );
  require( huge.remaining_bytes() == std::numeric_limits<uint64_t>::max(), "credit arithmetic overflowed" );
  require( huge.record_sent( std::numeric_limits<uint64_t>::max() ), "saturated credit rejected" );
  require( huge.remaining_bytes() == 0, "saturated credit overspent" );

  // RFC 9000 Section 8 note: client Initial and active migration initiate
  // contact; the three-times response limit does not apply to those sends.
  AntiAmplificationBudget initiator { AmplificationRole::Initiator };
  require( !initiator.address_validated(), "initiator was incorrectly marked validated" );
  require( !initiator.remaining_bytes().has_value(), "initiator incorrectly limited" );
  require( initiator.record_sent( 1200 ), "client Initial blocked by response budget" );
}
