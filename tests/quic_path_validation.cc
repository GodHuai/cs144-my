#include "quic/path_validation.hh"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

void require( bool value, std::string_view message )
{
  if ( !value ) {
    throw std::runtime_error( std::string { message } );
  }
}

int main()
{
  const std::array<uint8_t, 8> first { 1, 2, 3, 4, 5, 6, 7, 8 };
  const std::array<uint8_t, 8> second { 9, 10, 11, 12, 13, 14, 15, 16 };
  const std::array<uint8_t, 8> unrelated { 0, 0, 0, 0, 0, 0, 0, 0 };

  PathValidation path;
  require( path.state() == PathValidationState::Idle, "new path is not idle" );
  require( !path.start( first, 1200, 100, 0 ), "zero timeout accepted" );
  require( path.state() == PathValidationState::Idle, "rejected start changed state" );
  require( path.start( first, 1199, 100, 300 ), "small challenge start rejected" );
  require( path.state() == PathValidationState::Validating, "challenge did not start validation" );
  require( !path.on_response( unrelated, 120 ), "unrelated response accepted" );
  require( !path.record_sent_challenge( first, 1200, 120, 300 ), "duplicate challenge data accepted" );
  require( path.on_response( first, 130 ), "matching response rejected" );
  require( path.state() == PathValidationState::AddressValidated,
           "small probe response incorrectly validated path MTU" );
  require( !path.on_response( first, 131 ), "replayed response accepted" );
  require( path.record_sent_challenge( second, 1200, 131, 300 ), "MTU challenge rejected" );
  require( path.on_response( second, 140 ), "MTU response rejected" );
  require( path.state() == PathValidationState::Validated, "padded response did not validate MTU" );
  require( !path.expire( 500 ), "validated path expired" );

  // The first response can arrive after a retry was sent; token matching
  // succeeds even if the packet carrying the response took another path.
  PathValidation retried;
  require( retried.start( first, 1200, 20, 30 ), "retry setup rejected" );
  require( retried.record_sent_challenge( second, 1200, 25, 30 ), "retry challenge rejected" );
  require( retried.on_response( first, 49 ), "out-of-order response rejected" );
  require( retried.state() == PathValidationState::Validated, "out-of-order response did not validate" );
  require( !retried.on_response( second, 49 ), "response after success was accepted" );

  PathValidation late_small_probe;
  require( late_small_probe.start( first, 1199, 100, 30 ), "late small probe setup rejected" );
  require( late_small_probe.on_response( first, 129 ), "late address response rejected" );
  require( late_small_probe.record_sent_challenge( second, 1200, 129, 30 ), "late MTU follow-up rejected" );
  require( late_small_probe.on_response( second, 130 ), "prompt MTU response inherited expired first deadline" );

  PathValidation concurrent_probes;
  require( concurrent_probes.start( first, 1199, 100, 30 ), "concurrent probe setup rejected" );
  require( concurrent_probes.record_sent_challenge( second, 1200, 110, 30 ), "early MTU probe rejected" );
  require( concurrent_probes.on_response( first, 129 ), "concurrent address response rejected" );
  require( concurrent_probes.on_response( second, 130 ), "early MTU probe lost its own deadline" );

  PathValidation expired;
  require( expired.start( first, 1200, 10, 30 ), "expiry setup rejected" );
  require( !expired.expire( 39 ), "path expired before deadline" );
  require( !expired.on_response( first, 40 ), "response at deadline accepted" );
  require( expired.state() == PathValidationState::Failed, "expired path not marked failed" );
  require( !expired.record_sent_challenge( second, 1200, 40, 30 ), "challenge added after expiry" );
  require( expired.start( second, 1200, 50, 30 ), "restart after failure rejected" );
  require( !expired.on_response( first, 51 ), "old attempt's response accepted" );
  require( expired.on_response( second, 51 ), "new attempt's response rejected" );
}
