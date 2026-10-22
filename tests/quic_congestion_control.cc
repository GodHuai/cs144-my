#include "quic/congestion_control.hh"

#include <iostream>
#include <stdexcept>

using namespace quic;
namespace {
void require( bool value, const char* message )
{
  if ( !value )
    throw std::runtime_error( message );
}
void window_and_growth()
{
  NewReno cc;
  require( cc.stats().window == 12000 && cc.stats().bytes_in_flight == 0, "initial window" );
  cc.sent( 12000 );
  require( !cc.can_send( 1 ) && cc.can_send( 1200, true ), "window/probe boundary" );
  cc.acknowledged( 1200, 0, false );
  require( cc.stats().window == 13200 && cc.stats().bytes_in_flight == 10800, "slow start at zero time" );
  cc.acknowledged( 1200, 1, true );
  require( cc.stats().window == 13200 && cc.stats().bytes_in_flight == 9600, "limited ACK grew window" );
  cc.discard( 9600 );
  require( cc.stats().bytes_in_flight == 0 && cc.stats().window == 13200, "discard changed cwnd" );
}
void recovery_and_avoidance()
{
  NewReno cc;
  cc.sent( 12000 );
  cc.lost( 1200, 0, 100 );
  require( cc.stats().window == 6000, "first loss at timestamp zero" );
  cc.lost( 1200, 1, 101 );
  require( cc.stats().window == 6000, "same epoch cut twice" );
  cc.acknowledged( 1200, 100, false );
  require( cc.stats().window == 6000, "recovery ACK grew cwnd" );
  cc.acknowledged( 1200, 102, false );
  require( cc.stats().window == 6240, "avoidance increment" );
  cc.lost( 1200, 103, 200 );
  cc.lost( 1200, 201, 300 );
  require( cc.stats().window == 2400, "minimum window" );
  require( cc.stats().slow_start_threshold == 1560, "ssthresh must halve before clamping cwnd" );
  cc.discard( cc.stats().bytes_in_flight );
  bool rejected = false;
  try {
    cc.discard( 1 );
  } catch ( const std::logic_error& ) {
    rejected = true;
  }
  require( rejected, "flight underflow accepted" );
}
void fractional_credit()
{
  NewReno cc;
  cc.sent( 12000 );
  cc.lost( 1200, 0, 1 );
  cc.discard( 10800 );
  for ( unsigned i = 0; i < 5; ++i ) {
    cc.sent( 1 );
    cc.acknowledged( 1, 2 + i, false );
  }
  require( cc.stats().window == 6001, "small ACK credit lost to integer division" );
}
}
int main()
{
  try {
    window_and_growth();
    recovery_and_avoidance();
    fractional_credit();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
