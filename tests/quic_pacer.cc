#include "quic/pacer.hh"

#include <iostream>
#include <limits>
#include <stdexcept>

using namespace quic;
namespace {
void require( bool value, const char* message )
{
  if ( !value )
    throw std::runtime_error( message );
}
void bucket()
{
  PacketPacer p;
  require( !p.deadline( 0, 12000, 12000, 333000 ), "initial burst" );
  p.sent( 0, 12000, 12000, 333000 );
  require( p.deadline( 0, 1200, 12000, 333000 ) == 26640, "rate deadline" );
  require( p.deadline( 26639, 1200, 12000, 333000 ) == 26640, "fractional refill" );
  require( !p.deadline( 26640, 1200, 12000, 333000 ), "exact deadline" );
  p.sent( 26640, 1200, 12000, 333000 );
  require( p.deadline( 26640, 1, 12000, 333000 ) == 26663, "round up fractional wait" );
  require( !p.deadline( 1000000000, 12000, 12000, 333000 ), "idle refill" );
  p.sent( 1000000000, 12000, 12000, 333000 );
  require( p.deadline( 1000000000, 1200, 12000, 333000 ) == 1000026640, "idle over-credit" );
}
void parameters_and_probes()
{
  PacketPacer p;
  p.sent( 0, 12000, 12000, 100000 );
  // 1000us accrued at 0.15 bytes/us, not the new 0.03 bytes/us.
  require( p.deadline( 1000, 1200, 2400, 100000 ) == 36000, "retroactive rate change" );
  p.sent( 1000, 1200, 2400, 100000 ); // PTO bypass consumes available credit.
  require( p.deadline( 1000, 1200, 2400, 100000 ) == 41000, "probe credit debit" );
  require( !p.deadline( 1000000, 2400, 2400, 100000 ), "window shrink cap" );
  p.sent( 1000000, 2400, 2400, 100000 );
  require( p.deadline( 1000000, 1, 2400, 100000 ).has_value(), "shrink left excess credit" );
}
void bounds()
{
  PacketPacer p;
  p.sent( UINT64_MAX - 1, 12000, 12000, 333000 );
  require( p.deadline( UINT64_MAX - 1, 1200, 12000, 333000 ) == UINT64_MAX, "deadline saturation" );
  bool reversed = false;
  try {
    p.deadline( 0, 1200, 12000, 333000 );
  } catch ( const std::logic_error& ) {
    reversed = true;
  }
  require( reversed, "reverse clock accepted" );
  for ( const double rtt : { 0., -1., std::numeric_limits<double>::infinity() } ) {
    PacketPacer invalid;
    bool rejected = false;
    try {
      invalid.deadline( 0, 1200, 12000, rtt );
    } catch ( const std::invalid_argument& ) {
      rejected = true;
    }
    require( rejected, "invalid RTT accepted" );
  }
}
void capacity_growth()
{
  PacketPacer p;
  p.sent( 0, 2400, 2400, 100000 );
  require( p.deadline( 1000000, 12000, 12000, 100000 ) == 1064000,
           "window growth retroactively enlarged old idle bucket" );
}
}
int main()
{
  try {
    bucket();
    parameters_and_probes();
    bounds();
    capacity_growth();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
