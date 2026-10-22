#include "quic/acknowledgments.hh"

#include <iostream>
#include <stdexcept>

using namespace quic;
namespace {
void require( bool condition, const char* message )
{
  if ( !condition )
    throw std::runtime_error( message );
}
void receive_ranges()
{
  PacketAcknowledgments a;
  require( a.received( PacketKind::Initial, 2, true, 100 ), "first receive" );
  a.received( PacketKind::Initial, 0, true, 110 );
  auto ack = a.pending_ack( PacketKind::Initial, 200, 3 );
  require( ack && ack->frame.ranges.size() == 2 && ack->frame.ranges[0].smallest == 2
             && ack->frame.ranges[1].largest == 0 && ack->frame.ack_delay == 0,
           "ranges or Initial delay" );
  const auto old_generation = ack->generation;
  a.received( PacketKind::Initial, 1, true, 210 );
  a.ack_sent( PacketKind::Initial, old_generation );
  ack = a.pending_ack( PacketKind::Initial, 220, 3 );
  require( ack && ack->frame.ranges.size() == 1 && ack->frame.ranges[0].largest == 2
             && ack->frame.ranges[0].smallest == 0,
           "merge or stale snapshot" );
  a.ack_sent( PacketKind::Initial, ack->generation );
  require( !a.pending_ack( PacketKind::Initial, 230, 3 ), "pending not cleared" );
  require( !a.received( PacketKind::Initial, 2, true, 240 ), "duplicate accepted" );
  require( a.pending_ack( PacketKind::Initial, 250, 3 ).has_value(), "duplicate not re-ACKed" );
  a.received( PacketKind::OneRtt, 5, false, 1000 );
  require( !a.pending_ack( PacketKind::OneRtt, 1100, 3 ), "ACK-only caused ACK loop" );
  a.received( PacketKind::OneRtt, 3, true, 1100 );
  ack = a.pending_ack( PacketKind::OneRtt, 1160, 3 );
  require( ack && ack->frame.ack_delay == 20 && ack->frame.ranges.front().largest == 5,
           "delay must use largest packet reception, not latest arrival" );
  require( !a.pending_ack( PacketKind::Handshake, 1160, 3 ), "packet spaces mixed" );
  for ( uint64_t n = 10; n < 10000; n += 2 )
    a.received( PacketKind::OneRtt, n, true, n );
  ack = a.pending_ack( PacketKind::OneRtt, 10000, 3 );
  require( ack && ack->frame.ranges.size() == 32, "ACK range bound" );
  a.ack_sent( PacketKind::OneRtt, ack->generation );
  require( !a.received( PacketKind::OneRtt, 0, true, 10001 ) && !a.pending_ack( PacketKind::OneRtt, 10002, 3 ),
           "retired receive record rescheduled ACK" );
}
void sent_history()
{
  PacketAcknowledgments a;
  AckFrame ack { 0, { { 0, 0 } }, std::nullopt };
  require( !a.valid_ack( PacketKind::Initial, ack ), "unsent packet accepted" );
  a.sent( PacketKind::Initial, 0, true );
  a.sent( PacketKind::Initial, 1, false );
  a.sent( PacketKind::Initial, 2, true );
  ack.ranges = { { 1, 2 } };
  require( a.valid_ack( PacketKind::Initial, ack ) && !a.valid_ack( PacketKind::Handshake, ack ), "send spaces" );
  a.apply_ack( PacketKind::Initial, ack );
  a.apply_ack( PacketKind::Initial, ack );
  require( a.outstanding( PacketKind::Initial ) == 1, "ACK not idempotent" );
  ack.ranges = { { 0, 3 } };
  require( !a.valid_ack( PacketKind::Initial, ack ) && a.outstanding( PacketKind::Initial ) == 1,
           "invalid ACK mutated history" );
  for ( uint64_t n = 0; n < 4096; ++n )
    a.sent( PacketKind::OneRtt, n, true );
  require( !a.can_send( PacketKind::OneRtt ) && a.outstanding( PacketKind::OneRtt ) == 4096, "send bound" );
  a.sent( PacketKind::OneRtt, 4096, false ); // ACK-only output still permitted.
  ack.ranges = { { 0, 4096 } };
  a.apply_ack( PacketKind::OneRtt, ack );
  require( a.can_send( PacketKind::OneRtt ) && a.outstanding( PacketKind::OneRtt ) == 0, "ACK release" );
  bool rejected = false;
  try {
    a.sent( PacketKind::OneRtt, 4098, true );
  } catch ( const std::logic_error& ) {
    rejected = true;
  }
  require( rejected, "send history permitted skipped unsent packet number" );
  a.discard( PacketKind::Initial );
  require( !a.pending_ack( PacketKind::Initial, 10000, 3 ) && a.outstanding( PacketKind::Initial ) == 0,
           "discard retained state" );
}
}
int main()
{
  try {
    receive_ranges();
    sent_history();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
