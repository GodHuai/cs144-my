#include "quic/packet_recovery.hh"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>

using namespace quic;
namespace {
void require( bool ok, const char* message )
{
  if ( !ok )
    throw std::runtime_error( message );
}
auto ping()
{
  return std::make_shared<RecoveryData>( PingFrame {} );
}
AckFrame ack( uint64_t first, uint64_t last, uint64_t delay = 0 )
{
  return { delay, { { first, last } }, std::nullopt };
}
void rtt_samples()
{
  PacketRecovery r;
  RecoveryContext c;
  c.confirmed = c.peer_validated = true;
  r.sent( PacketKind::OneRtt, 0, 1000, ping() );
  r.sent( PacketKind::OneRtt, 1, 2000, nullptr );
  r.acknowledged( PacketKind::OneRtt, ack( 0, 1 ), 102000, c );
  require( r.rtt().latest_ms() == 100, "RTT must sample ACK-only largest" );
  r.acknowledged( PacketKind::OneRtt, ack( 0, 1 ), 202000, c );
  require( r.rtt().latest_ms() == 100, "duplicate ACK sampled" );
  r.sent( PacketKind::OneRtt, 2, 202000, nullptr );
  r.acknowledged( PacketKind::OneRtt, ack( 2, 2 ), 402000, c );
  require( r.rtt().latest_ms() == 100, "ACK-only ACK sampled" );
  r.sent( PacketKind::OneRtt, 3, 402000, ping() );
  r.acknowledged( PacketKind::OneRtt, ack( 3, 3, 2500 ), 532000, c );
  require( std::abs( r.rtt().smoothed_ms() - 101.25 ) < 0.001, "ACK delay exponent or microseconds" );
  r.sent( PacketKind::Handshake, 0, 600000, ping() );
  r.acknowledged( PacketKind::Handshake, ack( 0, 0, 999999 ), 730000, c );
  require( r.rtt().latest_ms() == 130, "Handshake sample" );
  require( std::abs( r.rtt().smoothed_ms() - 104.84375 ) < 0.001, "Handshake ACK delay must be ignored" );
  PacketRecovery zero;
  zero.sent( PacketKind::Initial, 0, 1, ping() );
  zero.acknowledged( PacketKind::Initial, ack( 0, 0 ), 1, c );
  require( zero.rtt().latest_ms() == 0.001, "same-tick RTT must be positive" );
}
void losses_and_probes()
{
  PacketRecovery r;
  RecoveryContext c;
  c.validation_probe_space = PacketKind::Initial;
  require( !r.deadline( c ), "timer before first handoff" );
  c.validation_probe_space.reset();
  auto data = ping();
  r.sent( PacketKind::Initial, 0, 0, data );
  require( r.deadline( c ) == 999000, "initial PTO" );
  r.timeout( 998999, c );
  require( !r.take_pending( PacketKind::Initial ), "premature probe" );
  const auto events = r.timeout( 999000, c );
  require( events[0].empty(), "PTO declared packet lost" );
  const auto probe = r.take_pending( PacketKind::Initial );
  require( probe && probe->probe && probe->data == data, "PTO did not reuse frame identity" );
  require( !r.deadline( c ), "pending handoff repeatedly fires timer" );
  r.sent( PacketKind::Initial, 1, 999000, probe->data );
  require( r.deadline( c ) == 2997000, "global PTO backoff" );
  r.acknowledged( PacketKind::Initial, ack( 0, 0 ), 1000000, c );
  require( data->acknowledged && !r.take_pending( PacketKind::Initial ), "late ACK delivery cancellation" );

  PacketRecovery loss;
  for ( uint64_t pn = 0; pn < 4; ++pn )
    loss.sent( PacketKind::Handshake, pn, pn * 1000, ping() );
  auto released = loss.acknowledged( PacketKind::Handshake, ack( 3, 3 ), 103000, c );
  require( std::find( released.begin(), released.end(), 0 ) != released.end(), "packet threshold loss" );
  require( loss.take_pending( PacketKind::Handshake ).has_value(), "lost frame not queued" );
  require( !loss.take_pending( PacketKind::Initial ), "loss crossed spaces" );
  const auto due = loss.deadline( c );
  require( due && *due == 113500, "time threshold deadline" );
  loss.timeout( *due, c );
  require( loss.take_pending( PacketKind::Handshake ).has_value(), "time threshold loss" );
  loss.discard( PacketKind::Handshake );
  require( !loss.deadline( c ) && !loss.take_pending( PacketKind::Handshake ), "retired recovery state" );

  PacketRecovery app;
  app.sent( PacketKind::OneRtt, 0, 0, ping() );
  require( !app.deadline( c ), "Application PTO before confirmation" );
  c.confirmed = true;
  require( app.deadline( c ) == 1024000, "Application max ACK delay" );
}
void late_delivery_and_backoff()
{
  PacketRecovery r;
  RecoveryContext c;
  auto original = ping();
  r.sent( PacketKind::Handshake, 0, 0, original );
  for ( uint64_t pn = 1; pn < 4; ++pn )
    r.sent( PacketKind::Handshake, pn, pn * 1000, ping() );
  r.acknowledged( PacketKind::Handshake, ack( 3, 3 ), 103000, c );
  r.acknowledged( PacketKind::Handshake, ack( 0, 0 ), 104000, c );
  require( original->acknowledged && !r.take_pending( PacketKind::Handshake ),
           "late original ACK left queued retransmit" );

  PacketRecovery retry;
  c.validation_probe_space = PacketKind::Initial;
  retry.sent( PacketKind::Initial, 0, 0, ping() );
  retry.timeout( 999000, c );
  retry.timeout( 999000, c );
  const auto p = retry.take_pending( PacketKind::Initial );
  require( p && !retry.take_pending( PacketKind::Initial ), "duplicate timer callback queued duplicate probe" );
  retry.sent( PacketKind::Initial, 1, 999000, p->data );
  retry.acknowledged( PacketKind::Initial, ack( 0, 0 ), 1000000, c );
  require( retry.deadline( c ) == 7000000, "Initial ACK improperly reset client backoff" );
  retry.timeout( 7000000, c );
  const auto validation = retry.take_pending( PacketKind::Initial );
  require( validation && std::holds_alternative<PingFrame>( validation->data->frame ), "anti-deadlock probe" );

  PacketRecovery huge;
  c.validation_probe_space.reset();
  c.confirmed = true;
  for ( uint64_t pn = 0; pn < 4; ++pn )
    huge.sent( PacketKind::OneRtt, pn, pn, ping() );
  huge.acknowledged( PacketKind::OneRtt, ack( 0, max_packet_number ), 1000, c );
  require( !huge.deadline( c ), "sparse huge ACK did not clear bounded metadata" );
}
void early_loss_timer_callback()
{
  PacketRecovery r;
  RecoveryContext c;
  c.peer_validated = true;
  uint64_t now = 0, pn = 0;
  for ( size_t i = 0; i < 30; ++i ) {
    r.sent( PacketKind::Handshake, pn, now, ping() );
    r.acknowledged( PacketKind::Handshake, ack( pn, pn ), now + 100000, c );
    ++pn;
    now += 200000;
  }
  r.sent( PacketKind::Handshake, pn++, now, ping() );
  r.sent( PacketKind::Handshake, pn, now + 10000, ping() );
  r.acknowledged( PacketKind::Handshake, ack( pn, pn ), now + 1010000, c );
  const auto loss_due = r.deadline( c );
  require( loss_due && *loss_due == now + 1125000, "loss timer priority setup" );
  r.timeout( *loss_due - 1, c );
  require( !r.take_pending( PacketKind::Handshake ), "early loss callback incorrectly fired suppressed PTO" );
}
void physical_flight()
{
  PacketRecovery r;
  RecoveryContext c;
  c.confirmed = c.peer_validated = true;
  auto data = ping();
  r.sent( PacketKind::OneRtt, 0, 0, data, 1200 );
  r.sent( PacketKind::OneRtt, 1, 1, data, 1200 );
  r.acknowledged( PacketKind::OneRtt, ack( 0, 0 ), 100001, c );
  require( data->acknowledged && r.congestion_stats().bytes_in_flight == 1200,
           "logical delivery removed physical retransmission" );
  r.acknowledged( PacketKind::OneRtt, ack( 1, 1 ), 100002, c );
  require( r.congestion_stats().bytes_in_flight == 0, "physical retransmit ACK not released" );
  r.sent( PacketKind::Initial, 0, 200000, nullptr, 1200, true );
  r.sent( PacketKind::OneRtt, 2, 200001, nullptr, 30 );
  require( r.congestion_stats().bytes_in_flight == 1200, "padding/pure ACK flight distinction" );
  require( !r.deadline( c ), "padded ACK-only armed PTO" );
  r.discard( PacketKind::Initial );
  require( r.congestion_stats().bytes_in_flight == 0 && r.congestion_stats().window == 12000,
           "discard debited twice or changed window" );
  r.discard( PacketKind::Initial );

  PacketRecovery loss;
  for ( uint64_t pn = 0; pn < 4; ++pn )
    loss.sent( PacketKind::Handshake, pn, pn, ping(), 1200 );
  loss.acknowledged( PacketKind::Handshake, ack( 3, 3 ), 100003, c );
  require( loss.congestion_stats().bytes_in_flight == 2400 && loss.congestion_stats().window == 6000,
           "packet loss congestion event" );
  loss.acknowledged( PacketKind::Handshake, ack( 0, 0 ), 100004, c );
  require( loss.congestion_stats().bytes_in_flight == 2400 && loss.congestion_stats().window == 6000,
           "late lost ACK changed physical flight or cwnd" );
  loss.discard( PacketKind::Handshake );
  require( loss.congestion_stats().bytes_in_flight == 0, "space discard leaked flight" );

  PacketRecovery redundant;
  auto shared = ping();
  redundant.sent( PacketKind::OneRtt, 0, 0, shared, 1200 );
  redundant.sent( PacketKind::OneRtt, 1, 1, shared, 1200 );
  redundant.sent( PacketKind::OneRtt, 4, 2, nullptr, 30 );
  redundant.acknowledged( PacketKind::OneRtt, AckFrame { 0, { { 4, 4 }, { 0, 0 } }, std::nullopt }, 100002, c );
  require( redundant.congestion_stats().bytes_in_flight == 0 && redundant.congestion_stats().window == 6000,
           "physically lost redundant copy was hidden by logical delivery" );
  require( !redundant.take_pending( PacketKind::OneRtt ), "delivered redundant loss queued retransmission" );

  PacketRecovery bounded;
  for ( uint64_t pn = 0; pn < 4096; ++pn )
    bounded.sent( PacketKind::Initial, pn, pn, nullptr, 1200, true );
  require( !bounded.can_send( PacketKind::Initial, 1200, true, true, true ),
           "probe bypassed physical metadata capacity" );
  require( bounded.can_send( PacketKind::Initial, 30, false, false ), "capacity blocked pure ACK" );
  bounded.discard( PacketKind::Initial );
  require( bounded.congestion_stats().bytes_in_flight == 0, "capacity discard leaked bytes" );
}
void logical_delivery_callback()
{
  PacketRecovery r;
  RecoveryContext c;
  c.confirmed = c.peer_validated = true;
  auto shared = std::make_shared<RecoveryData>( StreamFrame { 0, 0, "abc", true, true, true } );
  r.sent( PacketKind::OneRtt, 0, 0, shared, 30 );
  r.sent( PacketKind::OneRtt, 1, 1, shared, 30 );
  std::vector<std::string> delivered;
  auto receive = [&]( const Frame& f ) { delivered.push_back( std::get<StreamFrame>( f ).data ); };
  r.acknowledged( PacketKind::OneRtt, ack( 1, 1 ), 2, c, receive );
  require( delivered == std::vector<std::string> { "abc" } && r.congestion_stats().bytes_in_flight == 30,
           "logical callback must preserve other physical flight" );
  r.acknowledged( PacketKind::OneRtt, ack( 0, 0 ), 3, c, receive );
  r.acknowledged( PacketKind::OneRtt, ack( 0, 1 ), 4, c, receive );
  require( delivered.size() == 1 && r.congestion_stats().bytes_in_flight == 0,
           "duplicate logical copy called delivery twice" );
}
}
int main()
{
  try {
    rtt_samples();
    losses_and_probes();
    late_delivery_and_backoff();
    early_loss_timer_callback();
    physical_flight();
    logical_delivery_callback();
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
