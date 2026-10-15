#include "tcp_sender.hh"
#include "tcp_config.hh"

#include <algorithm>
#include <utility>

using namespace std;

uint64_t TCPSender::sequence_numbers_in_flight() const
{
  return in_flight_;
}

uint64_t TCPSender::consecutive_retransmissions() const
{
  return consecutive_retransmissions_;
}

void TCPSender::push( const TransmitFunction& transmit )
{
  // A zero window permits a one-sequence-number probe, but does not change
  // the receiver's remembered advertised window.
  const uint64_t right_edge = acknowledged_ + max<uint64_t>( window_size_, 1 );

  while ( next_seqno_ < right_edge ) {
    TCPSenderMessage message = make_empty_message();
    uint64_t space = right_edge - next_seqno_;

    if ( next_seqno_ == 0 ) {
      message.SYN = true;
      --space;
    }

    const uint64_t payload_size
      = min( { space, uint64_t { TCPConfig::MAX_PAYLOAD_SIZE }, input_.reader().bytes_buffered() } );
    if ( payload_size > 0 ) {
      read( input_.reader(), payload_size, message.payload );
      space -= message.payload.size();
    }

    // FIN uses a sequence number and can be attached only if the whole
    // outbound stream has now been consumed and the window has room.
    if ( !fin_sent_ && input_.reader().is_finished() && space > 0 ) {
      message.FIN = true;
      fin_sent_ = true;
    }

    if ( message.sequence_length() == 0 ) {
      break;
    }

    next_seqno_ += message.sequence_length();
    in_flight_ += message.sequence_length();
    outstanding_.push_back( { message, next_seqno_ } );
    transmit( message );

    // Later new segments must not postpone the oldest segment's deadline.
    if ( !timer_running_ ) {
      timer_running_ = true;
      timer_elapsed_ms_ = 0;
    }
  }
}

TCPSenderMessage TCPSender::make_empty_message() const
{
  TCPSenderMessage message {};
  message.seqno = Wrap32::wrap( next_seqno_, isn_ );
  message.RST = input_.has_error();
  return message;
}

void TCPSender::receive( const TCPReceiverMessage& msg )
{
  if ( msg.RST ) {
    input_.set_error();
  }

  if ( !msg.ackno.has_value() ) {
    window_size_ = msg.window_size;
    return;
  }

  const uint64_t ack = msg.ackno->unwrap( isn_, next_seqno_ );
  if ( ack > next_seqno_ || ack < acknowledged_ ) {
    return; // An impossible or stale ACK cannot advance the sender.
  }

  window_size_ = msg.window_size;
  if ( ack == acknowledged_ ) {
    return; // A repeated ACK may update the window, but not the timer.
  }

  acknowledged_ = ack;
  while ( !outstanding_.empty() && outstanding_.front().end <= ack ) {
    in_flight_ -= outstanding_.front().message.sequence_length();
    outstanding_.pop_front();
  }

  current_RTO_ms_ = initial_RTO_ms_;
  consecutive_retransmissions_ = 0;
  timer_elapsed_ms_ = 0;
  timer_running_ = !outstanding_.empty();
}

void TCPSender::tick( uint64_t ms_since_last_tick, const TransmitFunction& transmit )
{
  if ( !timer_running_ || outstanding_.empty() ) {
    return;
  }

  // Compare before addition to avoid overflowing the accumulated elapsed time.
  if ( ms_since_last_tick < current_RTO_ms_ - timer_elapsed_ms_ ) {
    timer_elapsed_ms_ += ms_since_last_tick;
    return;
  }

  transmit( outstanding_.front().message );
  if ( window_size_ > 0 ) {
    ++consecutive_retransmissions_;
    current_RTO_ms_ *= 2;
  }
  timer_elapsed_ms_ = 0;
}
