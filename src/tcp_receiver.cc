#include "tcp_receiver.hh"

#include <algorithm>
#include <cstdint>
#include <utility>

using namespace std;

void TCPReceiver::receive( TCPSenderMessage message )
{
  if ( message.RST ) {
    reassembler_.reader().set_error();
    return;
  }
  if ( reassembler_.reader().has_error() ) {
    return;
  }

  // Only the first SYN establishes the zero point. A segment without it
  // cannot be placed in the byte stream yet.
  if ( !isn_.has_value() ) {
    if ( !message.SYN ) {
      return;
    }
    isn_ = message.seqno;
  }

  const uint64_t checkpoint = reassembler_.writer().bytes_pushed() + 1;
  const uint64_t absolute_seqno = message.seqno.unwrap( *isn_, checkpoint );
  if ( absolute_seqno == 0 && !message.SYN ) {
    return;
  }

  // SYN occupies absolute sequence number zero, but is not a stream byte.
  const uint64_t first_index = absolute_seqno + message.SYN - 1;
  reassembler_.insert( first_index, move( message.payload ), message.FIN );
}

TCPReceiverMessage TCPReceiver::send() const
{
  TCPReceiverMessage response {};
  if ( isn_.has_value() ) {
    // Acknowledge SYN, assembled bytes, and FIN only after it is assembled.
    const uint64_t next_absolute = 1 + reassembler_.writer().bytes_pushed() + reassembler_.writer().is_closed();
    response.ackno = Wrap32::wrap( next_absolute, *isn_ );
  }

  response.window_size
    = static_cast<uint16_t>( min<uint64_t>( reassembler_.writer().available_capacity(), UINT16_MAX ) );
  response.RST = reassembler_.reader().has_error();
  return response;
}
