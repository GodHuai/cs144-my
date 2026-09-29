#include "byte_stream.hh"

#include <algorithm>

using namespace std;

ByteStream::ByteStream( uint64_t capacity ) : buffer_( capacity ), capacity_( capacity ) {}

bool Writer::is_closed() const
{
  return closed_;
}

void Writer::push( string data )
{
  if ( closed_ || capacity_ == 0 ) {
    return;
  }

  const uint64_t count = min<uint64_t>( data.size(), available_capacity() );
  const uint64_t first = min<uint64_t>( count, capacity_ - tail_ );
  copy_n( data.begin(), first, buffer_.begin() + tail_ );
  copy_n( data.begin() + first, count - first, buffer_.begin() );

  tail_ = ( tail_ + count ) % capacity_;
  write_count_ += count;
}

void Writer::close()
{
  closed_ = true;
}

uint64_t Writer::available_capacity() const
{
  return capacity_ - ( write_count_ - read_count_ );
}

uint64_t Writer::bytes_pushed() const
{
  return write_count_;
}

bool Reader::is_finished() const
{
  return closed_ && bytes_buffered() == 0;
}

uint64_t Reader::bytes_popped() const
{
  return read_count_;
}

string_view Reader::peek() const
{
  if ( bytes_buffered() == 0 ) {
    return {};
  }

  const uint64_t contiguous = min<uint64_t>( bytes_buffered(), capacity_ - head_ );
  return { buffer_.data() + head_, contiguous };
}

void Reader::pop( uint64_t len )
{
  const uint64_t count = min( len, bytes_buffered() );
  if ( count == 0 ) {
    return;
  }

  head_ = ( head_ + count ) % capacity_;
  read_count_ += count;
}

uint64_t Reader::bytes_buffered() const
{
  return write_count_ - read_count_;
}
