#include "application_streams.hh"
#include "varint.hh"
#include <algorithm>
#include <iterator>
#include <stdexcept>
namespace quic {
namespace {
uint64_t value( const TransportParameters& p, uint64_t id )
{
  return transport_parameter_integer( p, id ).value_or( 0 );
}
uint64_t add( uint64_t a, uint64_t b )
{
  return b > max_varint - a ? max_varint : a + b;
}
constexpr size_t capacity = 1048576;
}
void ApplicationStreams::validate_local( const TransportParameters& p )
{
  for ( uint64_t id = 4; id <= 7; ++id )
    if ( value( p, id ) > capacity )
      throw std::invalid_argument( "QUIC receive window exceeds 1 MiB" );
  if ( value( p, 8 ) > 128 || value( p, 9 ) > 128 )
    throw std::invalid_argument( "QUIC stream count exceeds 128" );
}
ApplicationStreams::ApplicationStreams( bool server, TransportParameters local, TransportParameters peer )
  : server_( server ), local_( std::move( local ) ), peer_( std::move( peer ) )
{
  validate_local( local_ );
  send_limit_ = value( peer_, 4 );
  recv_limit_ = value( local_, 4 );
  send_counts_ = { value( peer_, 8 ), value( peer_, 9 ) };
  recv_counts_ = { value( local_, 8 ), value( local_, 9 ) };
}
bool ApplicationStreams::local( uint64_t id ) const
{
  return bool( id & 1 ) == server_;
}
bool ApplicationStreams::sends( uint64_t id ) const
{
  return !( id & 2 ) || local( id );
}
bool ApplicationStreams::receives( uint64_t id ) const
{
  return !( id & 2 ) || !local( id );
}
ApplicationStreams::Stream ApplicationStreams::make( uint64_t id ) const
{
  Stream s;
  s.send_limit = value( peer_, ( id & 2 ) ? 7 : ( local( id ) ? 6 : 5 ) );
  s.recv_limit = s.recv_window = value( local_, ( id & 2 ) ? 7 : ( local( id ) ? 5 : 6 ) );
  return s;
}
ApplicationStreams::Stream& ApplicationStreams::get( uint64_t id, bool sending, bool from_peer )
{
  if ( id > max_varint || ( sending ? !sends( id ) : !receives( id ) ) )
    throw Error { 5 };
  const size_t dir = ( id & 2 ) ? 1 : 0;
  if ( local( id ) ) {
    if ( id / 4 >= opened_[dir] )
      throw Error { 5 };
  } else {
    if ( id / 4 >= recv_counts_[dir] )
      throw Error { 4 };
    if ( from_peer )
      peer_opened_[dir] = std::max( peer_opened_[dir], id / 4 + 1 );
    else if ( id / 4 >= peer_opened_[dir] )
      throw Error { 5 };
  }
  auto [it, inserted] = streams_.try_emplace( id );
  if ( inserted )
    it->second = make( id );
  return it->second;
}
std::pair<size_t, uint64_t> ApplicationStreams::key( const Frame& f )
{
  uint64_t id = 0;
  std::visit(
    [&]( const auto& x ) {
      if constexpr ( requires { x.stream_id; } )
        id = x.stream_id;
      else if constexpr ( requires { x.unidirectional; } )
        id = x.unidirectional;
    },
    f );
  return { f.index(), id };
}
void ApplicationStreams::queue( Frame f )
{
  controls_.insert_or_assign( key( f ), std::move( f ) );
}
bool ApplicationStreams::handles( const Frame& f )
{
  return std::holds_alternative<StreamFrame>( f ) || std::holds_alternative<ResetStreamFrame>( f )
         || std::holds_alternative<StopSendingFrame>( f ) || std::holds_alternative<MaxDataFrame>( f )
         || std::holds_alternative<MaxStreamDataFrame>( f ) || std::holds_alternative<MaxStreamsFrame>( f )
         || std::holds_alternative<DataBlockedFrame>( f ) || std::holds_alternative<StreamDataBlockedFrame>( f )
         || std::holds_alternative<StreamsBlockedFrame>( f );
}
std::optional<uint64_t> ApplicationStreams::open( bool uni )
{
  const size_t dir = uni ? 1 : 0;
  if ( opened_[dir] >= send_counts_[dir] ) {
    if ( streams_blocked_[dir] != send_counts_[dir] ) {
      queue( StreamsBlockedFrame { uni, send_counts_[dir] } );
      streams_blocked_[dir] = send_counts_[dir];
    }
    return std::nullopt;
  }
  if ( opened_[dir] >= 128 )
    return std::nullopt;
  const uint64_t id = 4 * opened_[dir]++ + ( server_ ? 1 : 0 ) + ( uni ? 2 : 0 );
  streams_.emplace( id, make( id ) );
  return id;
}
bool ApplicationStreams::write( uint64_t id, std::string_view bytes, bool fin )
{
  try {
    auto& s = get( id, true, false );
    if ( s.fin_requested || s.send_reset || bytes.size() > capacity - buffered_
         || bytes.size() > max_varint - s.send_next - s.queued.size() )
      return false;
    s.queued.append( bytes );
    buffered_ += bytes.size();
    s.fin_requested = fin;
    return true;
  } catch ( const Error& ) {
    return false;
  }
}
void ApplicationStreams::credit( Stream& s, uint64_t id, uint64_t bytes )
{
  consumed_ = add( consumed_, bytes );
  recv_limit_ = add( recv_limit_, bytes );
  queue( MaxDataFrame { recv_limit_ } );
  if ( !s.final ) {
    s.recv_limit = add( s.recv_limit, bytes );
    queue( MaxStreamDataFrame { id, s.recv_limit } );
  }
}
StreamRead ApplicationStreams::read( uint64_t id, size_t maximum )
{
  try {
    auto& s = get( id, false, false );
    if ( s.reset_error )
      return { {}, false, s.reset_error };
    StreamRead out;
    auto it = s.received.begin();
    if ( maximum && it != s.received.end() && it->first == s.read ) {
      const size_t count = std::min( maximum, it->second.size() );
      out.data = it->second.substr( 0, count );
      auto node = s.received.extract( it );
      node.key() += count;
      node.mapped().erase( 0, count );
      if ( !node.mapped().empty() )
        s.received.insert( std::move( node ) );
      s.read += count;
      credit( s, id, count );
    }
    out.eof = s.final && s.read == *s.final;
    return out;
  } catch ( const Error& ) {
    return {};
  }
}
std::vector<uint64_t> ApplicationStreams::ids() const
{
  std::vector<uint64_t> out;
  for ( const auto& [id, s] : streams_ ) {
    (void)s;
    out.push_back( id );
  }
  return out;
}
bool ApplicationStreams::reset( uint64_t id, uint64_t error )
{
  try {
    auto& s = get( id, true, false );
    if ( error > max_varint || s.send_reset || ( s.fin_acked && s.inflight.empty() ) )
      return false;
    buffered_ -= s.queued.size();
    s.queued.clear();
    // Committed copies remain in recovery; retain their admission charge until ACK.
    s.send_reset = true;
    queue( ResetStreamFrame { id, error, s.send_next } );
    return true;
  } catch ( const Error& ) {
    return false;
  }
}
bool ApplicationStreams::stop( uint64_t id, uint64_t error )
{
  try {
    auto& s = get( id, false, false );
    if ( error > max_varint || s.reset_error || ( s.final && s.read == *s.final ) )
      return false;
    queue( StopSendingFrame { id, error } );
    return true;
  } catch ( const Error& ) {
    return false;
  }
}
void ApplicationStreams::accept( uint64_t id, uint64_t end, bool final )
{
  auto& s = get( id, false, true );
  if ( ( s.final && ( end > *s.final || ( final && end != *s.final ) ) ) || ( final && end < s.high ) )
    throw Error { 6 };
  if ( end > s.recv_limit || ( end > s.high && end - s.high > recv_limit_ - received_ ) )
    throw Error { 3 };
  if ( end > s.high ) {
    received_ += end - s.high;
    s.high = end;
  }
  if ( final )
    s.final = end;
}
void ApplicationStreams::apply( const Frame& f )
{
  if ( const auto* input_1 = std::get_if<StreamFrame>( &f ) ) {
    if ( input_1->offset > max_varint || input_1->data.size() > max_varint - input_1->offset )
      throw Error { 7 };
    const uint64_t end = input_1->offset + input_1->data.size();
    accept( input_1->stream_id, end, input_1->fin );
    auto& s = streams_.at( input_1->stream_id );
    if ( s.reset_error || end <= s.read || input_1->data.empty() )
      return;
    uint64_t begin = std::max( s.read, input_1->offset ), merged_end = end;
    auto first = s.received.lower_bound( begin );
    if ( first != s.received.begin() ) {
      auto prev = std::prev( first );
      if ( prev->first + prev->second.size() >= begin )
        first = prev;
    }
    auto last = first;
    uint64_t merged_begin = begin;
    while ( last != s.received.end() && last->first <= merged_end ) {
      merged_begin = std::min( merged_begin, last->first );
      merged_end = std::max( merged_end, last->first + last->second.size() );
      ++last;
    }
    std::string bytes( merged_end - merged_begin, '\0' );
    bytes.replace(
      begin - merged_begin, end - begin, std::string_view( input_1->data ).substr( begin - input_1->offset ) );
    // Retain previously accepted overlap bytes; never redeliver consumed bytes.
    for ( auto it = first; it != last; ++it )
      bytes.replace( it->first - merged_begin, it->second.size(), it->second );
    s.received.erase( first, last );
    s.received.emplace( merged_begin, std::move( bytes ) );
  } else if ( const auto* input_2 = std::get_if<ResetStreamFrame>( &f ) ) {
    accept( input_2->stream_id, input_2->final_size, true );
    auto& s = streams_.at( input_2->stream_id );
    if ( !s.reset_error ) {
      s.reset_error = input_2->error_code;
      s.received.clear();
      credit( s, input_2->stream_id, *s.final - s.read );
      s.read = *s.final;
    }
  } else if ( const auto* input_3 = std::get_if<StopSendingFrame>( &f ) ) {
    (void)get( input_3->stream_id, true, true );
    (void)reset( input_3->stream_id, input_3->error_code );
  } else if ( const auto* input_4 = std::get_if<MaxDataFrame>( &f ) )
    send_limit_ = std::max( send_limit_, input_4->maximum_data );
  else if ( const auto* input_5 = std::get_if<MaxStreamDataFrame>( &f ) ) {
    auto& s = get( input_5->stream_id, true, true );
    s.send_limit = std::max( s.send_limit, input_5->maximum_data );
  } else if ( const auto* input_6 = std::get_if<MaxStreamsFrame>( &f ) ) {
    if ( input_6->maximum_streams > ( uint64_t { 1 } << 60 ) )
      throw Error { 7 };
    auto& count = send_counts_[input_6->unidirectional ? 1 : 0];
    count = std::max( count, input_6->maximum_streams );
  } else if ( const auto* input_7 = std::get_if<StreamDataBlockedFrame>( &f ) ) {
    (void)get( input_7->stream_id, false, true );
  } else if ( const auto* input_8 = std::get_if<StreamsBlockedFrame>( &f ) ) {
    if ( input_8->maximum_streams > ( uint64_t { 1 } << 60 ) )
      throw Error { 7 };
  }
}
std::optional<uint64_t> ApplicationStreams::receive( const std::vector<Frame>& frames )
{
  // Bound storage by advertised credit; stage all application effects before ACK.
  auto staged = *this;
  try {
    for ( const auto& f : frames )
      staged.apply( f );
  } catch ( const Error& e ) {
    return e.code;
  }
  *this = std::move( staged );
  return std::nullopt;
}
std::optional<Frame> ApplicationStreams::pending()
{
  if ( !controls_.empty() )
    return controls_.begin()->second;
  auto begin = last_stream_ ? streams_.upper_bound( *last_stream_ ) : streams_.begin();
  auto it = begin;
  for ( size_t n = 0; n < streams_.size(); ++n ) {
    if ( it == streams_.end() )
      it = streams_.begin();
    auto& [id, s] = *it++;
    if ( !sends( id ) || s.send_reset || s.fin_sent || ( s.queued.empty() && !s.fin_requested ) )
      continue;
    const auto available = std::min( send_limit_ - sent_, s.send_limit - s.send_next );
    if ( s.queued.empty() )
      return StreamFrame { id, s.send_next, {}, true, true, true };
    if ( !available ) {
      if ( send_limit_ == sent_ && data_blocked_ != send_limit_ ) {
        queue( DataBlockedFrame { send_limit_ } );
        data_blocked_ = send_limit_;
      }
      if ( s.send_limit == s.send_next && s.blocked != s.send_limit ) {
        queue( StreamDataBlockedFrame { id, s.send_limit } );
        s.blocked = s.send_limit;
      }
      continue;
    }
    const size_t count = std::min<uint64_t>( 600, std::min<uint64_t>( available, s.queued.size() ) );
    return StreamFrame {
      id, s.send_next, s.queued.substr( 0, count ), s.fin_requested && count == s.queued.size(), true, true };
  }
  return controls_.empty() ? std::nullopt : std::optional<Frame> { controls_.begin()->second };
}
void ApplicationStreams::sent( const Frame& frame )
{
  if ( const auto* f = std::get_if<StreamFrame>( &frame ) ) {
    auto& s = streams_.at( f->stream_id );
    if ( f->offset != s.send_next || f->data != s.queued.substr( 0, f->data.size() ) )
      throw std::logic_error( "STREAM handoff changed" );
    if ( !f->data.empty() )
      s.inflight.emplace( f->offset, f->data );
    s.queued.erase( 0, f->data.size() );
    s.send_next += f->data.size();
    sent_ += f->data.size();
    s.fin_sent = f->fin;
    last_stream_ = f->stream_id;
  } else
    controls_.erase( key( frame ) );
}
void ApplicationStreams::acknowledged( const Frame& frame )
{
  if ( const auto* f = std::get_if<StreamFrame>( &frame ) ) {
    auto it = streams_.find( f->stream_id );
    if ( it == streams_.end() )
      return;
    auto& s = it->second;
    if ( auto entry = s.inflight.find( f->offset ); entry != s.inflight.end() ) {
      buffered_ -= entry->second.size();
      s.inflight.erase( entry );
    }
    if ( f->fin )
      s.fin_acked = true;
  }
}
} // namespace quic
