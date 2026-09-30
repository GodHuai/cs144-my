#include "reassembler.hh"

#include <algorithm>
#include <iterator>

using namespace std;

void Reassembler::insert( uint64_t first_index, string data, bool is_last_substring )
{
  // 写端关闭后，后续重复到达的片段不能再改变流内容。
  if ( output_.writer().is_closed() ) {
    return;
  }

  // EOF 位置由原始片段决定。即使这次只能接收片段前缀，也要记住真正的结尾。
  if ( is_last_substring ) {
    eof_index_ = first_index + data.size();
  }

  // 可接收窗口是 [已写入流的下标, 已读出流的下标 + 总容量)。
  // 已写入但未读出的字节仍占空间，所以窗口右端随 Reader::pop() 前进。
  const uint64_t first_unassembled = output_.writer().bytes_pushed();
  const uint64_t first_unread = output_.reader().bytes_popped();
  const uint64_t first_unacceptable = first_unread + capacity_;

  // 裁掉已经交给 ByteStream 的旧字节，避免重复输出。
  if ( first_index < first_unassembled ) {
    const uint64_t obsolete = first_unassembled - first_index;
    data.erase( 0, min<uint64_t>( obsolete, data.size() ) );
    first_index += obsolete;
  }

  if ( first_index < first_unacceptable && !data.empty() ) {
    // 窗口右侧的字节当前放不下；以后若重传，再重新尝试接收。
    data.resize( min<uint64_t>( data.size(), first_unacceptable - first_index ) );

    // map 按起点排序。lower_bound 找右侧候选；前一个区间也可能与新片段相接。
    auto first = buffer_.lower_bound( first_index );
    if ( first != buffer_.begin() ) {
      auto previous = prev( first );
      if ( previous->first + previous->second.size() >= first_index ) {
        first = previous;
      }
    }

    uint64_t merged_start = first_index;
    uint64_t merged_end = first_index + data.size();
    auto last = first;
    // 把重叠或首尾相接的区间并成一个连续区间，连锁相接也一并处理。
    while ( last != buffer_.end() && last->first <= merged_end ) {
      merged_start = min( merged_start, last->first );
      merged_end = max<uint64_t>( merged_end, last->first + last->second.size() );
      ++last;
    }

    string merged( merged_end - merged_start, '\0' );
    // 先放新数据，再覆盖已缓存的数据；重传内容冲突时保留先收到的字节。
    copy( data.begin(), data.end(), merged.begin() + ( first_index - merged_start ) );
    for ( auto it = first; it != last; ++it ) {
      copy( it->second.begin(), it->second.end(), merged.begin() + ( it->first - merged_start ) );
      // 旧区间的长度先从计数中扣掉，合并后再加一次，重叠字节不会重复计数。
      pending_bytes_ -= it->second.size();
    }

    buffer_.erase( first, last );
    pending_bytes_ += merged.size();
    buffer_.emplace( merged_start, move( merged ) );
  }

  // 只有最前面的区间从“下一个待写字节”开始，才能交给 ByteStream。
  // 每写出一个区间，都可能使紧随其后的区间变成连续前缀。
  while ( !buffer_.empty() && buffer_.begin()->first == output_.writer().bytes_pushed() ) {
    auto it = buffer_.begin();
    const uint64_t count = it->second.size();
    output_.writer().push( move( it->second ) );
    pending_bytes_ -= count;
    buffer_.erase( it );
  }

  // close() 只终止写入；Reader 仍可继续读完已经写出的字节。
  if ( eof_index_ && output_.writer().bytes_pushed() == *eof_index_ ) {
    output_.writer().close();
  }
}

uint64_t Reassembler::bytes_pending() const
{
  return pending_bytes_;
}
