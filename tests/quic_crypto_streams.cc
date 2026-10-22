#include "quic/crypto_streams.hh"
#include "quic/initial_packet.hh"
#include "quic/packet_number_space.hh"
#include "quic/varint.hh"

#include <stdexcept>
#include <string>
#include <string_view>

using namespace quic;

// This target always links ASan. Query its live allocation count to verify the
// public discard contract without exposing private string capacity or replacing
// the allocator (which would alter the behavior being tested).
extern "C" size_t __sanitizer_get_current_allocated_bytes();

namespace {
void require( const bool ok, const std::string_view message )
{
  if ( !ok ) {
    throw std::runtime_error( std::string { message } );
  }
}

void receive_order_and_levels()
{
  CryptoStreams streams;
  require( !streams.receive( PacketKind::Initial, { 3, "def" } ), "out-of-order receive failed" );
  require( streams.take_contiguous( PacketKind::Initial ).empty(), "gap delivered to TLS" );
  require( !streams.receive( PacketKind::Handshake, { 0, "handshake" } ), "Handshake receive failed" );
  require( !streams.receive( PacketKind::OneRtt, { 0, "ticket" } ), "1-RTT receive failed" );
  require( !streams.receive( PacketKind::Initial, { 0, "abc" } ), "gap fill failed" );
  require( streams.take_contiguous( PacketKind::Initial ) == "abcdef", "Initial reassembly corrupted" );
  require( streams.read_offset( PacketKind::Initial ) == 6, "Initial cursor not advanced" );
  require( streams.take_contiguous( PacketKind::Initial ).empty(), "bytes delivered twice" );
  require( streams.take_contiguous( PacketKind::Handshake ) == "handshake", "levels shared offset/data" );
  require( streams.take_contiguous( PacketKind::OneRtt ) == "ticket", "1-RTT data lost" );
  require( !streams.receive( PacketKind::Initial, { 0, "abcdef" } ), "consumed duplicate failed" );
  require( streams.bytes_buffered( PacketKind::Initial ) == 0, "consumed duplicate retained" );
  require( !streams.receive( PacketKind::Initial, { 4, "efgh" } ), "partial old duplicate failed" );
  require( streams.take_contiguous( PacketKind::Initial ) == "gh", "old prefix redelivered" );
}

void overlap_and_atomic_errors()
{
  CryptoStreams streams;
  require( !streams.receive( PacketKind::Initial, { 2, "cde" } ), "first interval failed" );
  require( !streams.receive( PacketKind::Initial, { 7, "hi" } ), "second interval failed" );
  require( !streams.receive( PacketKind::Initial, { 3, "defgh" } ), "bridging overlap failed" );
  require( streams.bytes_buffered( PacketKind::Initial ) == 7, "overlap charged twice" );
  require( streams.receive( PacketKind::Initial, { 0, "abcdX" } ) == CryptoReceiveError::ProtocolViolation,
           "conflicting overlap accepted" );
  require( streams.bytes_buffered( PacketKind::Initial ) == 7
             && streams.take_contiguous( PacketKind::Initial ).empty(),
           "conflict partially mutated receive state" );
  require( !streams.receive( PacketKind::Initial, { 0, "abcd" } ), "overlap prepend failed" );
  require( streams.take_contiguous( PacketKind::Initial ) == "abcdefghi", "merged data incorrect" );

  const std::string binary { "\0\xff\0x", 4 };
  require( !streams.receive( PacketKind::Handshake, { 1, binary.substr( 1 ) } ), "binary tail failed" );
  require( !streams.receive( PacketKind::Handshake, { 0, binary.substr( 0, 2 ) } ), "binary overlap failed" );
  require( streams.take_contiguous( PacketKind::Handshake ) == binary, "NUL or high byte corrupted" );
}

void capacity_and_sparse_offsets()
{
  CryptoStreams streams { 4096 };
  const std::string block( 4096, 'b' );
  require( !streams.receive( PacketKind::Initial, { 1, block } ), "4096 out-of-order bytes rejected" );
  require( !streams.receive( PacketKind::Initial, { 1000, block.substr( 0, 1000 ) } ), "duplicate overcharged" );
  require( streams.bytes_buffered( PacketKind::Initial ) == 4096, "duplicate changed capacity" );
  require( streams.receive( PacketKind::Initial, { 0, "ab" } ) == CryptoReceiveError::BufferExceeded,
           "capacity overflow accepted" );
  require( streams.bytes_buffered( PacketKind::Initial ) == 4096 && streams.read_offset( PacketKind::Initial ) == 0
             && streams.take_contiguous( PacketKind::Initial ).empty(),
           "overflow partially modified state" );
  streams.discard( PacketKind::Initial );
  require( streams.bytes_buffered( PacketKind::Initial ) == 0, "discard leaked receive bytes" );

  require( !streams.receive( PacketKind::Handshake, { 0, block } ), "contiguous capacity failed" );
  require( streams.take_contiguous( PacketKind::Handshake ) == block, "capacity-sized read lost bytes" );
  require( !streams.receive( PacketKind::Handshake, { 4096, block } ), "draining did not free capacity" );
  require( streams.take_contiguous( PacketKind::Handshake ) == block, "second capacity-sized read failed" );

  CryptoStreams sparse { 4096 };
  require( !sparse.receive( PacketKind::Initial, { max_varint - 1, "z" } ), "valid maximum end rejected" );
  require( sparse.bytes_buffered( PacketKind::Initial ) == 1, "far offset allocated its gap" );
  require( sparse.receive( PacketKind::Initial, { max_varint - 1, "zz" } )
             == CryptoReceiveError::FrameEncodingError,
           "offset plus length overflow accepted" );
  require( sparse.receive( PacketKind::Initial, { max_varint + 1, "" } ) == CryptoReceiveError::FrameEncodingError,
           "invalid empty offset accepted" );
  require( !sparse.receive( PacketKind::Initial, { max_varint, "" } ), "valid empty end rejected" );
  require( sparse.bytes_buffered( PacketKind::Initial ) == 1, "empty frame changed memory use" );
  require( !sparse.receive( PacketKind::Initial, { 0, "start" } ), "sparse prefix failed" );
  require( sparse.take_contiguous( PacketKind::Initial ) == "start", "far gap blocked contiguous prefix" );
  require( sparse.bytes_buffered( PacketKind::Initial ) == 1, "read freed unrelated far fragment" );

  bool rejected = false;
  try {
    const CryptoStreams too_small { 4095 };
  } catch ( const std::invalid_argument& ) {
    rejected = true;
  }
  require( rejected, "less than 4096 receive capacity accepted" );
}

void outgoing_and_discard()
{
  CryptoStreams streams { 4096, 8 };
  require( streams.append( PacketKind::Initial, "abc" ) && streams.append( PacketKind::Initial, "defgh" ),
           "outgoing append failed" );
  require( !streams.append( PacketKind::Initial, "i" ), "send capacity exceeded" );
  const auto first = streams.frame( PacketKind::Initial, 0, 3 );
  const auto middle = streams.frame( PacketKind::Initial, 2, 4 );
  const auto tail = streams.frame( PacketKind::Initial, 7, 100 );
  require( first && first->offset == 0 && first->data == "abc", "first fragment incorrect" );
  require( middle && middle->offset == 2 && middle->data == "cdef", "refragmentation changed offsets" );
  require( tail && tail->offset == 7 && tail->data == "h", "tail crossed retained data" );
  require( !streams.frame( PacketKind::Initial, 8, 1 ) && !streams.frame( PacketKind::Initial, max_varint, 1 )
             && !streams.frame( PacketKind::Initial, 0, 0 ),
           "invalid or empty outgoing range emitted" );
  require( streams.frame( PacketKind::Initial, 0, 8 )->data == "abcdefgh", "framing consumed retransmission data" );
  require( streams.append( PacketKind::Handshake, "H" ) && streams.append( PacketKind::OneRtt, "T" ),
           "send levels shared capacity" );
  require( !streams.receive( PacketKind::Initial, { 2, "pending" } ), "pending receive failed" );
  streams.discard( PacketKind::Initial );
  streams.discard( PacketKind::Initial );
  require( !streams.append( PacketKind::Initial, "new" ) && !streams.frame( PacketKind::Initial, 0, 8 ),
           "discarded send level resurrected" );
  require( !streams.receive( PacketKind::Initial, { 0, "late" } )
             && streams.take_contiguous( PacketKind::Initial ).empty()
             && streams.bytes_buffered( PacketKind::Initial ) == 0,
           "late packet resurrected discarded level" );
  require( streams.frame( PacketKind::Handshake, 0, 1 )->data == "H"
             && streams.frame( PacketKind::OneRtt, 0, 1 )->data == "T",
           "discard crossed encryption levels" );
  require( streams.receive( PacketKind::ZeroRtt, { 0, "early" } ) == CryptoReceiveError::ProtocolViolation,
           "0-RTT CRYPTO accepted" );
  require( !streams.append( PacketKind::ZeroRtt, "early" ) && !streams.frame( PacketKind::ZeroRtt, 0, 1 ),
           "0-RTT CRYPTO sent" );
}

void discard_releases_heap_storage()
{
  const std::string large( 1024 * 1024, 'x' );
  CryptoStreams streams { 4096, large.size() };
  const size_t before = __sanitizer_get_current_allocated_bytes();
  require( streams.append( PacketKind::Initial, large ), "large outgoing append failed" );
  const size_t queued = __sanitizer_get_current_allocated_bytes();
  require( queued >= before + large.size(), "large outgoing allocation not observed" );
  streams.discard( PacketKind::Initial );
  require( __sanitizer_get_current_allocated_bytes() <= before, "discard retained outgoing heap storage" );
}

void fragmented_interval_stress()
{
  CryptoStreams streams { 4096 };
  // 2048 isolated bytes followed by their gaps exercise many intervals and
  // merging in both directions without ever allocating the missing gaps.
  for ( uint64_t i = 1; i < 4096; i += 2 ) {
    require( !streams.receive( PacketKind::Initial, { i, "b" } ), "sparse byte rejected" );
  }
  require( streams.bytes_buffered( PacketKind::Initial ) == 2048, "isolated bytes counted incorrectly" );
  for ( uint64_t i = 4094; i > 0; i -= 2 ) {
    require( !streams.receive( PacketKind::Initial, { i, "a" } ), "bridging byte rejected" );
  }
  require( streams.take_contiguous( PacketKind::Initial ).empty(), "missing offset zero ignored" );
  require( !streams.receive( PacketKind::Initial, { 0, "a" } ), "final gap rejected" );
  std::string expected;
  for ( size_t i = 0; i < 2048; ++i ) {
    expected += "ab";
  }
  require( streams.take_contiguous( PacketKind::Initial ) == expected, "fragmented intervals corrupted" );
  require( streams.bytes_buffered( PacketKind::Initial ) == 0, "fragmented read leaked capacity" );
}

void protected_initial_transport()
{
  CryptoStreams sender;
  CryptoStreams receiver;
  PacketNumberSpaces send_numbers;
  PacketNumberSpaces receive_numbers;
  const auto keys = derive_initial_keys( "original-dcid" );
  require( keys.has_value(), "Initial key derivation failed" );
  const std::string bytes = std::string { "C\0H\xff", 4 } + "handshake-bytes";
  require( sender.append( PacketKind::Initial, bytes ), "handshake bytes not queued" );

  const auto packet = [&]( const uint64_t offset, const size_t count ) {
    const auto fragment = sender.frame( PacketKind::Initial, offset, count );
    require( fragment.has_value(), "missing outgoing handshake fragment" );
    const auto number = send_numbers.allocate( PacketKind::Initial );
    require( number.has_value(), "packet number allocation failed" );
    // Datagram sizing is the future connection's responsibility; pad here so
    // the test packets also meet the client's minimum Initial datagram size.
    const auto payload = encode_frame( *fragment ) + encode_frame( PaddingFrame { 1200 } );
    return seal_initial_packet(
      keys->client, InitialSender::Client, "original-dcid", "client-cid", "", *number, 2, payload );
  };
  const auto deliver = [&]( const std::string& wire ) {
    const auto opened = open_initial_packet(
      keys->client, InitialSender::Client, wire, 0, receive_numbers.largest_received( PacketKind::Initial ) );
    if ( !opened ) {
      return false;
    }
    const auto frames = decode_frames( opened->plaintext );
    require( frames && frames_allowed_in_packet( *frames, PacketKind::Initial ), "Initial frames invalid" );
    if ( !receive_numbers.record_authenticated( PacketKind::Initial, opened->packet_number ) ) {
      return false;
    }
    for ( const auto& frame : *frames ) {
      if ( const auto* crypto = std::get_if<CryptoFrame>( &frame ) ) {
        require( !receiver.receive( PacketKind::Initial, *crypto ), "authenticated CRYPTO not buffered" );
      }
    }
    return true;
  };

  const auto first = packet( 0, 4 );   // packet number 0
  const auto missing = packet( 4, 4 ); // packet number 1: lost in this simulated network
  const auto last = packet( 8, 100 );  // packet number 2
  require( !missing.empty(), "missing-fragment packet not constructed" );
  auto corrupted = first;
  corrupted.back() ^= 1;
  require( !deliver( corrupted ) && receiver.bytes_buffered( PacketKind::Initial ) == 0
             && !receive_numbers.largest_received( PacketKind::Initial ),
           "unauthenticated packet changed CRYPTO or packet-number state" );
  require( deliver( last ) && !deliver( last ), "out-of-order or duplicate packet handling failed" );
  require( receiver.take_contiguous( PacketKind::Initial ).empty(), "out-of-order Initial reached TLS" );
  require( deliver( first ) && receiver.take_contiguous( PacketKind::Initial ) == std::string { "C\0H\xff", 4 },
           "authenticated prefix not delivered exactly once" );
  const auto resend = packet( 4, 4 ); // same CRYPTO offset, fresh packet number 3
  require( resend != missing && deliver( resend ), "retransmission did not use a fresh packet number" );
  require( receive_numbers.largest_received( PacketKind::Initial ) == 3, "resend packet number incorrect" );
  require( receiver.take_contiguous( PacketKind::Initial ) == "handshake-bytes",
           "lost fragment resend did not repair the handshake stream" );
  require( receiver.read_offset( PacketKind::Initial ) == bytes.size()
             && receiver.bytes_buffered( PacketKind::Initial ) == 0,
           "handshake bytes lost or duplicated" );
}
} // namespace

int main()
{
  receive_order_and_levels();
  overlap_and_atomic_errors();
  capacity_and_sparse_offsets();
  outgoing_and_discard();
  discard_releases_heap_storage();
  fragmented_interval_stress();
  protected_initial_transport();
}
