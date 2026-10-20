#include "quic/frame.hh"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

using namespace quic;

void require( bool condition, std::string_view message )
{
  if ( !condition ) {
    throw std::runtime_error( std::string( message ) );
  }
}

int main()
{
  require( !decode_frames( "" ), "empty packet payload accepted" );

  // Two PADDING bytes, PING, CRYPTO(offset=2, length=3), STREAM(id=4, FIN).
  const std::string wire { "\x00\x00\x01\x06\x02\x03"
                           "abc\x0f\x04\x01\x02xy",
                           15 };
  const auto frames = decode_frames( wire );
  require( frames && frames->size() == 4, "frame sequence parse" );
  require( std::get<PaddingFrame>( ( *frames )[0] ).length == 2, "padding run" );
  require( std::holds_alternative<PingFrame>( ( *frames )[1] ), "ping frame" );
  const auto& crypto = std::get<CryptoFrame>( ( *frames )[2] );
  require( crypto.offset == 2 && crypto.data == "abc", "crypto fields" );
  const auto& stream = std::get<StreamFrame>( ( *frames )[3] );
  require( stream.stream_id == 4 && stream.offset == 1 && stream.data == "xy" && stream.fin, "stream fields" );
  require( stream.offset_present && stream.length_present, "stream field flags" );
  std::string encoded;
  for ( const auto& frame : *frames ) {
    encoded += encode_frame( frame );
  }
  require( encoded == wire, "frame wire roundtrip" );

  const auto rest = decode_frames( std::string( "\x08\x01xyz", 5 ) );
  require( rest && rest->size() == 1, "no-LEN stream parse" );
  const auto& consume_rest = std::get<StreamFrame>( rest->front() );
  require( consume_rest.data == "xyz" && !consume_rest.length_present && !consume_rest.fin,
           "no-LEN consumes payload remainder" );
  require( encode_frame( rest->front() ) == std::string( "\x08\x01xyz", 5 ), "no-LEN encoding" );

  const auto empty_fin = decode_frames( std::string( "\x09\x00", 2 ) );
  require( empty_fin && std::get<StreamFrame>( empty_fin->front() ).fin, "zero-length FIN" );
  require( !decode_frames( std::string( "\x06\x00\x04xy", 5 ) ), "truncated CRYPTO" );
  require( !decode_frames( std::string( "\x0a\x00\x04xy", 5 ) ), "truncated STREAM" );
  require( !decode_frames( std::string( "\x40\x01", 2 ) ), "nonminimal frame type" );
  require( !decode_frames( std::string( "\x21", 1 ) ), "unknown frame type" );
  require( !decode_frames( std::string( "\x01\x06\x00\x03x", 5 ) ), "reject whole payload after valid prefix" );

  const std::string max_offset( 8, static_cast<char>( 0xff ) );
  std::string last_byte_offset = max_offset;
  last_byte_offset.back() = static_cast<char>( 0xfe );
  require( decode_frames( std::string( 1, '\x06' ) + last_byte_offset + "\x01x" ).has_value(),
           "CRYPTO exact 62-bit stream end" );
  require( !decode_frames( std::string( 1, '\x06' ) + max_offset + "\x01x" ), "CRYPTO stream end overflow" );
  require( decode_frames( std::string( "\x0e\x00", 2 ) + last_byte_offset + "\x01x" ).has_value(),
           "STREAM exact 62-bit stream end" );
  require( !decode_frames( std::string( "\x0e\x00", 2 ) + max_offset + "\x01x" ), "STREAM stream end overflow" );

  const std::string ack_wire { "\x02\x0a\x03\x01\x02\x01\x01", 7 };
  const auto ack_frames = decode_frames( ack_wire );
  require( ack_frames && ack_frames->size() == 1, "ACK frame parsed" );
  const auto& ack = std::get<AckFrame>( ack_frames->front() );
  require( ack.ack_delay == 3 && !ack.ecn && ack.ranges.size() == 2, "ACK fields" );
  require( ack.ranges[0].smallest == 8 && ack.ranges[0].largest == 10, "first ACK range" );
  require( ack.ranges[1].smallest == 4 && ack.ranges[1].largest == 5, "second ACK range" );
  require( encode_frame( ack_frames->front() ) == ack_wire, "ACK wire roundtrip" );

  const std::string ecn_wire { "\x03\x0a\x03\x00\x02\x01\x02\x03", 8 };
  const auto ecn_frames = decode_frames( ecn_wire );
  require( ecn_frames && ecn_frames->size() == 1, "ACK_ECN parsed" );
  const auto& ecn = std::get<AckFrame>( ecn_frames->front() );
  require( ecn.ecn && ecn.ecn->ect0 == 1 && ecn.ecn->ect1 == 2 && ecn.ecn->ce == 3, "ECN counts" );
  require( encode_frame( ecn_frames->front() ) == ecn_wire, "ACK_ECN wire roundtrip" );
  require( !decode_frames( std::string( "\x02\x01\x00\x00\x02", 5 ) ), "first ACK range underflow" );
  require( !decode_frames( std::string( "\x02\x02\x00\x01\x00\x01\x00", 7 ) ), "ACK gap underflow" );
  require( !decode_frames( std::string( "\x02\x0a\x00\x3f\x00", 5 ) ), "huge ACK range count with short payload" );
  require( !decode_frames( std::string( "\x03\x01\x00\x00\x00\x01\x02", 7 ) ), "truncated ECN counts" );

  // RFC 9000 §§19.4-19.5: all fields are QUIC varints, in wire order.
  const std::string reset_wire { "\x04\x25\x02\x40\x40", 5 }; // stream 37, error 2, final size 64
  const auto reset_frames = decode_frames( reset_wire );
  require( reset_frames && reset_frames->size() == 1, "RESET_STREAM decoded" );
  const auto& reset = std::get<ResetStreamFrame>( reset_frames->front() );
  require( reset.stream_id == 37 && reset.error_code == 2 && reset.final_size == 64, "RESET_STREAM fields" );
  require( encode_frame( reset_frames->front() ) == reset_wire, "RESET_STREAM encoded bytes" );

  const std::string stop_wire { "\x05\x03\x25", 3 }; // stream 3, error 37
  const auto stop_frames = decode_frames( stop_wire );
  require( stop_frames && stop_frames->size() == 1, "STOP_SENDING decoded" );
  const auto& stop = std::get<StopSendingFrame>( stop_frames->front() );
  require( stop.stream_id == 3 && stop.error_code == 37, "STOP_SENDING fields" );
  require( encode_frame( stop_frames->front() ) == stop_wire, "STOP_SENDING encoded bytes" );
  require( !decode_frames( std::string( "\x01\x04\x00\x00", 4 ) ), "truncated RESET_STREAM kept PING prefix" );
  require( !decode_frames( std::string( "\x05\x01", 2 ) ), "truncated STOP_SENDING accepted" );

  // RFC 9000 §§19.9-19.14: each control frame must leave the cursor at the next type byte.
  const std::string credit_wire { "\x10\x40\x40\x11\x03\x25\x12\x02\x13\x00"
                                  "\x14\x40\x40\x15\x03\x25\x16\x02\x17\x00",
                                  20 };
  const auto credit_frames = decode_frames( credit_wire );
  require( credit_frames && credit_frames->size() == 8, "credit and blocked frame sequence decoded" );
  require( std::get<MaxDataFrame>( ( *credit_frames )[0] ).maximum_data == 64, "MAX_DATA field" );
  const auto& max_stream_data = std::get<MaxStreamDataFrame>( ( *credit_frames )[1] );
  require( max_stream_data.stream_id == 3 && max_stream_data.maximum_data == 37, "MAX_STREAM_DATA fields" );
  require( !std::get<MaxStreamsFrame>( ( *credit_frames )[2] ).unidirectional
             && std::get<MaxStreamsFrame>( ( *credit_frames )[2] ).maximum_streams == 2,
           "bidirectional MAX_STREAMS" );
  require( std::get<MaxStreamsFrame>( ( *credit_frames )[3] ).unidirectional
             && std::get<MaxStreamsFrame>( ( *credit_frames )[3] ).maximum_streams == 0,
           "unidirectional MAX_STREAMS zero" );
  require( std::get<DataBlockedFrame>( ( *credit_frames )[4] ).maximum_data == 64, "DATA_BLOCKED field" );
  const auto& stream_blocked = std::get<StreamDataBlockedFrame>( ( *credit_frames )[5] );
  require( stream_blocked.stream_id == 3 && stream_blocked.maximum_data == 37, "STREAM_DATA_BLOCKED fields" );
  require( !std::get<StreamsBlockedFrame>( ( *credit_frames )[6] ).unidirectional
             && std::get<StreamsBlockedFrame>( ( *credit_frames )[6] ).maximum_streams == 2,
           "bidirectional STREAMS_BLOCKED" );
  require( std::get<StreamsBlockedFrame>( ( *credit_frames )[7] ).unidirectional
             && std::get<StreamsBlockedFrame>( ( *credit_frames )[7] ).maximum_streams == 0,
           "unidirectional STREAMS_BLOCKED zero" );
  std::string credit_encoded;
  for ( const auto& frame : *credit_frames ) {
    credit_encoded += encode_frame( frame );
  }
  require( credit_encoded == credit_wire, "credit and blocked frame wire bytes" );

  const std::string stream_limit_max = std::string( "\x12\xd0", 2 ) + std::string( 7, '\0' );
  const auto max_streams = decode_frames( stream_limit_max );
  require( max_streams
             && std::get<MaxStreamsFrame>( max_streams->front() ).maximum_streams == ( uint64_t { 1 } << 60 ),
           "MAX_STREAMS 2^60 boundary" );
  require( !decode_frames( stream_limit_max + std::string( "\x17\xd0\x00\x00\x00\x00\x00\x00\x01", 9 ) ),
           "STREAMS_BLOCKED 2^60+1 accepted" );
  require( !decode_frames( std::string( "\x01\x11\x03", 3 ) ), "truncated MAX_STREAM_DATA kept PING prefix" );

  bool rejected_limit = false;
  try {
    encode_frame( MaxStreamsFrame { true, ( uint64_t { 1 } << 60 ) + 1 } );
  } catch ( const std::out_of_range& ) {
    rejected_limit = true;
  }
  require( rejected_limit, "oversize MAX_STREAMS encoded" );
}
