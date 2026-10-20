#include "frame.hh"

#include "varint.hh"

#include <stdexcept>
#include <type_traits>

namespace quic {

namespace {
constexpr uint64_t max_stream_count = uint64_t { 1 } << 60;

bool valid_end( const uint64_t offset, const size_t length )
{
  return offset <= max_varint && length <= max_varint - offset;
}

std::optional<std::string> read_data( const std::string_view payload, size_t& cursor, const uint64_t length )
{
  if ( length > payload.size() - cursor ) {
    return std::nullopt;
  }
  std::string result( payload.substr( cursor, static_cast<size_t>( length ) ) );
  cursor += static_cast<size_t>( length );
  return result;
}

template<size_t N>
std::optional<std::array<uint8_t, N>> read_fixed( const std::string_view payload, size_t& cursor )
{
  if ( payload.size() - cursor < N ) {
    return std::nullopt;
  }
  std::array<uint8_t, N> result {};
  for ( size_t i = 0; i < N; ++i ) {
    result[i] = static_cast<uint8_t>( payload[cursor + i] );
  }
  cursor += N;
  return result;
}
} // namespace

std::optional<std::vector<Frame>> decode_frames( const std::string_view payload )
{
  if ( payload.empty() ) {
    return std::nullopt;
  }
  std::vector<Frame> frames;
  size_t cursor = 0;
  while ( cursor < payload.size() ) {
    const uint8_t type = static_cast<uint8_t>( payload[cursor++] );
    if ( type == 0 ) {
      size_t length = 1;
      while ( cursor < payload.size() && payload[cursor] == '\0' ) {
        ++cursor;
        ++length;
      }
      frames.emplace_back( PaddingFrame { length } );
    } else if ( type == 1 ) {
      frames.emplace_back( PingFrame {} );
    } else if ( type == 2 || type == 3 ) {
      const auto largest = decode_varint( payload, cursor );
      const auto delay = decode_varint( payload, cursor );
      const auto range_count = decode_varint( payload, cursor );
      const auto first_length = decode_varint( payload, cursor );
      if ( !largest || !delay || !range_count || !first_length || *first_length > *largest
           || *range_count > ( payload.size() - cursor ) / 2 ) {
        return std::nullopt;
      }
      AckFrame ack { *delay, { AckRange { *largest - *first_length, *largest } }, std::nullopt };
      for ( uint64_t i = 0; i < *range_count; ++i ) {
        const auto gap = decode_varint( payload, cursor );
        const auto length = decode_varint( payload, cursor );
        if ( !gap || !length || ack.ranges.back().smallest < *gap + 2 ) {
          return std::nullopt;
        }
        const uint64_t range_largest = ack.ranges.back().smallest - *gap - 2;
        if ( *length > range_largest ) {
          return std::nullopt;
        }
        ack.ranges.push_back( AckRange { range_largest - *length, range_largest } );
      }
      if ( type == 3 ) {
        const auto ect0 = decode_varint( payload, cursor );
        const auto ect1 = decode_varint( payload, cursor );
        const auto ce = decode_varint( payload, cursor );
        if ( !ect0 || !ect1 || !ce ) {
          return std::nullopt;
        }
        ack.ecn = EcnCounts { *ect0, *ect1, *ce };
      }
      frames.emplace_back( std::move( ack ) );
    } else if ( type == 4 ) {
      const auto stream_id = decode_varint( payload, cursor );
      const auto error_code = decode_varint( payload, cursor );
      const auto final_size = decode_varint( payload, cursor );
      if ( !stream_id || !error_code || !final_size ) {
        return std::nullopt;
      }
      frames.emplace_back( ResetStreamFrame { *stream_id, *error_code, *final_size } );
    } else if ( type == 5 ) {
      const auto stream_id = decode_varint( payload, cursor );
      const auto error_code = decode_varint( payload, cursor );
      if ( !stream_id || !error_code ) {
        return std::nullopt;
      }
      frames.emplace_back( StopSendingFrame { *stream_id, *error_code } );
    } else if ( type == 6 ) {
      const auto offset = decode_varint( payload, cursor );
      const auto length = decode_varint( payload, cursor );
      if ( !offset || !length || !valid_end( *offset, *length ) ) {
        return std::nullopt;
      }
      auto data = read_data( payload, cursor, *length );
      if ( !data ) {
        return std::nullopt;
      }
      frames.emplace_back( CryptoFrame { *offset, std::move( *data ) } );
    } else if ( type == 7 ) {
      const auto length = decode_varint( payload, cursor );
      if ( !length || *length == 0 ) {
        return std::nullopt;
      }
      auto token = read_data( payload, cursor, *length );
      if ( !token ) {
        return std::nullopt;
      }
      frames.emplace_back( NewTokenFrame { std::move( *token ) } );
    } else if ( type >= 8 && type <= 15 ) {
      const auto stream_id = decode_varint( payload, cursor );
      if ( !stream_id ) {
        return std::nullopt;
      }
      const bool offset_present = type & 4;
      const bool length_present = type & 2;
      const uint64_t offset = offset_present ? decode_varint( payload, cursor ).value_or( max_varint + 1 ) : 0;
      if ( offset > max_varint ) {
        return std::nullopt;
      }
      const uint64_t length
        = length_present ? decode_varint( payload, cursor ).value_or( max_varint + 1 ) : payload.size() - cursor;
      if ( length > max_varint || !valid_end( offset, length ) ) {
        return std::nullopt;
      }
      auto data = read_data( payload, cursor, length );
      if ( !data ) {
        return std::nullopt;
      }
      frames.emplace_back(
        StreamFrame { *stream_id, offset, std::move( *data ), bool( type & 1 ), offset_present, length_present } );
    } else if ( type == 0x10 || type == 0x14 ) {
      const auto maximum_data = decode_varint( payload, cursor );
      if ( !maximum_data ) {
        return std::nullopt;
      }
      if ( type == 0x10 ) {
        frames.emplace_back( MaxDataFrame { *maximum_data } );
      } else {
        frames.emplace_back( DataBlockedFrame { *maximum_data } );
      }
    } else if ( type == 0x11 || type == 0x15 ) {
      const auto stream_id = decode_varint( payload, cursor );
      const auto maximum_data = decode_varint( payload, cursor );
      if ( !stream_id || !maximum_data ) {
        return std::nullopt;
      }
      if ( type == 0x11 ) {
        frames.emplace_back( MaxStreamDataFrame { *stream_id, *maximum_data } );
      } else {
        frames.emplace_back( StreamDataBlockedFrame { *stream_id, *maximum_data } );
      }
    } else if ( type == 0x12 || type == 0x13 || type == 0x16 || type == 0x17 ) {
      const auto maximum_streams = decode_varint( payload, cursor );
      if ( !maximum_streams || *maximum_streams > max_stream_count ) {
        return std::nullopt;
      }
      if ( type == 0x12 || type == 0x13 ) {
        frames.emplace_back( MaxStreamsFrame { bool( type & 1 ), *maximum_streams } );
      } else {
        frames.emplace_back( StreamsBlockedFrame { bool( type & 1 ), *maximum_streams } );
      }
    } else if ( type == 0x18 ) {
      const auto sequence = decode_varint( payload, cursor );
      const auto retire_prior_to = decode_varint( payload, cursor );
      if ( !sequence || !retire_prior_to || *retire_prior_to > *sequence || cursor >= payload.size() ) {
        return std::nullopt;
      }
      const uint8_t cid_length = static_cast<uint8_t>( payload[cursor++] );
      if ( cid_length == 0 || cid_length > 20 ) {
        return std::nullopt;
      }
      auto cid = read_data( payload, cursor, cid_length );
      if ( !cid ) {
        return std::nullopt;
      }
      const auto reset_token = read_fixed<16>( payload, cursor );
      if ( !reset_token ) {
        return std::nullopt;
      }
      frames.emplace_back( NewConnectionIdFrame { *sequence, *retire_prior_to, std::move( *cid ), *reset_token } );
    } else if ( type == 0x19 ) {
      const auto sequence = decode_varint( payload, cursor );
      if ( !sequence ) {
        return std::nullopt;
      }
      frames.emplace_back( RetireConnectionIdFrame { *sequence } );
    } else if ( type == 0x1a || type == 0x1b ) {
      const auto data = read_fixed<8>( payload, cursor );
      if ( !data ) {
        return std::nullopt;
      }
      if ( type == 0x1a ) {
        frames.emplace_back( PathChallengeFrame { *data } );
      } else {
        frames.emplace_back( PathResponseFrame { *data } );
      }
    } else if ( type == 0x1c || type == 0x1d ) {
      const auto error_code = decode_varint( payload, cursor );
      if ( !error_code ) {
        return std::nullopt;
      }
      std::optional<uint64_t> frame_type;
      if ( type == 0x1c ) {
        frame_type = decode_varint( payload, cursor );
        if ( !frame_type ) {
          return std::nullopt;
        }
      }
      const auto reason_length = decode_varint( payload, cursor );
      if ( !reason_length ) {
        return std::nullopt;
      }
      auto reason = read_data( payload, cursor, *reason_length );
      if ( !reason ) {
        return std::nullopt;
      }
      frames.emplace_back( ConnectionCloseFrame { type == 0x1d, *error_code, frame_type, std::move( *reason ) } );
    } else if ( type == 0x1e ) {
      frames.emplace_back( HandshakeDoneFrame {} );
    } else {
      return std::nullopt;
    }
  }
  return frames;
}

std::string encode_frame( const Frame& frame )
{
  return std::visit(
    []( const auto& value ) -> std::string {
      using T = std::decay_t<decltype( value )>;
      if constexpr ( std::is_same_v<T, PaddingFrame> ) {
        if ( value.length == 0 ) {
          throw std::invalid_argument( "PADDING length must be positive" );
        }
        return std::string( value.length, '\0' );
      } else if constexpr ( std::is_same_v<T, PingFrame> ) {
        return std::string( 1, '\x01' );
      } else if constexpr ( std::is_same_v<T, CryptoFrame> ) {
        if ( !valid_end( value.offset, value.data.size() ) ) {
          throw std::out_of_range( "CRYPTO stream end exceeds 62 bits" );
        }
        return std::string( 1, '\x06' ) + encode_varint( value.offset ) + encode_varint( value.data.size() )
               + value.data;
      } else if constexpr ( std::is_same_v<T, StreamFrame> ) {
        if ( !valid_end( value.offset, value.data.size() ) || ( !value.offset_present && value.offset != 0 )
             || value.stream_id > max_varint ) {
          throw std::out_of_range( "invalid STREAM offset or stream ID" );
        }
        const uint8_t type
          = 8 | ( value.offset_present ? 4 : 0 ) | ( value.length_present ? 2 : 0 ) | ( value.fin ? 1 : 0 );
        std::string result( 1, static_cast<char>( type ) );
        result += encode_varint( value.stream_id );
        if ( value.offset_present ) {
          result += encode_varint( value.offset );
        }
        if ( value.length_present ) {
          result += encode_varint( value.data.size() );
        }
        result += value.data;
        return result;
      } else if constexpr ( std::is_same_v<T, ResetStreamFrame> ) {
        return std::string( 1, '\x04' ) + encode_varint( value.stream_id ) + encode_varint( value.error_code )
               + encode_varint( value.final_size );
      } else if constexpr ( std::is_same_v<T, StopSendingFrame> ) {
        return std::string( 1, '\x05' ) + encode_varint( value.stream_id ) + encode_varint( value.error_code );
      } else if constexpr ( std::is_same_v<T, MaxDataFrame> ) {
        return std::string( 1, '\x10' ) + encode_varint( value.maximum_data );
      } else if constexpr ( std::is_same_v<T, MaxStreamDataFrame> ) {
        return std::string( 1, '\x11' ) + encode_varint( value.stream_id ) + encode_varint( value.maximum_data );
      } else if constexpr ( std::is_same_v<T, MaxStreamsFrame> ) {
        if ( value.maximum_streams > max_stream_count ) {
          throw std::out_of_range( "MAX_STREAMS exceeds 2^60" );
        }
        return std::string( 1, value.unidirectional ? '\x13' : '\x12' ) + encode_varint( value.maximum_streams );
      } else if constexpr ( std::is_same_v<T, DataBlockedFrame> ) {
        return std::string( 1, '\x14' ) + encode_varint( value.maximum_data );
      } else if constexpr ( std::is_same_v<T, StreamDataBlockedFrame> ) {
        return std::string( 1, '\x15' ) + encode_varint( value.stream_id ) + encode_varint( value.maximum_data );
      } else if constexpr ( std::is_same_v<T, StreamsBlockedFrame> ) {
        if ( value.maximum_streams > max_stream_count ) {
          throw std::out_of_range( "STREAMS_BLOCKED exceeds 2^60" );
        }
        return std::string( 1, value.unidirectional ? '\x17' : '\x16' ) + encode_varint( value.maximum_streams );
      } else if constexpr ( std::is_same_v<T, NewTokenFrame> ) {
        if ( value.token.empty() ) {
          throw std::invalid_argument( "NEW_TOKEN token must be nonempty" );
        }
        return std::string( 1, '\x07' ) + encode_varint( value.token.size() ) + value.token;
      } else if constexpr ( std::is_same_v<T, PathChallengeFrame> ) {
        return std::string( 1, '\x1a' ) + std::string( value.data.begin(), value.data.end() );
      } else if constexpr ( std::is_same_v<T, PathResponseFrame> ) {
        return std::string( 1, '\x1b' ) + std::string( value.data.begin(), value.data.end() );
      } else if constexpr ( std::is_same_v<T, HandshakeDoneFrame> ) {
        return std::string( 1, '\x1e' );
      } else if constexpr ( std::is_same_v<T, NewConnectionIdFrame> ) {
        if ( value.cid.empty() || value.cid.size() > 20 || value.retire_prior_to > value.sequence ) {
          throw std::invalid_argument( "invalid NEW_CONNECTION_ID fields" );
        }
        return std::string( 1, '\x18' ) + encode_varint( value.sequence ) + encode_varint( value.retire_prior_to )
               + static_cast<char>( value.cid.size() ) + value.cid
               + std::string( value.reset_token.begin(), value.reset_token.end() );
      } else if constexpr ( std::is_same_v<T, RetireConnectionIdFrame> ) {
        return std::string( 1, '\x19' ) + encode_varint( value.sequence );
      } else if constexpr ( std::is_same_v<T, ConnectionCloseFrame> ) {
        if ( value.application == value.frame_type.has_value() ) {
          throw std::invalid_argument( "CONNECTION_CLOSE frame type must match variant" );
        }
        std::string result( 1, value.application ? '\x1d' : '\x1c' );
        result += encode_varint( value.error_code );
        if ( value.frame_type ) {
          result += encode_varint( *value.frame_type );
        }
        result += encode_varint( value.reason.size() );
        result += value.reason;
        return result;
      } else {
        if ( value.ranges.empty() || value.ranges.front().largest > max_varint ) {
          throw std::invalid_argument( "ACK needs a valid first range" );
        }
        std::string result( 1, value.ecn ? '\x03' : '\x02' );
        result += encode_varint( value.ranges.front().largest );
        result += encode_varint( value.ack_delay );
        result += encode_varint( value.ranges.size() - 1 );
        for ( size_t i = 0; i < value.ranges.size(); ++i ) {
          const auto& range = value.ranges[i];
          if ( range.smallest > range.largest || range.largest > max_varint ) {
            throw std::invalid_argument( "invalid ACK range" );
          }
          if ( i > 0 ) {
            const auto& previous = value.ranges[i - 1];
            if ( previous.smallest < range.largest + 2 ) {
              throw std::invalid_argument( "ACK ranges must descend with a gap" );
            }
            result += encode_varint( previous.smallest - range.largest - 2 );
          }
          result += encode_varint( range.largest - range.smallest );
        }
        if ( value.ecn ) {
          result += encode_varint( value.ecn->ect0 );
          result += encode_varint( value.ecn->ect1 );
          result += encode_varint( value.ecn->ce );
        }
        return result;
      }
    },
    frame );
}

bool frame_allowed_in_packet( const Frame& frame, const PacketKind packet_kind )
{
  // Keep this table under review when a new frame variant is added.
  static_assert( std::variant_size_v<Frame> == 20 );
  if ( packet_kind != PacketKind::Initial && packet_kind != PacketKind::Handshake
       && packet_kind != PacketKind::ZeroRtt && packet_kind != PacketKind::OneRtt ) {
    return false;
  }
  if ( packet_kind == PacketKind::OneRtt ) {
    return true;
  }
  if ( std::holds_alternative<PaddingFrame>( frame ) || std::holds_alternative<PingFrame>( frame ) ) {
    return true;
  }
  const auto* close = std::get_if<ConnectionCloseFrame>( &frame );
  if ( packet_kind == PacketKind::Initial || packet_kind == PacketKind::Handshake ) {
    return std::holds_alternative<AckFrame>( frame ) || std::holds_alternative<CryptoFrame>( frame )
           || ( close && !close->application );
  }
  if ( packet_kind != PacketKind::ZeroRtt ) {
    return false;
  }
  // 0-RTT shares the application packet-number space, but Table 3 prohibits
  // these six frame types in 0-RTT packets.
  return !std::holds_alternative<AckFrame>( frame ) && !std::holds_alternative<CryptoFrame>( frame )
         && !std::holds_alternative<NewTokenFrame>( frame ) && !std::holds_alternative<PathResponseFrame>( frame )
         && !std::holds_alternative<RetireConnectionIdFrame>( frame )
         && !std::holds_alternative<HandshakeDoneFrame>( frame );
}

bool frames_allowed_in_packet( const std::vector<Frame>& frames, const PacketKind packet_kind )
{
  if ( frames.empty() ) {
    return false;
  }
  for ( const auto& frame : frames ) {
    if ( !frame_allowed_in_packet( frame, packet_kind ) ) {
      return false;
    }
  }
  return true;
}

} // namespace quic
