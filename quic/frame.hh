#pragma once

#include "packet_header.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace quic {

struct PaddingFrame
{
  size_t length;
};
struct PingFrame
{};
struct CryptoFrame
{
  uint64_t offset;
  std::string data;
};
struct StreamFrame
{
  uint64_t stream_id;
  uint64_t offset;
  std::string data;
  bool fin;
  bool offset_present;
  bool length_present;
};
struct ResetStreamFrame
{
  uint64_t stream_id;
  uint64_t error_code;
  uint64_t final_size;
};
struct StopSendingFrame
{
  uint64_t stream_id;
  uint64_t error_code;
};
struct MaxDataFrame
{
  uint64_t maximum_data;
};
struct MaxStreamDataFrame
{
  uint64_t stream_id;
  uint64_t maximum_data;
};
struct MaxStreamsFrame
{
  bool unidirectional;
  uint64_t maximum_streams;
};
struct DataBlockedFrame
{
  uint64_t maximum_data;
};
struct StreamDataBlockedFrame
{
  uint64_t stream_id;
  uint64_t maximum_data;
};
struct StreamsBlockedFrame
{
  bool unidirectional;
  uint64_t maximum_streams;
};
struct NewTokenFrame
{
  std::string token;
};
struct PathChallengeFrame
{
  std::array<uint8_t, 8> data;
};
struct PathResponseFrame
{
  std::array<uint8_t, 8> data;
};
struct HandshakeDoneFrame
{};
struct NewConnectionIdFrame
{
  uint64_t sequence;
  uint64_t retire_prior_to;
  std::string cid;
  std::array<uint8_t, 16> reset_token;
};
struct RetireConnectionIdFrame
{
  uint64_t sequence;
};
struct ConnectionCloseFrame
{
  bool application;
  uint64_t error_code;
  std::optional<uint64_t> frame_type;
  std::string reason;
};
struct AckRange
{
  uint64_t smallest;
  uint64_t largest;
};
struct EcnCounts
{
  uint64_t ect0;
  uint64_t ect1;
  uint64_t ce;
};
struct AckFrame
{
  uint64_t ack_delay;
  std::vector<AckRange> ranges;
  std::optional<EcnCounts> ecn;
};

using Frame = std::variant<PaddingFrame,
                           PingFrame,
                           CryptoFrame,
                           StreamFrame,
                           AckFrame,
                           ResetStreamFrame,
                           StopSendingFrame,
                           MaxDataFrame,
                           MaxStreamDataFrame,
                           MaxStreamsFrame,
                           DataBlockedFrame,
                           StreamDataBlockedFrame,
                           StreamsBlockedFrame,
                           NewTokenFrame,
                           PathChallengeFrame,
                           PathResponseFrame,
                           HandshakeDoneFrame,
                           NewConnectionIdFrame,
                           RetireConnectionIdFrame,
                           ConnectionCloseFrame>;

std::optional<std::vector<Frame>> decode_frames( std::string_view payload );
std::string encode_frame( const Frame& frame );

// RFC 9000 Section 12.4 Table 3. Call after authenticated packet decryption;
// false means the combination is prohibited; the connection layer chooses
// the RFC 9000 Section 12.5 handling for prohibited 0-RTT frames.
bool frame_allowed_in_packet( const Frame& frame, PacketKind packet_kind );
bool frames_allowed_in_packet( const std::vector<Frame>& frames, PacketKind packet_kind );

} // namespace quic
