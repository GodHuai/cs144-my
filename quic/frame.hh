#pragma once

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

using Frame = std::variant<PaddingFrame, PingFrame, CryptoFrame, StreamFrame, AckFrame>;

std::optional<std::vector<Frame>> decode_frames( std::string_view payload );
std::string encode_frame( const Frame& frame );

} // namespace quic
