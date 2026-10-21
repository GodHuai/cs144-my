#pragma once

#include "frame.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace quic {

enum class CidAcceptResult
{
  Accepted,
  Duplicate,
  FrameEncodingError,
  ProtocolViolation,
  ConnectionIdLimitError,
  ResourceLimitError
};

enum class CidRetireResult
{
  Retired,
  NoPath,
  ConnectionIdLimitError
};

struct PeerConnectionIdChoice
{
  uint64_t sequence;
  std::string cid;
  std::optional<std::array<uint8_t, 16>> reset_token;
};

// RFC 9000 sections 5.1 and 9.5: IDs issued by the peer for our DCID field.
// A path key must uniquely identify a local/remote IP+port pair. Packet
// protection and network path discovery belong to the connection layer.
class PeerConnectionIds
{
public:
  PeerConnectionIds( std::string initial_peer_scid, uint64_t advertised_active_limit, size_t history_limit = 4096 );

  CidAcceptResult add_preferred_address( std::string cid, std::array<uint8_t, 16> reset_token );
  CidAcceptResult on_new_id( const NewConnectionIdFrame& frame );

  // Select an already-bound ID for this path, or bind an unused active ID.
  // Nonzero IDs are never bound to another path afterward.
  std::optional<PeerConnectionIdChoice> select_for_path( std::string_view path_key );
  // Retire the active ID used by a path after the path is abandoned.
  CidRetireResult retire_path( std::string_view path_key );

  std::vector<RetireConnectionIdFrame> pending_retirements() const;
  bool acknowledge_retirement( uint64_t sequence );
  uint64_t retire_prior_to() const { return retire_prior_to_; }
  size_t active_count() const;

private:
  struct Entry
  {
    std::string cid;
    std::optional<std::array<uint8_t, 16>> reset_token;
    std::optional<std::string> bound_path;
    bool locally_retired {};
    bool retirement_queued {};
  };

  void apply_retire_prior_to( uint64_t threshold );

  uint64_t active_limit_;
  size_t history_limit_;
  size_t pending_limit_;
  uint64_t retire_prior_to_ {};
  bool preferred_address_present_ {};
  std::map<uint64_t, Entry> entries_ {};
  std::set<uint64_t> pending_retirements_ {};
};

} // namespace quic
