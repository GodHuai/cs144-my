#pragma once

#include "frame.hh"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace quic {

enum class LocalRetireResult
{
  Retired,
  Duplicate,
  ProtocolViolation
};

// RFC 9000 sections 5.1.1 and 19.16: IDs that we issue for the peer's DCID.
// The caller provides unpredictable CIDs and reset tokens and routes packets
// only through IDs returned by lookup().
class LocalConnectionIds
{
public:
  LocalConnectionIds( std::string initial_source_cid, uint64_t peer_active_limit, size_t total_issue_limit = 4096 );

  // The preferred_address transport parameter reserves sequence 1. It is not
  // sent in a NEW_CONNECTION_ID frame.
  bool reserve_preferred_address( std::string cid, std::array<uint8_t, 16> token );
  std::optional<NewConnectionIdFrame> issue( std::string cid, std::array<uint8_t, 16> token );
  // Call only after the preferred-address parameter or NEW_CONNECTION_ID frame
  // has actually been transmitted; repeated calls are harmless.
  bool mark_sent( uint64_t sequence );

  // packet_dcid is the Destination Connection ID of the packet carrying frame.
  LocalRetireResult on_retire( const RetireConnectionIdFrame& frame, std::string_view packet_dcid );
  std::optional<uint64_t> lookup( std::string_view cid ) const;
  size_t active_count() const;
  bool needs_replacement() const;

private:
  struct Entry
  {
    std::string cid;
    std::optional<std::array<uint8_t, 16>> token;
    bool retired {};
    bool sent {};
  };

  bool can_add( std::string_view cid, const std::array<uint8_t, 16>& token ) const;

  uint64_t peer_active_limit_;
  size_t total_issue_limit_;
  bool replacement_requested_ {};
  std::map<uint64_t, Entry> entries_ {};
};

} // namespace quic
