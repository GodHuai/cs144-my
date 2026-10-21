#pragma once

#include <cstdint>
#include <optional>

namespace quic {

// The three-times rule applies when responding to an unvalidated address.
// It does not apply to a client Initial or an endpoint initiating migration.
enum class AmplificationRole
{
  Initiator,
  Responder
};

// RFC 9000 sections 8 and 9.3.1. One instance belongs to one peer transport
// address on one connection. The caller records UDP payload bytes from
// datagrams uniquely attributed to this connection, including discarded
// packets, and reserves outgoing bytes before sending to that address.
class AntiAmplificationBudget
{
public:
  explicit AntiAmplificationBudget( AmplificationRole role ) : role_( role ) {}

  void record_received( uint64_t udp_payload_bytes );

  // Atomically check and account a proposed UDP payload. A rejected send
  // leaves the budget unchanged. The caller must serialize path send decisions.
  bool record_sent( uint64_t udp_payload_bytes );

  // nullopt means the three-times cap does not apply: this endpoint is the
  // initiator or the address is validated. Check address_validated()
  // separately. Other limits (congestion, flow control, PMTU) still apply.
  std::optional<uint64_t> remaining_bytes() const;
  void validate_address() { validated_ = true; }
  bool address_validated() const { return validated_; }

private:
  AmplificationRole role_;
  bool validated_ {};
  uint64_t received_ {};
  uint64_t sent_ {};
};

} // namespace quic
