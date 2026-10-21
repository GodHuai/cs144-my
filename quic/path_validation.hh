#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>

namespace quic {

enum class PathValidationState
{
  Idle,
  Validating,
  AddressValidated,
  Validated,
  Failed
};

// RFC 9000 section 8.2, one instance per candidate network path. The
// connection layer supplies CSPRNG-generated challenge data and calls these
// methods only for datagrams actually sent or authenticated responses.
class PathValidation
{
public:
  using Challenge = std::array<uint8_t, 8>;

  // Start a new attempt after sending a PATH_CHALLENGE. Timeout is chosen by
  // the caller, usually 3 * max(current PTO, new-path PTO).
  bool start( const Challenge& challenge, size_t datagram_size, uint64_t now_ms, uint64_t timeout_ms );

  // A retransmission uses fresh challenge data; old outstanding responses
  // remain valid until success or timeout. If the first probe was small,
  // the first >=1200-byte probe begins a separate MTU validation timer.
  bool record_sent_challenge( const Challenge& challenge,
                              size_t datagram_size,
                              uint64_t now_ms,
                              uint64_t timeout_ms );

  // The response may arrive on any network path. A matching response
  // validates the path on which its challenge was sent.
  bool on_response( const Challenge& response, uint64_t now_ms );
  bool expire( uint64_t now_ms );
  PathValidationState state() const { return state_; }

private:
  PathValidationState state_ { PathValidationState::Idle };
  uint64_t deadline_ms_ {};
  bool mtu_probe_started_ {};
  std::map<Challenge, bool> pending_ {}; // Value: challenge datagram was >=1200 bytes.
  std::set<Challenge> used_ {};
};

} // namespace quic
