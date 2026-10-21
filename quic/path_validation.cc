#include "path_validation.hh"

#include <limits>

using namespace std;

namespace quic {

bool PathValidation::start( const Challenge& challenge,
                            const size_t datagram_size,
                            const uint64_t now_ms,
                            const uint64_t timeout_ms )
{
  if ( timeout_ms == 0 ) {
    return false;
  }
  pending_.clear();
  used_.clear();
  state_ = PathValidationState::Validating;
  mtu_probe_started_ = datagram_size >= 1200;
  deadline_ms_
    = timeout_ms > numeric_limits<uint64_t>::max() - now_ms ? numeric_limits<uint64_t>::max() : now_ms + timeout_ms;
  return record_sent_challenge( challenge, datagram_size, now_ms, timeout_ms );
}

bool PathValidation::record_sent_challenge( const Challenge& challenge,
                                            const size_t datagram_size,
                                            const uint64_t now_ms,
                                            const uint64_t timeout_ms )
{
  if ( timeout_ms == 0 || expire( now_ms )
       || ( state_ != PathValidationState::Validating && state_ != PathValidationState::AddressValidated ) ) {
    return false;
  }
  if ( !used_.insert( challenge ).second ) {
    return false;
  }
  if ( datagram_size >= 1200 && !mtu_probe_started_ ) {
    deadline_ms_ = timeout_ms > numeric_limits<uint64_t>::max() - now_ms ? numeric_limits<uint64_t>::max()
                                                                         : now_ms + timeout_ms;
    mtu_probe_started_ = true;
  }
  pending_.emplace( challenge, datagram_size >= 1200 );
  return true;
}

bool PathValidation::on_response( const Challenge& response, const uint64_t now_ms )
{
  if ( expire( now_ms )
       || ( state_ != PathValidationState::Validating && state_ != PathValidationState::AddressValidated ) ) {
    return false;
  }
  const auto it = pending_.find( response );
  if ( it == pending_.end() ) {
    return false;
  }
  const bool mtu_validated = it->second;
  pending_.erase( it );
  if ( mtu_validated ) {
    state_ = PathValidationState::Validated;
    pending_.clear();
  } else {
    state_ = PathValidationState::AddressValidated;
  }
  return true;
}

bool PathValidation::expire( const uint64_t now_ms )
{
  if ( ( state_ != PathValidationState::Validating && state_ != PathValidationState::AddressValidated )
       || now_ms < deadline_ms_ ) {
    return false;
  }
  pending_.clear();
  state_ = PathValidationState::Failed;
  return true;
}

} // namespace quic
