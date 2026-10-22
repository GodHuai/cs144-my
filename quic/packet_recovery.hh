#pragma once

#include "congestion_control.hh"
#include "frame.hh"
#include "packet_number_space.hh"
#include "rtt_estimator.hh"

#include <array>
#include <deque>
#include <map>
#include <memory>

namespace quic {
struct RecoveryData
{
  explicit RecoveryData( Frame value ) : frame( std::move( value ) ) {}
  Frame frame;
  bool acknowledged {}, queued {};
};
struct RecoverySend
{
  std::shared_ptr<RecoveryData> data;
  bool probe {};
};
struct RecoveryContext
{
  bool confirmed {}, peer_validated {};
  double max_ack_delay_ms { 25 };
  uint8_t ack_delay_exponent { 3 };
  std::optional<PacketKind> validation_probe_space {};
};
// Single-path recovery with physical flight accounting and basic NewReno. All times are
// monotonic microseconds. ACK validity is checked by PacketAcknowledgments first.
class PacketRecovery
{
public:
  using Events = std::array<std::vector<uint64_t>, 3>;
  void sent( PacketKind kind,
             uint64_t pn,
             uint64_t now,
             std::shared_ptr<RecoveryData> data,
             uint64_t bytes = 0,
             bool padded = false );
  bool can_send( PacketKind kind, uint64_t bytes, bool eliciting, bool padded, bool probe = false ) const;
  CongestionStats congestion_stats() const { return congestion_.stats(); }
  std::optional<RecoverySend> pending( PacketKind kind );
  std::vector<uint64_t> acknowledged( PacketKind kind,
                                      const AckFrame& ack,
                                      uint64_t now,
                                      const RecoveryContext& context );
  std::optional<uint64_t> deadline( const RecoveryContext& context ) const;
  Events timeout( uint64_t now, const RecoveryContext& context );
  std::optional<RecoverySend> take_pending( PacketKind kind );
  void discard( PacketKind kind );
  const RttEstimator& rtt() const { return rtt_; }

private:
  struct Record
  {
    uint64_t time;
    std::shared_ptr<RecoveryData> data;
  };
  struct Space
  {
    struct Flight
    {
      uint64_t time, bytes;
      bool eliciting;
    };
    std::map<uint64_t, Flight> flight {};
    std::map<uint64_t, Record> active {}, recent {};
    std::deque<RecoverySend> pending {};
    std::optional<uint64_t> largest_acked {};
    uint64_t last_sent {};
  };
  std::array<Space, 3> spaces_ {};
  RttEstimator rtt_ {};
  NewReno congestion_ {};
  unsigned pto_count_ {};
  std::optional<uint64_t> validation_anchor_ {};
  std::weak_ptr<RecoveryData> pending_probe_ {};
  Space& space( PacketKind kind );
  const Space& space( PacketKind kind ) const;
  uint64_t loss_delay() const;
  std::optional<uint64_t> loss_time( const Space& s ) const;
  std::optional<std::pair<uint64_t, PacketKind>> pto( const RecoveryContext& context ) const;
  void detect_lost( Space& s, uint64_t now, std::vector<uint64_t>& released );
  static void remember( Space& s, uint64_t pn, Record record );
  static void enqueue( Space& s, const std::shared_ptr<RecoveryData>& data, bool probe );
};
} // namespace quic
