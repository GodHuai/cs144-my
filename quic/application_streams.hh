#pragma once
#include "frame.hh"
#include "transport_parameters.hh"
#include <array>
#include <map>

namespace quic {
struct StreamRead
{
  std::string data {};
  bool eof {};
  std::optional<uint64_t> reset_error {};
};
// Bounded, single-threaded stream/flow state. All credit is absolute and negotiated.
class ApplicationStreams
{
public:
  ApplicationStreams( bool server, TransportParameters local, TransportParameters peer );
  static void validate_local( const TransportParameters& local );
  static bool handles( const Frame& frame );
  std::optional<uint64_t> open( bool unidirectional );
  bool write( uint64_t id, std::string_view data, bool fin );
  StreamRead read( uint64_t id, size_t maximum );
  std::vector<uint64_t> ids() const;
  bool reset( uint64_t id, uint64_t error );
  bool stop( uint64_t id, uint64_t error );
  // Transactional: a rejected packet changes no stream state.
  std::optional<uint64_t> receive( const std::vector<Frame>& frames );
  std::optional<Frame> pending();
  void sent( const Frame& frame );
  void acknowledged( const Frame& frame );
  size_t buffered() const { return buffered_; }

private:
  struct Stream
  {
    uint64_t send_limit {}, send_next {}, recv_limit {}, recv_window {}, high {}, read {};
    std::string queued {};
    std::map<uint64_t, std::string> inflight {}, received {};
    std::optional<uint64_t> final {}, reset_error {}, blocked {};
    bool fin_requested {}, fin_sent {}, fin_acked {}, send_reset {};
  };
  struct Error
  {
    uint64_t code;
  };
  bool server_;
  TransportParameters local_, peer_;
  std::map<uint64_t, Stream> streams_ {};
  std::array<uint64_t, 2> opened_ {}, peer_opened_ {}, send_counts_ {}, recv_counts_ {};
  uint64_t send_limit_ {}, sent_ {}, recv_limit_ {}, consumed_ {}, received_ {};
  size_t buffered_ {};
  std::optional<uint64_t> data_blocked_ {}, last_stream_ {};
  std::array<std::optional<uint64_t>, 2> streams_blocked_ {};
  std::map<std::pair<size_t, uint64_t>, Frame> controls_ {};
  bool local( uint64_t id ) const;
  bool sends( uint64_t id ) const;
  bool receives( uint64_t id ) const;
  Stream make( uint64_t id ) const;
  Stream& get( uint64_t id, bool sending, bool from_peer );
  void apply( const Frame& frame );
  void accept( uint64_t id, uint64_t end, bool final );
  void credit( Stream& stream, uint64_t id, uint64_t bytes );
  void queue( Frame frame );
  static std::pair<size_t, uint64_t> key( const Frame& frame );
};
} // namespace quic
