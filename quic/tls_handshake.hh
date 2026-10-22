#pragma once

#include "crypto_streams.hh"
#include "transport_parameters.hh"

#include <array>
#include <memory>
#include <optional>
#include <string>

namespace quic {

struct TlsConfig
{
  bool server { false };
  std::string alpn {};
  std::string server_name {};
  std::string ca_file {};
  std::string certificate_file {};
  std::string private_key_file {};
  TransportParameters local_parameters {};
  // Supply authenticated context from the peer's actual Initial/Retry headers.
  std::string peer_initial_source_connection_id {};
  std::optional<std::string> original_destination_connection_id {};
  std::optional<std::string> retry_source_connection_id {};
};

enum class TlsProgress
{
  NeedData,
  Complete,
  Failed
};

// TLS 1.3 over QUIC CRYPTO streams. Owns all config and callback buffers.
// Input must already be authenticated/decrypted. Handshake completion is TLS
// completion, not QUIC handshake confirmation or permission to deliver STREAMs.
// Single-threaded; no 0-RTT, resumption, post-handshake processing or client auth.
class TlsHandshake
{
public:
  explicit TlsHandshake( TlsConfig config, size_t receive_capacity = 65536, size_t send_capacity = 65536 );
  ~TlsHandshake();
  TlsHandshake( const TlsHandshake& ) = delete;
  TlsHandshake& operator=( const TlsHandshake& ) = delete;

  TlsProgress advance();
  bool receive( PacketKind kind, const CryptoFrame& frame );
  std::optional<CryptoFrame> outgoing( PacketKind kind, uint64_t offset, size_t max_data ) const;

  // TLS_AES_128_GCM_SHA256 only. Initial secrets belong to InitialKeys. Copies
  // returned here are caller-owned sensitive data; never log them.
  std::optional<std::array<uint8_t, 32>> secret( PacketKind kind, bool write ) const;
  std::optional<TransportParameters> peer_parameters() const;
  std::string negotiated_alpn() const;
  bool failed() const;
  bool complete() const;
  std::optional<uint64_t> transport_error() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace quic
