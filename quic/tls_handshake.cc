#include "tls_handshake.hh"

#include "varint.hh"

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace quic {
namespace {
bool c_string( const std::string& value )
{
  return value.find( '\0' ) == std::string::npos;
}

std::optional<std::string_view> view( const std::optional<std::string>& value )
{
  return value ? std::optional<std::string_view> { *value } : std::nullopt;
}

std::optional<size_t> key_index( const PacketKind kind, const bool write )
{
  if ( kind != PacketKind::Handshake && kind != PacketKind::OneRtt ) {
    return std::nullopt;
  }
  return ( kind == PacketKind::Handshake ? size_t { 0 } : size_t { 2 } ) + ( write ? 1 : 0 );
}
} // namespace

struct TlsHandshake::Impl
{
  TlsConfig config;
  CryptoStreams streams;
  WriteSecretObserver write_secret_observer;
  std::string local_parameters {};
  std::string input_record {};
  bool record_held { false };
  PacketKind read_level { PacketKind::Initial };
  PacketKind write_level { PacketKind::Initial };
  std::array<std::optional<std::array<uint8_t, 32>>, 4> keys {};
  std::optional<TransportParameters> peer {};
  std::optional<uint64_t> error {};
  bool done { false };
  std::unique_ptr<SSL_CTX, decltype( &SSL_CTX_free )> ctx { nullptr, SSL_CTX_free };
  std::unique_ptr<SSL, decltype( &SSL_free )> ssl { nullptr, SSL_free };

  void cleanse() noexcept
  {
    for ( auto& key : keys ) {
      if ( key ) {
        OPENSSL_cleanse( key->data(), key->size() );
        key.reset();
      }
    }
  }

  void fail( const uint64_t code ) noexcept
  {
    if ( !error ) {
      error = code;
    }
    done = false;
    cleanse();
  }

  template<class F>
  int callback( F&& action ) noexcept
  {
    if ( error ) {
      return 0;
    }
    try {
      return action();
    } catch ( ... ) {
      fail( 0x01 );
      return 0;
    }
  }

  static int send( SSL*, const unsigned char* bytes, size_t length, size_t* consumed, void* arg ) noexcept
  {
    auto& self = *static_cast<Impl*>( arg );
    *consumed = 0;
    return self.callback( [&] {
      if ( !self.streams.append( self.write_level, { reinterpret_cast<const char*>( bytes ), length } ) ) {
        self.fail( 0x01 );
        return 0;
      }
      *consumed = length;
      return 1;
    } );
  }

  static int recv( SSL*, const unsigned char** bytes, size_t* length, void* arg ) noexcept
  {
    auto& self = *static_cast<Impl*>( arg );
    *bytes = nullptr;
    *length = 0;
    return self.callback( [&] {
      if ( self.record_held ) {
        self.fail( 0x01 );
        return 0;
      }
      self.input_record = self.streams.take_contiguous( self.read_level );
      *length = self.input_record.size();
      self.record_held = *length != 0;
      *bytes = reinterpret_cast<const unsigned char*>( self.input_record.data() );
      return 1; // Zero length is WANT_READ, not an error.
    } );
  }

  static int release( SSL*, size_t length, void* arg ) noexcept
  {
    auto& self = *static_cast<Impl*>( arg );
    // Release may run during SSL_free after a terminal error. Never change the
    // record while OpenSSL owns it, including when its encryption level changes.
    if ( !self.record_held || self.input_record.size() != length ) {
      self.fail( 0x01 );
      return 0;
    }
    self.record_held = false;
    self.input_record.clear();
    return 1;
  }

  static int yield_secret( SSL*,
                           uint32_t level,
                           int direction,
                           const unsigned char* bytes,
                           size_t length,
                           void* arg ) noexcept
  {
    auto& self = *static_cast<Impl*>( arg );
    return self.callback( [&] {
      if ( ( level != OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE && level != OSSL_RECORD_PROTECTION_LEVEL_APPLICATION )
           || ( direction != 0 && direction != 1 ) || length != 32 ) {
        self.fail( 0x01 );
        return 0;
      }
      const auto kind
        = level == OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE ? PacketKind::Handshake : PacketKind::OneRtt;
      if ( direction == 0 && kind != self.read_level
           && ( self.streams.bytes_buffered( self.read_level ) != 0 || self.record_held ) ) {
        self.fail( 0x0a );
        return 0;
      }
      auto& key = self.keys[*key_index( kind, direction == 1 )];
      key.emplace();
      std::copy_n( bytes, length, key->begin() );
      if ( direction == 1 && self.write_secret_observer )
        self.write_secret_observer( kind, *key );
      ( direction == 1 ? self.write_level : self.read_level ) = kind;
      return 1;
    } );
  }

  static int parameters( SSL*, const unsigned char* bytes, size_t length, void* arg ) noexcept
  {
    auto& self = *static_cast<Impl*>( arg );
    return self.callback( [&] {
      auto decoded = decode_transport_parameters( { reinterpret_cast<const char*>( bytes ), length } );
      const TransportParameterContext context { !self.config.server,
                                                self.config.peer_initial_source_connection_id,
                                                view( self.config.original_destination_connection_id ),
                                                view( self.config.retry_source_connection_id ) };
      if ( self.config.defer_peer_initial_source_connection_id || self.peer || !decoded
           || !validate_transport_parameters( *decoded, context ) ) {
        self.fail( 0x08 );
        return 0;
      }
      self.peer = std::move( decoded );
      return 1;
    } );
  }

  static int alert( SSL*, unsigned char code, void* arg ) noexcept
  {
    // OpenSSL rejects surplus bytes in its currently held record before
    // yielding a new read secret. QUIC calls this a level-boundary violation,
    // rather than a TLS record error (RFC 9001 section 4.1.3).
    const auto last_error = ERR_peek_last_error();
    const bool boundary = code == SSL_AD_UNEXPECTED_MESSAGE && ERR_GET_LIB( last_error ) == ERR_LIB_SSL
                          && ERR_GET_REASON( last_error ) == SSL_R_NOT_ON_RECORD_BOUNDARY;
    static_cast<Impl*>( arg )->fail( boundary ? 0x0a : 0x100 + code );
    return 1;
  }

  static int alpn( SSL*,
                   const unsigned char** out,
                   unsigned char* out_length,
                   const unsigned char* in,
                   unsigned int in_length,
                   void* arg ) noexcept
  {
    const auto& self = *static_cast<Impl*>( arg );
    size_t offset = 0;
    while ( offset < in_length ) {
      const size_t length = in[offset++];
      if ( length == 0 || length > in_length - offset ) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
      }
      if ( std::string_view { reinterpret_cast<const char*>( in + offset ), length } == self.config.alpn ) {
        *out = in + offset;
        *out_length = static_cast<unsigned char>( length );
        return SSL_TLSEXT_ERR_OK;
      }
      offset += length;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  Impl( TlsConfig cfg, size_t receive_capacity, size_t send_capacity, WriteSecretObserver observer )
    : config( std::move( cfg ) )
    , streams( receive_capacity, send_capacity )
    , write_secret_observer( std::move( observer ) )
  {
    const auto own_cid = config.local_parameters.find( 0x0f );
    const auto original = config.local_parameters.find( 0x00 );
    const auto retry = config.local_parameters.find( 0x10 );
    if ( own_cid == config.local_parameters.end() || config.alpn.empty() || config.alpn.size() > 255
         || !c_string( config.server_name ) || !c_string( config.ca_file ) || !c_string( config.certificate_file )
         || !c_string( config.private_key_file ) || config.peer_initial_source_connection_id.size() > 20
         || ( config.original_destination_connection_id && config.original_destination_connection_id->size() > 20 )
         || ( config.retry_source_connection_id && config.retry_source_connection_id->size() > 20 )
         || ( !config.server
              && ( config.server_name.empty() || config.ca_file.empty()
                   || !config.original_destination_connection_id ) )
         || ( config.server && ( config.certificate_file.empty() || config.private_key_file.empty() ) ) ) {
      throw std::invalid_argument( "invalid QUIC TLS configuration" );
    }
    const TransportParameterContext own_context {
      config.server,
      own_cid->second,
      original == config.local_parameters.end() ? std::nullopt
                                                : std::optional<std::string_view> { original->second },
      retry == config.local_parameters.end() ? std::nullopt : std::optional<std::string_view> { retry->second } };
    if ( !validate_transport_parameters( config.local_parameters, own_context ) ) {
      throw std::invalid_argument( "invalid local QUIC transport parameters" );
    }
    local_parameters = encode_transport_parameters( config.local_parameters );
    ctx.reset( SSL_CTX_new( TLS_method() ) );
    if ( !ctx || !SSL_CTX_set_min_proto_version( ctx.get(), TLS1_3_VERSION )
         || !SSL_CTX_set_max_proto_version( ctx.get(), TLS1_3_VERSION )
         || !SSL_CTX_set_ciphersuites( ctx.get(), "TLS_AES_128_GCM_SHA256" )
         || !SSL_CTX_set_num_tickets( ctx.get(), 0 ) ) {
      throw std::runtime_error( "cannot initialize QUIC TLS context" );
    }
    SSL_CTX_set_session_cache_mode( ctx.get(), SSL_SESS_CACHE_OFF );
    if ( config.server ) {
      if ( SSL_CTX_use_certificate_chain_file( ctx.get(), config.certificate_file.c_str() ) != 1
           || SSL_CTX_use_PrivateKey_file( ctx.get(), config.private_key_file.c_str(), SSL_FILETYPE_PEM ) != 1
           || SSL_CTX_check_private_key( ctx.get() ) != 1 ) {
        throw std::invalid_argument( "cannot load QUIC TLS server certificate/key" );
      }
      SSL_CTX_set_alpn_select_cb( ctx.get(), alpn, this );
    } else {
      SSL_CTX_set_verify( ctx.get(), SSL_VERIFY_PEER, nullptr );
      if ( SSL_CTX_load_verify_locations( ctx.get(), config.ca_file.c_str(), nullptr ) != 1 ) {
        throw std::invalid_argument( "cannot load QUIC TLS trust anchors" );
      }
    }
    ssl.reset( SSL_new( ctx.get() ) );
    static const OSSL_DISPATCH callbacks[]
      = { { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, reinterpret_cast<void ( * )( void )>( send ) },
          { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, reinterpret_cast<void ( * )( void )>( recv ) },
          { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, reinterpret_cast<void ( * )( void )>( release ) },
          { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, reinterpret_cast<void ( * )( void )>( yield_secret ) },
          { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, reinterpret_cast<void ( * )( void )>( parameters ) },
          { OSSL_FUNC_SSL_QUIC_TLS_ALERT, reinterpret_cast<void ( * )( void )>( alert ) },
          { 0, nullptr } };
    if ( !ssl || SSL_set_quic_tls_cbs( ssl.get(), callbacks, this ) != 1
         || SSL_set_quic_tls_transport_params( ssl.get(),
                                               reinterpret_cast<const unsigned char*>( local_parameters.data() ),
                                               local_parameters.size() )
              != 1
         || SSL_set_quic_tls_early_data_enabled( ssl.get(), 0 ) != 1 ) {
      throw std::runtime_error( "cannot initialize QUIC TLS callbacks" );
    }
    if ( config.server ) {
      SSL_set_accept_state( ssl.get() );
    } else {
      const std::string wire_alpn = std::string( 1, static_cast<char>( config.alpn.size() ) ) + config.alpn;
      if ( SSL_set_alpn_protos( ssl.get(),
                                reinterpret_cast<const unsigned char*>( wire_alpn.data() ),
                                static_cast<unsigned int>( wire_alpn.size() ) )
             != 0
           || SSL_set_tlsext_host_name( ssl.get(), config.server_name.c_str() ) != 1
           || SSL_set1_host( ssl.get(), config.server_name.c_str() ) != 1 ) {
        throw std::invalid_argument( "cannot set QUIC TLS peer identity/ALPN" );
      }
      SSL_set_connect_state( ssl.get() );
    }
  }

  ~Impl()
  {
    ssl.reset(); // May release input_record: other members must still be alive.
    cleanse();
  }
};

TlsHandshake::TlsHandshake( TlsConfig config,
                            size_t receive_capacity,
                            size_t send_capacity,
                            WriteSecretObserver observer )
  : impl_( std::make_unique<Impl>( std::move( config ), receive_capacity, send_capacity, std::move( observer ) ) )
{}
TlsHandshake::~TlsHandshake() = default;

bool TlsHandshake::bind_peer_initial_source_connection_id( std::string cid )
{
  if ( !impl_->config.defer_peer_initial_source_connection_id || impl_->peer || impl_->error || cid.size() > 20 )
    return false;
  impl_->config.peer_initial_source_connection_id = std::move( cid );
  impl_->config.defer_peer_initial_source_connection_id = false;
  return true;
}

void TlsHandshake::discard_keys( PacketKind kind )
{
  if ( kind != PacketKind::Initial && kind != PacketKind::Handshake )
    throw std::invalid_argument( "only handshake encryption levels can be retired" );
  if ( kind == PacketKind::Handshake ) {
    for ( size_t i = 0; i < 2; ++i ) {
      if ( impl_->keys[i] ) {
        OPENSSL_cleanse( impl_->keys[i]->data(), impl_->keys[i]->size() );
        impl_->keys[i].reset();
      }
    }
  }
  impl_->streams.discard( kind );
}

TlsProgress TlsHandshake::advance()
{
  if ( impl_->error )
    return TlsProgress::Failed;
  if ( impl_->done )
    return TlsProgress::Complete;
  ERR_clear_error();
  const int result = SSL_do_handshake( impl_->ssl.get() );
  const int ssl_error = result == 1 ? SSL_ERROR_NONE : SSL_get_error( impl_->ssl.get(), result );
  if ( impl_->error )
    return TlsProgress::Failed;
  if ( result == 1 ) {
    const unsigned char* selected = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected( impl_->ssl.get(), &selected, &length );
    if ( !impl_->peer ) {
      impl_->fail( 0x100 + SSL_AD_MISSING_EXTENSION );
    } else if ( std::string_view { reinterpret_cast<const char*>( selected ), length } != impl_->config.alpn ) {
      impl_->fail( 0x100 + SSL_AD_NO_APPLICATION_PROTOCOL );
    } else if ( !impl_->config.server && SSL_get_verify_result( impl_->ssl.get() ) != X509_V_OK ) {
      impl_->fail( 0x100 + SSL_AD_BAD_CERTIFICATE );
    } else {
      impl_->done = true;
      return TlsProgress::Complete;
    }
  } else if ( ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE ) {
    return TlsProgress::NeedData;
  } else {
    impl_->fail( 0x01 );
  }
  return TlsProgress::Failed;
}

bool TlsHandshake::receive( PacketKind kind, const CryptoFrame& frame )
{
  if ( impl_->error )
    return false;
  const bool old_level = ( kind == PacketKind::Initial && impl_->read_level != PacketKind::Initial )
                         || ( kind == PacketKind::Handshake && impl_->read_level == PacketKind::OneRtt );
  if ( old_level ) {
    if ( frame.offset > max_varint || frame.data.size() > max_varint - frame.offset ) {
      impl_->fail( 0x07 );
    } else if ( !frame.data.empty() && frame.offset + frame.data.size() > impl_->streams.read_offset( kind ) ) {
      impl_->fail( 0x0a );
    }
    return !impl_->error; // Fully consumed retransmissions carry no new bytes.
  }
  try {
    if ( const auto error = impl_->streams.receive( kind, frame ) ) {
      impl_->fail( static_cast<uint64_t>( *error ) );
    }
  } catch ( ... ) {
    impl_->fail( 0x01 );
  }
  return !impl_->error;
}

std::optional<CryptoFrame> TlsHandshake::outgoing( PacketKind kind, uint64_t offset, size_t max_data ) const
{
  return impl_->error ? std::nullopt : impl_->streams.frame( kind, offset, max_data );
}

std::optional<std::array<uint8_t, 32>> TlsHandshake::secret( PacketKind kind, bool write ) const
{
  const auto index = key_index( kind, write );
  return !impl_->error && index ? impl_->keys[*index] : std::nullopt;
}

std::optional<TransportParameters> TlsHandshake::peer_parameters() const
{
  return complete() ? impl_->peer : std::nullopt;
}

std::string TlsHandshake::negotiated_alpn() const
{
  return complete() ? impl_->config.alpn : std::string {};
}

bool TlsHandshake::failed() const
{
  return impl_->error.has_value();
}
bool TlsHandshake::complete() const
{
  return impl_->done && !failed();
}
std::optional<uint64_t> TlsHandshake::transport_error() const
{
  return impl_->error;
}

} // namespace quic
