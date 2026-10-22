#include "udp_socket.hh"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace quic {
namespace {
[[noreturn]] void os_error( const char* operation )
{
  throw std::system_error( errno, std::generic_category(), operation );
}
const sockaddr_in& v4( const sockaddr_storage& storage )
{
  return reinterpret_cast<const sockaddr_in&>( storage );
}
const sockaddr_in6& v6( const sockaddr_storage& storage )
{
  return reinterpret_cast<const sockaddr_in6&>( storage );
}
}

UdpEndpoint UdpEndpoint::numeric( std::string_view ip, uint16_t port, uint32_t scope_id )
{
  if ( ip.empty() || ip.find( '\0' ) != std::string_view::npos )
    throw std::invalid_argument( "invalid numeric UDP address" );
  UdpEndpoint result;
  const std::string text { ip };
  sockaddr_in ipv4 {};
  ipv4.sin_family = AF_INET;
  ipv4.sin_port = htons( port );
  if ( inet_pton( AF_INET, text.c_str(), &ipv4.sin_addr ) == 1 ) {
    if ( scope_id != 0 )
      throw std::invalid_argument( "IPv4 address cannot have a scope" );
    std::memcpy( &result.address_, &ipv4, sizeof( ipv4 ) );
    return result;
  }
  sockaddr_in6 ipv6 {};
  ipv6.sin6_family = AF_INET6;
  ipv6.sin6_port = htons( port );
  ipv6.sin6_scope_id = scope_id;
  if ( inet_pton( AF_INET6, text.c_str(), &ipv6.sin6_addr ) != 1 )
    throw std::invalid_argument( "invalid numeric UDP address" );
  std::memcpy( &result.address_, &ipv6, sizeof( ipv6 ) );
  return result;
}
socklen_t UdpEndpoint::length() const
{
  return family() == AF_INET ? sizeof( sockaddr_in ) : sizeof( sockaddr_in6 );
}
std::string UdpEndpoint::ip() const
{
  char text[INET6_ADDRSTRLEN] {};
  const void* address = family() == AF_INET ? static_cast<const void*>( &v4( address_ ).sin_addr )
                                            : static_cast<const void*>( &v6( address_ ).sin6_addr );
  if ( !inet_ntop( family(), address, text, sizeof( text ) ) )
    os_error( "inet_ntop" );
  return text;
}
uint16_t UdpEndpoint::port() const
{
  return ntohs( family() == AF_INET ? v4( address_ ).sin_port : v6( address_ ).sin6_port );
}
uint32_t UdpEndpoint::scope_id() const
{
  return family() == AF_INET6 ? v6( address_ ).sin6_scope_id : 0;
}
bool UdpEndpoint::operator==( const UdpEndpoint& other ) const
{
  if ( family() != other.family() || port() != other.port() || scope_id() != other.scope_id() )
    return false;
  if ( family() == AF_INET )
    return v4( address_ ).sin_addr.s_addr == v4( other.address_ ).sin_addr.s_addr;
  return std::memcmp( &v6( address_ ).sin6_addr, &v6( other.address_ ).sin6_addr, sizeof( in6_addr ) ) == 0;
}

UdpSocket::UdpSocket( const UdpEndpoint& bind_address ) : family_( bind_address.family() )
{
  fd_ = socket( family_, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0 );
  if ( fd_ < 0 )
    os_error( "socket" );
  try {
    const int enabled = 1;
    if ( family_ == AF_INET6 && setsockopt( fd_, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof( enabled ) ) < 0 )
      os_error( "IPV6_V6ONLY" );
    if ( setsockopt( fd_,
                     family_ == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                     family_ == AF_INET ? IP_RECVTOS : IPV6_RECVTCLASS,
                     &enabled,
                     sizeof( enabled ) )
         < 0 )
      os_error( "enable ECN receive" );
    if ( bind( fd_, reinterpret_cast<const sockaddr*>( &bind_address.address_ ), bind_address.length() ) < 0 )
      os_error( "bind" );
  } catch ( ... ) {
    close( fd_ );
    throw;
  }
}
UdpSocket::~UdpSocket()
{
  close( fd_ );
}
UdpEndpoint UdpSocket::local_endpoint() const
{
  UdpEndpoint result;
  socklen_t size = sizeof( result.address_ );
  if ( getsockname( fd_, reinterpret_cast<sockaddr*>( &result.address_ ), &size ) < 0 )
    os_error( "getsockname" );
  return result;
}
bool UdpSocket::send( const UdpEndpoint& peer, std::string_view payload, uint8_t ecn )
{
  if ( peer.family() != family_ || ecn > 3 )
    throw std::invalid_argument( "UDP family mismatch or invalid ECN" );
  if ( payload.size() > ( family_ == AF_INET ? 65507U : 65527U ) )
    throw std::length_error( "UDP payload too large" );
  iovec data { const_cast<char*>( payload.data() ), payload.size() };
  alignas( cmsghdr ) char control[CMSG_SPACE( sizeof( int ) )] {};
  msghdr message {};
  message.msg_name = const_cast<sockaddr_storage*>( &peer.address_ );
  message.msg_namelen = peer.length();
  message.msg_iov = &data;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof( control );
  auto* header = CMSG_FIRSTHDR( &message );
  header->cmsg_level = family_ == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
  header->cmsg_type = family_ == AF_INET ? IP_TOS : IPV6_TCLASS;
  header->cmsg_len = CMSG_LEN( sizeof( int ) );
  const int traffic_class = ecn;
  std::memcpy( CMSG_DATA( header ), &traffic_class, sizeof( traffic_class ) );
  ssize_t sent;
  do {
    sent = sendmsg( fd_, &message, MSG_DONTWAIT );
  } while ( sent < 0 && errno == EINTR );
  if ( sent < 0 ) {
    if ( errno == EAGAIN || errno == EWOULDBLOCK )
      return false;
    os_error( "sendmsg" );
  }
  if ( static_cast<size_t>( sent ) != payload.size() )
    throw std::runtime_error( "partial UDP send" );
  return true;
}
std::optional<UdpDatagram> UdpSocket::receive( size_t capacity )
{
  if ( capacity == 0 || capacity > 65535 )
    throw std::invalid_argument( "UDP receive capacity must be 1..65535" );
  UdpEndpoint peer;
  std::string payload( capacity, '\0' );
  iovec data { payload.data(), payload.size() };
  alignas( cmsghdr ) char control[CMSG_SPACE( sizeof( int ) )] {};
  msghdr message {};
  message.msg_name = &peer.address_;
  message.msg_namelen = sizeof( peer.address_ );
  message.msg_iov = &data;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof( control );
  ssize_t received;
  do {
    received = recvmsg( fd_, &message, MSG_DONTWAIT );
  } while ( received < 0 && errno == EINTR );
  if ( received < 0 ) {
    if ( errno == EAGAIN || errno == EWOULDBLOCK )
      return std::nullopt;
    os_error( "recvmsg" );
  }
  if ( ( message.msg_flags & ( MSG_TRUNC | MSG_CTRUNC ) ) != 0 )
    throw std::length_error( "truncated UDP payload or metadata discarded" );
  if ( peer.family() != family_ || message.msg_namelen < peer.length() )
    throw std::runtime_error( "invalid UDP source address" );
  std::optional<uint8_t> ecn;
  for ( auto* header = CMSG_FIRSTHDR( &message ); header; header = CMSG_NXTHDR( &message, header ) ) {
    if ( family_ == AF_INET && header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_TOS
         && header->cmsg_len >= CMSG_LEN( sizeof( uint8_t ) ) ) {
      ecn = static_cast<uint8_t>( *CMSG_DATA( header ) & 3 );
    } else if ( family_ == AF_INET6 && header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_TCLASS
                && header->cmsg_len >= CMSG_LEN( sizeof( int ) ) ) {
      int traffic_class = 0;
      std::memcpy( &traffic_class, CMSG_DATA( header ), sizeof( traffic_class ) );
      ecn = static_cast<uint8_t>( traffic_class & 3 );
    }
  }
  payload.resize( received );
  return UdpDatagram { peer, std::move( payload ), ecn };
}
} // namespace quic
