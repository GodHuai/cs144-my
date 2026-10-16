#include "quic/varint.hh"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

using namespace quic;

void require( const bool condition, const std::string_view message )
{
  if ( !condition ) {
    throw std::runtime_error( std::string { message } );
  }
}

int main()
{
  struct Case
  {
    uint64_t value;
    size_t length;
  };

  constexpr std::array cases { Case { 0, 1 },
                               Case { 63, 1 },
                               Case { 64, 2 },
                               Case { 16383, 2 },
                               Case { 16384, 4 },
                               Case { ( uint64_t { 1 } << 30 ) - 1, 4 },
                               Case { uint64_t { 1 } << 30, 8 },
                               Case { max_varint, 8 } };
  for ( const auto& test : cases ) {
    const std::string encoded = encode_varint( test.value );
    require( encoded.size() == test.length, "incorrect encoded length" );
    size_t offset = 0;
    require( decode_varint( encoded, offset ) == test.value, "boundary roundtrip failed" );
    require( offset == encoded.size(), "boundary offset incorrect" );
    require( !decode_varint( encoded, offset ).has_value(), "end-of-input accepted" );
  }

  // RFC 9000 permits longer-than-necessary encodings.
  const std::string nonminimal { '\x40', '\x25' };
  size_t offset = 0;
  require( decode_varint( nonminimal, offset ) == 37, "nonminimal encoding failed" );
  require( offset == 2, "nonminimal offset incorrect" );

  // RFC 9000 Appendix A.1 sample encodings.
  const std::array samples {
    std::pair { std::string { "\x25", 1 }, uint64_t { 37 } },
    std::pair { std::string { "\x7b\xbd", 2 }, uint64_t { 15293 } },
    std::pair { std::string { "\x9d\x7f\x3e\x7d", 4 }, uint64_t { 494878333 } },
    std::pair { std::string { "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 8 }, uint64_t { 151288809941952652 } } };
  for ( const auto& [bytes, expected] : samples ) {
    offset = 0;
    require( decode_varint( bytes, offset ) == expected, "RFC decode vector failed" );
    require( offset == bytes.size(), "RFC vector offset incorrect" );
    require( encode_varint( expected ) == bytes, "RFC encode vector failed" );
  }

  const std::string truncated { '\xc0', '\x00', '\x00' };
  offset = 0;
  require( !decode_varint( truncated, offset ).has_value(), "truncated input accepted" );
  require( offset == 0, "truncated input advanced offset" );

  bool threw = false;
  try {
    encode_varint( max_varint + 1 );
  } catch ( const std::out_of_range& ) {
    threw = true;
  }
  require( threw, "oversize varint accepted" );
}
