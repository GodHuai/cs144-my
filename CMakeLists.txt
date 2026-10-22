cmake_minimum_required(VERSION 3.24.2)

project(minnow CXX)

if(${CMAKE_GENERATOR} STREQUAL "Unix Makefiles")
  set(CMAKE_MAKE_PROGRAM "${PROJECT_SOURCE_DIR}/scripts/make-parallel.sh" CACHE STRING "" FORCE)
endif()

if(${PROJECT_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "Minnow must be built outside its source directory, e.g. `cmake -B build`.")
endif()

include(etc/build_type.cmake)
include(etc/cflags.cmake)
include(etc/scanners.cmake)
include(etc/tests.cmake)

include_directories("${PROJECT_SOURCE_DIR}/util")
include_directories("${PROJECT_SOURCE_DIR}/src")

find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
check_cxx_source_compiles("#include <openssl/ssl.h>
int main() { return SSL_set_quic_tls_cbs(nullptr, nullptr, nullptr); }"
  QUIC_OPENSSL_EXTERNAL_TLS)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT QUIC_OPENSSL_EXTERNAL_TLS)
  message(FATAL_ERROR "OpenSSL external QUIC TLS API is required; see docs/quic-v1/tls-handshake.md")
endif()

add_subdirectory("${PROJECT_SOURCE_DIR}/util")
add_subdirectory("${PROJECT_SOURCE_DIR}/src")
add_subdirectory("${PROJECT_SOURCE_DIR}/quic")
add_subdirectory("${PROJECT_SOURCE_DIR}/tests")
add_subdirectory("${PROJECT_SOURCE_DIR}/apps")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
