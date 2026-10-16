add_library(quic_debug STATIC varint.cc)
target_include_directories(quic_debug PUBLIC "${PROJECT_SOURCE_DIR}")

add_library(quic_sanitized EXCLUDE_FROM_ALL STATIC varint.cc)
target_include_directories(quic_sanitized PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_options(quic_sanitized PUBLIC ${SANITIZING_FLAGS})
