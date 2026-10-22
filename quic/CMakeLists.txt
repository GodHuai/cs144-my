set(QUIC_SOURCES varint.cc packet_number.cc packet_number_space.cc header_protection.cc rtt_estimator.cc frame.cc packet_header.cc transport_parameters.cc path_validation.cc anti_amplification.cc peer_connection_ids.cc local_connection_ids.cc initial_keys.cc retry_integrity.cc initial_packet.cc crypto_streams.cc tls_handshake.cc)

add_library(quic_debug STATIC ${QUIC_SOURCES})
target_include_directories(quic_debug PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(quic_debug PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_library(quic_sanitized EXCLUDE_FROM_ALL STATIC ${QUIC_SOURCES})
target_include_directories(quic_sanitized PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(quic_sanitized PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(quic_sanitized PUBLIC ${SANITIZING_FLAGS})
