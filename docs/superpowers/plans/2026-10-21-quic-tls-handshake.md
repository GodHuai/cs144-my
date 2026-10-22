# QUIC TLS Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute inline with TDD, then request a fresh final review.

**Goal:** Negotiate a real TLS 1.3 client/server handshake through existing CRYPTO streams, with authenticated server identity, ALPN, QUIC transport parameters and directional traffic secrets.

**Architecture:** Use OpenSSL 3.5's external QUIC TLS callbacks, replacing only its record layer. A noncopyable `TlsHandshake` owns SSL_CTX/SSL and its CRYPTO streams, keeps callback input alive until release, maintains independent read/write encryption levels, validates peer parameters and makes failures terminal. No socket or QUIC recovery state is introduced.

**Tech Stack:** C++20; OpenSSL 3.5.9 from pinned official tag archive, static per-worktree build; CMake/CTest with ASan/UBSan.

**Spec:** `docs/quic-v1/requirements.md` R1/R6 and `design.md`; RFC 9001 sections 4, 8; OpenSSL `SSL_set_quic_tls_cbs(3)`.

## Global Constraints

- Existing authorized continuation, worktree `/home/huai/minnow-quic-proposal`, base `b4714fd`. Preserve TCP source and existing QUIC vectors.
- Design ruling: replace the earlier BoringSSL probe candidate with OpenSSL 3.5 external TLS API, because it now exposes the needed callbacks and shares the existing crypto backend. OpenSSL provides TLS only; we continue implementing QUIC transport.
- Pin 3.5.9 tag archive SHA256 `796831ec533bf41998eaaee9d632d921b8a69f57394fa4086ff01a941113d26d`; build under `build/deps`, never install system-wide.
- TLS 1.3 only; `TLS_AES_128_GCM_SHA256` for this first integration; no 0-RTT, resumption or client-certificate API yet. Do not enable key logging or output secrets.
- Clients require nonempty expected DNS hostname and an explicit CA file; always verify both chain and hostname. Servers require certificate/private-key files. ALPN is mandatory, 1–255 bytes, no NUL in C-string config values.
- Local and peer QUIC transport parameters use the existing codec and role/CID validation. CID context is supplied from the future connection; copying config must own every byte used by callbacks.
- Default receive/send buffers retain existing 64 KiB limits. Errors become terminal `failed()` with QUIC transport error: CRYPTO errors unchanged, transport parameter error `0x08`, TLS alerts `0x100 + alert`, callback/internal failures `0x01`.
- Read callback drains only the current read level. Storage remains stable until the release callback, including across encryption level changes and SSL destruction. No C++ exception may escape a C callback. Outgoing callback must reject capacity exhaustion instead of dropping bytes.
- TLS handshake completion differs from QUIC handshake confirmation. Finished status requires peer parameters and the configured ALPN plus TLS success; it must not authorize application delivery by itself.

## Review Focus

- Wrong CA/hostname and ALPN mismatch must be terminal, without reporting success or releasing traffic secrets to callers.
- Out-of-order next-level CRYPTO must stay isolated until TLS requests that level; a retained record cannot dangle on release or destructor.
- Missing/invalid/CID-inconsistent peer parameters must map to transport errors and never pass handshake completion.
- Callbacks must contain exceptions and resource errors; inputs and queued output must remain bounded.
- Error handling must prevent retrying a failed connection; no 0-RTT or unsupported cipher may be silently enabled.

### Task 1: Dependency and handshake adapter

**Files:** `scripts/build-quic-openssl.sh`, root/quic/tests CMake, `etc/tests.cmake`, `quic/tls_handshake.hh/.cc`, `tests/quic_tls_handshake.cc`, test credential generator and docs.

**Interfaces:** `TlsConfig` owns role, ALPN, server_name, CA/cert/key paths, local parameters, expected peer Initial CID and optional original/Retry CID. `TlsHandshake(config, receive_capacity=65536, send_capacity=65536)`; `advance() -> TlsProgress { NeedData, Complete, Failed }`; `receive(PacketKind,const CryptoFrame&) -> bool`; `outgoing(PacketKind,offset,max_data) -> optional<CryptoFrame>`; `secret(PacketKind,bool write) -> optional<array<uint8_t,32>>`; `peer_parameters() -> optional<TransportParameters>`; `negotiated_alpn() -> string`; `failed()/complete() -> bool`; `transport_error() -> optional<uint64_t>`.

- [x] Write reproducible pinned-archive dependency builder; build locally in VM, check 3.5 QUIC API and baseline QUIC suite.
- [x] Write adapter tests first: valid trusted localhost cert/ALPN/parameters, Initial & Handshake fragments delivered in reverse order and duplicated, both ends complete and read/write secrets cross-match without printing them. Wrong CA, wrong hostname, ALPN mismatch, invalid peer CID, 0-RTT, capacity exhaustion and config validation fail; failed sessions remain terminal. Compile expecting missing adapter header.
- [x] Implement RAII adapter and callbacks with input lifetime preservation, existing CRYPTO reassembly, TLS1.3/cipher constraints, certificate/ALPN/parameter verification and terminal errors.
- [x] Run new test and all QUIC tests under sanitizers; record RED/GREEN and warnings/format checks. Run full CTest with explicit 30-second per-test budget, report pre-existing slow tests and missing executables by name; do not change those tests or expectations.
- [x] Update dependency/usage/coverage/learning docs, obtain fresh review, fix material findings with regressions and commit on the existing branch. Record limitations: no encrypted Handshake/1-RTT packets, UDP connection, ACK/recovery, resumption or full interoperability yet.

## Execution Evidence

- RED: the initial adapter test failed compilation because `quic/tls_handshake.hh` was absent.
- GREEN: real trusted/negative two-party TLS tests passed with ASan/UBSan and OpenSSL 3.5.9.
- Review regressions: queued Initial gap at offset 10000 first failed with "old-level buffered data ignored at TLS transition". Fixed read-transition and late-old-level checks; retransmissions remain accepted. A contiguous ClientHello + extra byte first failed the required 0x0a assertion because OpenSSL reported TLS unexpected_message (0x10a). Verified OpenSSL fatal-error ordering and narrowly map its NOT_ON_RECORD_BOUNDARY reason to QUIC PROTOCOL_VIOLATION; the regression now passes.
- Added real incremental TLS driving at every 13-byte fragment; current sanitized TLS binary passes. Fresh reviewer confirmed the fixes and expiry-aware test credential generation.
- Dependency deviation: local VM cannot reach GitHub; downloaded the pinned official tag archive on host and copied it into build/deps. Source hash verified by the builder. No system installation or TLS replacement code.

- Final checks: `cmake --build build --target functionality_testing quic_debug -j2` succeeded. QUIC CTest 15/15 passed (8.84s, ASan/UBSan); full CTest with 30s per test and -j2 completed in 102.39s, 46/53 passed, five existing non-QUIC tests timed out and two existing test executables were missing. All QUIC tests passed in the full run. Details in tls-handshake.md and ignored build log. clang-format dry-run, shell syntax and git diff --check passed. Expired certificate refresh was exercised in isolated build/quic-tls-refresh-check.
- Review disposition: all important/minor findings fixed, no deferred minors. Accepted exclusions: packet protection/UDP/recovery/independent interoperability and resumption/0-RTT/post-handshake processing remain future milestones; Linux ARM64 builder matches the user's VM.
