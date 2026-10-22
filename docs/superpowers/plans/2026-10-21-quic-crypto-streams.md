# QUIC CRYPTO Streams Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Supply ordered, bounded TLS handshake bytes and reproducible outgoing CRYPTO fragments independently for Initial, Handshake and 1-RTT.

**Architecture:** Add `quic/crypto_streams.hh/.cc`, using sparse merged intervals for receive data and retained outgoing bytes per encryption level. Use existing `CryptoFrame`, frame codecs and Initial protection in integration tests. The existing project design and the user's instruction to continue authorize this prerequisite to its TLS integration task; no TLS library or connection state machine is claimed here.

**Tech Stack:** C++20, existing CMake/CTest, ASan/UBSan, existing OpenSSL crypto dependency.

**Spec:** `docs/quic-v1/design.md`, `docs/quic-v1/requirements.md`; RFC 9000 sections 7.5 and 19.6; RFC 9001 section 4.1.3.

## Global Constraints

- Worktree `/home/huai/minnow-quic-proposal`, branch `quic-v1-proposal`; preserve existing TCP functionality.
- No CRYPTO data in 0-RTT. Offsets start at zero separately per level; offset plus length is at most `2^62-1`.
- Default receive/send storage limits are 65536 data bytes per level. Receive limits below 4096 are invalid.
- Count unique undelivered receive bytes, including contiguous unread bytes; never silently truncate accepted data.
- All receive failures leave that level unchanged and return a transport-error value: FRAME_ENCODING_ERROR (`0x07`), PROTOCOL_VIOLATION (`0x0a`) or CRYPTO_BUFFER_EXCEEDED (`0x0d`). The future connection must send the close.
- Design decision: inconsistent overlapping unread bytes produce PROTOCOL_VIOLATION; already consumed duplicates are ignored. No history of consumed bytes is retained.
- Discarding a level releases both directions permanently. Delayed receive data is ignored; outgoing data cannot be appended or framed afterwards. 0-RTT remains invalid.
- Outgoing bytes remain available for arbitrary refragmentation until level discard; append fails atomically at the configured limit. This is not an ACK/loss scheduler or an unlimited post-handshake sender.

## Review Focus

- A far-future offset must consume memory only for actual received bytes, with no allocation proportional to the offset.
- Duplicate and bridging overlaps must not inflate capacity, double-deliver bytes, or partially mutate on conflict/overflow.
- Binary handshake data containing NULs must survive reordering, fragmentation and packet authentication.
- Equal offsets at different levels must not mix data; discarding one must leave other levels intact.
- A corrupted Initial must not contribute any CRYPTO bytes or authenticated packet-number state.

### Task 1: Bounded CRYPTO streams and protected Initial integration

**Files:** Create `quic/crypto_streams.hh`, `quic/crypto_streams.cc`, `tests/quic_crypto_streams.cc`; modify the two CMakeLists and `etc/tests.cmake`, update `docs/quic-v1/`.

**Interfaces:**
- Consumes: `CryptoFrame { uint64_t offset; std::string data; }`, `PacketKind`, existing frame codec and Initial protection APIs.
- Produces: `CryptoStreams(size_t receive_capacity=65536, size_t send_capacity=65536)`; `receive(PacketKind, const CryptoFrame&) -> optional<CryptoReceiveError>`; `take_contiguous(PacketKind) -> string`; `bytes_buffered(PacketKind) -> size_t`; `read_offset(PacketKind) -> uint64_t`; `append(PacketKind, string_view) -> bool`; `frame(PacketKind, uint64_t offset, size_t max_data) -> optional<CryptoFrame>`; `discard(PacketKind) -> void`.

- [x] Write failing tests: `{3,"def"}` then `{0,"abc"}` yields `"abcdef"` exactly once; three levels at offset zero yield their own data; consistent overlaps merge, conflicting overlap returns `0x0a` atomically. Buffer exactly 4096 unique bytes, accept duplicates, reject byte 4097 with `0x0d`, drain and reuse. Far offset `max_varint-1` plus one byte is allowed, plus two is `0x07`. Sparse fragments, zero-length frames, binary bytes, old/partial duplicates, invalid 0-RTT, discard and send-capacity behavior are covered.
- [x] Register test and run `cmake -S . -B build && cmake --build build --target quic_crypto_streams_sanitized -j2`; expect failure for missing `quic/crypto_streams.hh`.
- [x] Implement the interfaces above; merge touching intervals only after overlap validation and unique-byte accounting. Avoid offset-proportional loops/allocations.
- [x] Run `ctest --test-dir build -R '^quic_' --output-on-failure -j2`; expect all QUIC tests and compile fixture passing.
- [x] Extend the test with sender fragmentation -> frame codec -> authenticated Initial -> reverse delivery/duplicate and missing-fragment resend under a new packet number -> exact binary receiver output. Corrupt a tag and prove it cannot advance receive or packet state.
- [x] Run full `ctest --test-dir build --output-on-failure -j2`, preserving its log and reporting all pre-existing unavailable tests. Run formatting and diff checks.
- [x] Update coverage and learning docs, obtain a fresh review, address material findings, commit the tested changes on the existing branch.

Verification outcome: QUIC 14/14 pass including compile fixture after the review fix. Full suite: 49/52 pass; existing net_interface/router executables unavailable; wrapping_integers_roundtrip manually stopped after 494.64 seconds. Full log: build/quic-crypto-full-ctest.log. Independent review approved the milestone after the discard-allocation fix; no complete TLS or connection claim.
