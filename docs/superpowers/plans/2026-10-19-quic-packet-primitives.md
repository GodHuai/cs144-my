# QUIC packet primitives implementation plan

**Execution record:** Tasks 1–3 were implemented and their focused sanitizer tests pass. Full CTest was run with a 12-second per-test limit: 34/41 passed, five existing tests timed out and two unrelated executables were absent. See `docs/quic-v1/implementation.md` for the exact limits.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add independently tested RFC 9000 packet number, RFC 9001 header mask, and RFC 9002 RTT/PTO primitives to the existing QUIC library.

**Architecture:** Keep wire encoding, header masking, and path timing in separate small modules under `quic/`. None of these modules claims to implement a QUIC connection; packet protection, TLS, loss tracking, and UDP integration follow later.

**Tech Stack:** C++20, existing CMake/CTest, standard library. Header mask input is supplied by a future TLS/crypto integration; this milestone does not implement cryptography.

**Spec:** RFC 9000 §§12.3, 17.1, A.2–A.3; RFC 9001 §5.4; RFC 9002 §§5.1–5.3, 6.2.1–6.2.2.

## Global Constraints

- Packet numbers are in `[0, 2^62-1]` and their wire field is 1–4 bytes.
- No packet number reuse within a number space; connection state must enforce this later.
- Header masking must preserve all unmasked header bits and must not mutate malformed buffers.
- An RTT sample requires an ACK that newly acknowledges its Largest Acknowledged packet and at least one ack-eliciting packet. The sample uses the Largest Acknowledged packet's send time; the future ACK processor owns this gate.
- Existing TCP code and tests remain unchanged.

## Review Focus

- Empty and truncated headers: reject before mutation.
- Packet number wrap boundary: decode nearest to expected without exceeding 62 bits.
- Large ACK delays: cap only after handshake confirmation and never reduce below min RTT.
- No ACK yet: use an encoding that safely carries the initial full packet number.
- First RTT sample: reset the initial 333 ms estimate.

---

### Task 1: RFC 9000 packet number codec

**Files:** `quic/packet_number.hh/.cc`, `tests/quic_packet_primitives.cc`, `quic/CMakeLists.txt`, `tests/CMakeLists.txt`, `etc/tests.cmake`.

**Interfaces:** `choose_packet_number_length`, `encode_packet_number`, `decode_packet_number` in namespace `quic`.

- [x] Write RFC example, boundary, invalid length, and 62-bit limit tests.
- [x] Build and observe RED for the missing codec.
- [x] Implement shortest safe encoding selection and nearest expected decoding.
- [x] Build and run new test until GREEN.

### Task 2: RFC 9001 header mask application

**Files:** `quic/header_protection.hh/.cc`, `tests/quic_packet_primitives.cc`, CMake files above.

**Interfaces:** `header_protection_sample`, `apply_header_mask`, `remove_header_mask`.

- [x] Add RFC 9001 Appendix A.2 protected Initial header and short-header roundtrip tests.
- [x] Verify RED.
- [x] Implement mask application/removal and 16-byte sample bounds checks.
- [x] Verify GREEN.

### Task 3: RFC 9002 RTT estimator

**Files:** `quic/rtt_estimator.hh/.cc`, `tests/quic_packet_primitives.cc`, CMake files above.

**Interfaces:** `RttEstimator::observe`, `reset`, `pto_ms`, and read-only estimate accessors.

- [x] Add first sample, ACK-delay, PTO, reset and invalid input tests.
- [x] Verify RED.
- [x] Implement RFC formulas with path-local state.
- [x] Run focused and existing tests, then document coverage and remaining integration.

### Finish

- [x] Update `docs/quic-v1/coverage.md` and `implementation.md` with exact partial scope and evidence.
- [x] Run CTest and inspect Git diff, then commit this milestone on `quic-v1-proposal`.
