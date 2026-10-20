# QUIC Basic Frames Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse and encode RFC 9000 PADDING, PING, ACK/ACK_ECN, CRYPTO and STREAM frames.

**Architecture:** Add one frame model and codec under `quic/`; decode a complete authenticated payload transactionally. Keep packet type, stream state and packet number space validation outside the codec.

**Tech Stack:** C++20, existing QUIC varint library, CMake/CTest sanitizers.

**Spec:** `docs/superpowers/specs/2026-10-19-quic-basic-frames-design.md`

## Global Constraints

- All wire integer fields are QUIC varints; frame types use shortest encoding.
- Stream and CRYPTO offset plus data length must not exceed `2^62-1`.
- ACK ranges are descending, non-overlapping inclusive packet-number intervals; computed negatives are invalid.
- Decoder rejects whole payload on malformed or unsupported frame.

## Review Focus

- Empty payload or truncated varint/data field must not yield partial output.
- STREAM without LEN consumes the remaining payload.
- ACK range subtraction must not underflow.
- Huge ACK Range Count must not trigger unbounded allocation or loops.
- Empty FIN stream frame is valid; offset overflow is not.

---

### Task 1: PADDING, PING, CRYPTO and STREAM

**Files:** `quic/frame.hh`, `quic/frame.cc`, `tests/quic_frames.cc`, `quic/CMakeLists.txt`, `tests/CMakeLists.txt`, `etc/tests.cmake`.

**Interfaces:** `using Frame = std::variant<PaddingFrame, PingFrame, CryptoFrame, StreamFrame, AckFrame>`; `decode_frames(std::string_view) -> std::optional<std::vector<Frame>>`; `encode_frame(const Frame&) -> std::string`.

- [x] Write wire-vector and malformed-input tests for the four frame families.
- [x] Build and observe RED with missing codec.
- [x] Implement minimal decoder and encoder for the four frame families.
- [x] Build and verify GREEN.

### Task 2: ACK and ACK_ECN ranges

**Files:** `quic/frame.hh`, `quic/frame.cc`, `tests/quic_frames.cc`.

- [x] Add ACK and ACK_ECN vectors, descending ranges, underflow, truncation and large-count tests.
- [x] Observe RED in the focused test.
- [x] Implement range validation, ECN fields and encoding.
- [x] Verify focused tests and inspect whole-suite result.

### Finish

- [x] Update `docs/quic-v1/coverage.md` and `implementation.md` with exact scope and limits.
- [x] Run formatting, focused tests and diff check; commit milestone.
