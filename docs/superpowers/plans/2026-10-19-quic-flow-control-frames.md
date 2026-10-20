# QUIC Flow Control and Stream Stop Frames Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encode and decode RFC 9000 RESET_STREAM, STOP_SENDING, MAX_*, and *_BLOCKED frame wire formats.

**Architecture:** Extend the existing `Frame` variant and complete-payload codec. Keep stream ownership, flow-control state, and packet-type checks in the future connection layer. Reject malformed wire fields transactionally.

**Tech Stack:** C++20, existing QUIC varint codec, CMake/CTest sanitizers.

**Spec:** `docs/quic-v1/design.md`; RFC 9000 §§19.4–19.5, 19.9–19.14.

## Global Constraints

- Frame types remain single-byte shortest-form varints.
- Stream counts in MAX_STREAMS and STREAMS_BLOCKED cannot exceed `2^60`.
- Truncated fields reject the entire payload; the decoder never returns a prefix of frames.
- This milestone handles wire fields only, not flow-control state changes.

## Review Focus

- Zero and maximum valid stream counts remain accepted; `2^60+1` is rejected.
- A truncated final field rejects even if earlier frames were valid.
- Multiple adjacent control frames decode without stealing bytes from the next frame.
- Encoding 62-bit field overflow throws rather than truncates.
- Direction bit distinguishes bidirectional and unidirectional variants.

---

### Task 1: Stream stop frames

**Files:** Modify `quic/frame.hh`, `quic/frame.cc`, `tests/quic_frames.cc`.

**Interfaces:** Add `ResetStreamFrame {stream_id, error_code, final_size}` and `StopSendingFrame {stream_id, error_code}` to `Frame`.

- [x] Add manually derived wire-vector and truncated-field tests for types `0x04`, `0x05`.
- [x] Build and run the focused test; observe failure caused by missing behavior.
- [x] Implement decode and encode using QUIC varints.
- [x] Run focused tests and inspect output.

### Task 2: Credit and blocked frames

**Files:** Modify `quic/frame.hh`, `quic/frame.cc`, `tests/quic_frames.cc`.

**Interfaces:** Add `MaxDataFrame`, `MaxStreamDataFrame`, `MaxStreamsFrame`, `DataBlockedFrame`, `StreamDataBlockedFrame`, `StreamsBlockedFrame`. Directional frames carry `bool unidirectional`.

- [x] Add manual vectors for types `0x10`–`0x17`, zero/boundary counts, truncation, and encoder rejection.
- [x] Run focused test and observe RED.
- [x] Implement decode and encode, validating `2^60` for stream counts.
- [x] Run focused tests and inspect output.

### Finish

- [x] Update `docs/quic-v1/coverage.md` and `docs/quic-v1/implementation.md` with exact implemented scope and a beginner explanation.
- [x] Run formatting, QUIC tests, diff check, and independent review; commit the milestone.
