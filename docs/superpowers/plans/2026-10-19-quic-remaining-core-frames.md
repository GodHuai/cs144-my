# QUIC Remaining Core Frames Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete RFC 9000 core frame wire parsing and encoding through type `0x1e`.

**Architecture:** Extend the existing `Frame` variant and transactional payload codec. Validate local wire invariants at decode and encode; leave role, packet-type, CID inventory, path, and closing state to the connection layer.

**Tech Stack:** C++20, existing varint codec, CMake/CTest sanitizers.

**Spec:** `docs/quic-v1/design.md`; RFC 9000 §§19.7, 19.15–19.20.

## Global Constraints

- NEW_TOKEN token length is nonzero and bounded by the packet payload.
- NEW_CONNECTION_ID has `1 <= CID length <= 20`, exactly 16 token bytes, and `retire_prior_to <= sequence`.
- PATH_CHALLENGE and PATH_RESPONSE each carry exactly eight opaque bytes.
- CONNECTION_CLOSE type `0x1c` includes triggering frame type; type `0x1d` omits it. Reason length is in bytes.
- Decode rejects the complete payload on malformed/truncated input.

## Review Focus

- Truncated fields or fixed blobs cannot consume a following frame.
- Zero and 21 byte connection IDs are rejected.
- A NEW_CONNECTION_ID with retire_prior_to above sequence is rejected.
- Empty NEW_TOKEN is rejected while empty close reason is accepted.
- Both close variants retain their distinct field layout and do not misplace the next frame.

---

### Task 1: NEW_TOKEN, PATH_* and HANDSHAKE_DONE

**Files:** Modify `quic/frame.hh`, `quic/frame.cc`, `tests/quic_frames.cc`.

**Interfaces:** Add `NewTokenFrame {std::string token}`, `PathChallengeFrame {std::array<uint8_t, 8> data}`, `PathResponseFrame {std::array<uint8_t, 8> data}`, and `HandshakeDoneFrame {}`.

- [x] Write independent wire vectors and malformed tests; observe RED.
- [x] Implement minimal encoder/decoder; observe GREEN.

### Task 2: Connection ID management frames

**Files:** Modify the same codec and test files.

**Interfaces:** Add `NewConnectionIdFrame {sequence, retire_prior_to, std::string cid, std::array<uint8_t,16> reset_token}` and `RetireConnectionIdFrame {sequence}`.

- [x] Write manual vectors plus CID length, token truncation, and retire ordering tests; observe RED.
- [x] Implement minimal encoder/decoder; observe GREEN.

### Task 3: CONNECTION_CLOSE variants

**Files:** Modify the same codec and test files.

**Interfaces:** Add `ConnectionCloseFrame {bool application, uint64_t error_code, std::optional<uint64_t> frame_type, std::string reason}`. Transport close requires frame_type; application close forbids it.

- [x] Write both wire vectors, adjacent-frame, zero and truncated reason tests; observe RED.
- [x] Implement minimal encoder/decoder; observe GREEN.

### Finish

- [x] Update coverage and beginner implementation notes to distinguish complete *core frame wire formats* from incomplete connection behavior.
- [x] Format, run QUIC and full CTest, diff-check, independent review, commit.
