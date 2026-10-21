# QUIC Peer Connection ID Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track peer-issued connection IDs for path changes, including NEW_CONNECTION_ID retirement requests, local path retirement, and resource limits.

**Architecture:** One connection-level pool owns the peer's sequence-numbered IDs and their reset tokens. The connection layer supplies a stable key for each local/remote address pair; selecting an ID binds it to that path and never reuses it on another. The pool queues RETIRE_CONNECTION_ID work until its acknowledgement is reported.

**Tech Stack:** C++20, existing `NewConnectionIdFrame`/`RetireConnectionIdFrame`, CMake/CTest with sanitizers.

**Spec:** `docs/quic-v1/requirements.md`, `docs/quic-v1/tasks.md` task 9, RFC 9000 §§5.1, 9.5, 19.15–19.16.

## Global Constraints

- Initial peer source CID has sequence 0; preferred address CID has sequence 1 when present.
- `Retire Prior To` is monotonic; retired IDs are not selected again and remain queued until retirement is acknowledged.
- After applying a frame's retirement threshold, active IDs cannot exceed the locally advertised limit.
- Zero-length peer CIDs forbid NEW_CONNECTION_ID frames.

## Review Focus

- Reordered NEW_CONNECTION_ID below a prior retirement threshold must be retired immediately.
- Duplicate sequence with changed CID/token, or duplicate CID at another sequence, must not enter the pool.
- A new ID replacing retired IDs must be allowed despite a temporary pre-retirement count above the limit.
- A path change must not reuse an ID already bound to another address pair.
- An invalid frame must not partially retire working IDs.
- Repeated old frames must not requeue already acknowledged retirements.
- History and pending retirement state must have finite per-connection limits.

---

### Task 1: Peer-issued ID pool

**Files:** Create `quic/peer_connection_ids.hh/.cc`, `tests/quic_peer_connection_ids.cc`; modify `quic/CMakeLists.txt`, `tests/CMakeLists.txt`, `etc/tests.cmake`, `docs/quic-v1/`.

**Interfaces:** `PeerConnectionIds::on_new_id(NewConnectionIdFrame)`, `select_for_path(string_view)`, `retire_path(string_view)`, `pending_retirements()`, `acknowledge_retirement(uint64_t)`, `add_preferred_address`.

- [x] Write tests for path binding, duplicates, retire-prior-to, active limit, zero-length CID and preferred address.
- [x] Run the test and confirm failure from missing functionality.
- [x] Implement the pool with atomic frame validation before applying updates.
- [x] Build with sanitizers and run QUIC tests plus available full suite.
- [x] Add beginner-level RFC/code explanation and coverage updates.
- [x] Review and commit the change.
