# QUIC Path Validation State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a testable RFC 9000 §8.2 path-validation state component for a single candidate network path.

**Architecture:** The future connection layer owns one validator per path and supplies unpredictable eight-byte challenges only after a datagram is sent. The validator records outstanding challenges, distinguishes address validation from 1200-byte datagram validation, and expires an attempt on a caller-provided timer. It does not choose UDP paths or emit datagrams.

**Tech Stack:** C++20, existing QUIC frame structs, CMake/CTest with ASan/UBSan.

**Spec:** `docs/quic-v1/requirements.md` and `docs/quic-v1/tasks.md` task 9; RFC 9000 §8.2.

## Global Constraints

- Keep the component independent of TLS and UDP while those layers are absent.
- A matching PATH_RESPONSE on any incoming path validates the challenged path.
- A response to a challenge sent below 1200 bytes validates the peer address but requires another padded challenge for MTU validation.

## Review Focus

- An unrelated response must not validate a path: test unknown token.
- An expired response must not validate a path: test exact deadline.
- A padded MTU follow-up sent near the first deadline must receive a fresh timer: test late small-probe response.
- A padded probe may precede the small probe's response: test concurrent probes and the MTU timer.
- An ACK for a challenge must not validate a path: no ACK-driven validation interface.
- Reused challenge data must not create ambiguous matches: reject duplicate token.
- A small challenge must not mark the path fully validated: test address-only state.

---

### Task 1: Single-path validation state

**Files:** Create `quic/path_validation.hh/.cc`, `tests/quic_path_validation.cc`; modify `quic/CMakeLists.txt`, `tests/CMakeLists.txt`, `etc/tests.cmake`.

**Interfaces:** `PathValidation::start`, `record_sent_challenge`, `on_response`, `expire`, and `state`; tokens use `std::array<uint8_t,8>`, datagram size and timestamps are supplied by the connection layer.

- [x] Write tests for matching, mismatching, out-of-order and repeated responses, sub-1200 probes, duplicate challenges and exact deadline.
- [x] Compile the test and observe failure from the missing feature.
- [x] Implement the smallest state machine with explicit Idle, Validating, AddressValidated, Validated and Failed states.
- [x] Build with sanitizers, run QUIC tests and full available suite; check the final diff.
- [x] Document RFC rules and code mapping in `docs/quic-v1/implementation.md` and coverage matrix.
- [x] Commit the verified change.
