# QUIC Pacing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline; use TDD for code changes.

**Goal:** Pace fixed-path QUIC output while preserving immediate ACK/PTO behavior.
**Architecture:** Independent byte token bucket; connection owns candidate wakeup merged with recovery deadline. Pure ACK/probe bypass occurs in scheduling, exact wire bytes debit at handoff.
**Tech Stack:** Existing C++20/Linux/OpenSSL 3.5.9, CMake/CTest sanitizers.
**Spec:** `docs/superpowers/specs/2026-10-22-quic-pacing-design.md`

## Global Constraints

- Existing isolated VM worktree /home/huai/minnow-quic-proposal; base 9214181.
- Bucket cap min(cwnd,12000); rate multiplier 1.25; minimum pacing RTT 1000us.
- Pure ACK bypass; padded ACK paced; PTO bypasses but consumes available credit.
- No changes to recovery/CC arithmetic and no internal sleeps or threads.

## Review Focus

- Blocked polls never consume packet number, TLS or recovery work.
- Cached pacing wakeup cannot survive cancellation/terminal state or suppress PTO.
- ACK-only fallback cannot be delayed behind a paced frame.
- Idle and window/rate changes cannot create unbounded credit or retroactive refill.
- Time zero, tiny fractions and saturation cannot create early/busy timers.

### Task 1: PacketPacer

**Files:** create quic/pacer.hh/.cc, tests/quic_pacer.cc; extend quic/tests CMakeLists and etc/tests.cmake.
**Interfaces:** deadline(uint64_t now,uint64_t bytes,uint64_t window,double rtt_us), sent(same), optional<uint64_t> deadline return.

- [x] Write tests asserting 12000-byte initial burst, 1200 bytes need 26640us at cwnd12000/RTT333000; rate change applies only prospectively; idle cap and shrink; zero/reverse time and overflow.
- [x] Observe missing interface RED, implement bucket, run sanitized test GREEN.

### Task 2: Connection integration

**Files:** quic/handshake_connection.cc, tests/quic_handshake_connection.cc.
**Interfaces:** unchanged public API; cached optional pacing wakeup merged by next_timeout_us().

- [x] New connection test fills bucket, observes blocked PING and absolute wakeup, sends peer PING to verify immediate ACK, advances injected clock to wakeup, checks output/PN continuity and idle cleanup; PTO bypass included.
- [x] Observe behavioral RED, implement non-consuming pacing gate, ACK fallback and timer merge.
- [x] Update large-handshake and full-window drivers to advance explicit clocks; verify they exercise actual pacing and unchanged amplification/cwnd assertions.
- [x] Run QUIC and full suite with 30-second test timeout; fresh independent review, resolve findings via regressions, update project/local notes and commit in branch only.

## Execution evidence

Missing pacer interface and connection pacing behavior observed RED, then GREEN. Review regression for capacity growth observed RED before storing the previous capacity; final independent read-only review has no actionable findings. QUIC CTest 23/23 passed. Full suite and final documentation/commit verification recorded in docs/quic-v1/pacing.md. Existing congestion-fill driver passed unchanged; large-handshake driver now advances its injected clock on pacing deadlines.
