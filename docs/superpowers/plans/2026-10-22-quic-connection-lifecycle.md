# QUIC connection lifecycle implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for native execution, task-by-task.

**Goal:** bounded close/draining and negotiated silent idle expiry.
**Architecture:** extend connection state orchestration; cached close wire, one idle activity timestamp, fixed closure expiry, no recovery close retransmission.
**Tech Stack:** C++20, OpenSSL, sanitized CTest, injected microsecond clock.
**Spec:** ../specs/2026-10-22-quic-connection-lifecycle-design.md

## Global constraints
Existing pinned-peer isolated worktree /home/huai/minnow-quic-proposal. Default idle disabled. 256byte reason limit. Saturating timers. Existing Failed semantics retained. No push/merge.

## Review focus
Unauthenticated traffic must not reset idle. Closing without incoming keys must retain3xcap even after address validation. Amplification blocking must not suppress lifecycle expiry. Idle first-send reset only at real handoff. Milliseconds and3PTO arithmetic must not overflow.

## Task1: terminal/draining timer
- [x] Add tests/quic_connection_lifecycle.cc, sanitized executable/cert dependency in tests/CMakeLists.txt and ttest entry in etc/tests.cmake. Test authenticated Initial close =>Draining, close_info capture, fixed expiry =>Closed and resource disposal; run RED against current API/state (temporary API declarations may be required for later tests).
- [x] Implement Closing/Closed states, close_info(), terminal cleanup,3PTO duration and lifecycle deadline precedence in handshake_connection.hh/.cc; run GREEN.

## Task2: explicit close
- [x] Add close(error,reason) tests after real protected handshake; first close lost, incoming peer PING triggers same-wire bounded response, wrong route ignored, no autonomous retry, fixed expiry. Observe RED.
- [x] Implement cached 1-RTT close sealing before TLS cleanup, close response cap and rate limiter; run GREEN.

## Task3: idle expiry
- [x] Add local/peer minimum, sole nonzero, disabled defaults, first-send/receive refresh, forged traffic,3PTO floor and overflow tests; run RED.
- [x] Implement dynamic idle_deadline(), activity tracking at authentication/handoff, timers under amplification block, expiry enforcement on receive/poll; run GREEN.

## Task4: review/document/commit
- [x] Independent whole-change review; address findings via regression RED/GREEN.
- [x] QUIC and full CTest --timeout30 -j2, clang-format, diff/link checks. Record actual known failures; update implementation docs and local learning note. Commit branch only.

## Execution ledger

RED1: draining expiry absent (behavior). GREEN: peer Draining3PTO timer. RED2: local close rejected (false stub) then protected close/reply GREEN. RED3: idle below three PTO floor / prehandoff timer absent, then idle negotiation/activity/floor/saturation GREEN. Compile-only unused helper and range copy warnings corrected before behavioral RED. Added real buffered stream disposal and large15000byte server TP amplification block idle expiry, preinterval reject, timeout-only silence, doubled response interval. Independent design check adopted no duplicate idle refresh and close-at-expired guard. Whole-branch review no production defects; coverage additions applied. Independent3x exhaustion unreachable through current public API before rate bound; retained defensive check and documented validation limit. Ruling: existing Failed silent error semantics retained to keep automatic handshake error-close as next coherent task. Existing isolated worktree retained; user continuation authorizes native execution without another approval gate.

Final full CTest58/65 in159.82sec; QUIC27/27 including compile fixture. Lifecycle3.16sec. Existing five nonQUIC timeout failures and two missing binaries unchanged. Format/diff/link verification passes. Scope caveat: preconfirmation appclose only1RTT, multi-level fallback remains future work. No merge/push.
