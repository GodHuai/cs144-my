# QUIC NewReno Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline. Steps use checkbox syntax for tracking.

**Goal:** Enforce byte-based congestion limits in the existing single-path handshake engine.
**Architecture:** NewReno owns path cwnd/flight arithmetic; PacketRecovery owns bounded physical packet metadata separately from logical frame delivery; connection packet selection checks exact wire bytes before consuming packet numbers.
**Tech Stack:** C++20, Linux, existing OpenSSL 3.5.9, CMake/CTest with sanitizers.
**Spec:** `docs/superpowers/specs/2026-10-22-quic-congestion-design.md`

## Global Constraints

- Existing isolated worktree `/home/huai/minnow-quic-proposal`, branch `quic-v1-proposal`.
- Fixed max_datagram_size 1200; initial cwnd 12000, minimum 2400; metadata 4096 per space.
- No dependency changes, streams, persistent congestion, pacing, ECN or external interop claim.

## Review Focus

- Redundant retransmission physically remains in flight until its own ACK/loss/discard.
- Padding-only ACK packets count in flight but must not create ACK loops or PTO storms.
- Congestion blocking does not consume packet numbers or hide an ACK/PTO.
- Same-time recovery events, duplicate ACKs and cross-space discard do not double debit or cut.
- Sparse/application-limited traffic does not inflate cwnd; integer arithmetic retains small ACK credit.

### Task 1: NewReno arithmetic

**Files:** create `quic/congestion_control.hh/.cc`, `tests/quic_congestion_control.cc`; modify both CMake lists and `etc/tests.cmake`.
**Interfaces:** `CongestionStats{window,bytes_in_flight,slow_start_threshold}`; `NewReno::can_send(bytes,probe)`, `sent(bytes)`, `acknowledged(bytes,sent_at,limited)`, `lost(bytes,sent_at,now)`, `discard(bytes)`, `stats()`.

- [x] Write failing tests for initial/minimum window, exact boundary, probe exception, slow-start growth, limited-traffic suppression, recovery one-cut and avoidance credit.
- [x] Build/run test, observe missing interface failure.
- [x] Implement arithmetic with checked flight accounting and saturating cwnd growth; optional recovery timestamp accepts timestamp zero.
- [x] Run sanitizer target and record result.

### Task 2: Physical packet flight integration

**Files:** modify `quic/packet_recovery.hh/.cc`, `tests/quic_packet_recovery.cc`.
**Interfaces:** extend `sent(...,data,size=0,padded=false)`, expose `can_send(kind,size,eliciting,padded,probe)`, `congestion_stats()`, non-consuming `pending(kind)`; physical metadata includes time, wire size and eliciting flag.

- [x] Add failing tests: padded Initial ACK vs pure ACK, retransmission delivery vs physical flight, late ACK after loss, space discard, loss/PTO distinction and bounds.
- [x] Observe red; add physical map and controller callbacks. ACK batches share pre-ACK window-limited state; process congestion loss before ACK growth.
- [x] Loss deadlines include physical flights; PTO selects spaces with ack-eliciting physical packets. Shared frame delivery cancellation remains unchanged.
- [x] Run recovery and controller sanitizer tests.

### Task 3: Connection scheduling and documentation

**Files:** modify `quic/handshake_connection.hh/.cc`, `tests/quic_handshake_connection.cc`, `docs/quic-v1/*` relevant pages.
**Interfaces:** `HandshakeConnection::congestion_stats() const`; `PacketRecovery::pending(kind)` (non-consuming) for wire sizing and PTO priority.

- [x] Add failing connection test: fill window with PING, next poll blocked without PN gaps; peer PING still yields ACK; PTO bypass works, actual ACK reopens sending.
- [x] Observe red; use non-consuming frame selection and exact wire sizing before PN allocation, allowing ACK-only fallback. Preserve Prepared anti-amplification semantics.
- [x] Run QUIC CTest and full CTest with 30-second timeout, record every failure.
- [x] Update progress docs with scope/evidence, review complete diff, fix findings with regressions and commit only intended files.

## Execution record

- Task 1 complete: missing-header RED; sanitizer NewReno arithmetic GREEN.
- Task 2 complete: missing extended send/stat API RED; physical flight, late ACK, discard, redundant loss and capacity checks GREEN.
- Task 3 complete: missing connection stats API RED; congestion scheduling, ACK/PTO exception and real large-handshake ACK flow GREEN.
- Ruling: compute application/window limitation once from pre-ACK batch physical utilization rather than a per-send marker; matches current-utilization scope in RFC 9002 7.8 and avoids falsely treating early packets in a full flight as limited.
- Ruling: remove Prepared ciphertext entirely; peek TLS/recovery and size before allocating PN or consuming work. This avoids packet-number holes and stale prepared work blocking ACK/PTO.
- Existing amplification_pause fixture withheld every ACK for its 15KB flight. Diagnostic flight=11949/cwnd=12000 identified expected congestion blocking. Deliver real client ACKs during credit rounds; unchanged first-stage anti-amplification assertions still pass.
- QUIC CTest 22/22; full suite 53/60. Existing five timeouts and two unavailable network/router binaries recorded in congestion-control.md. Final added boundary assertions pass in both focused sanitizer executables.
- Fresh independent review: no actionable findings. Proposed ssthresh clamp withdrawn after comparison with normative RFC half-before-minimum formula; assertion now preserves that formula.
- Changes remain on quic-v1-proposal; no merge or push.
