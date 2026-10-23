# QUIC Stream Retirement Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline and test-driven-development.

**Goal:** Reclaim closed streams and reliably replenish cumulative stream credit.
**Architecture:** Track both terminal halves, compact retired ordinal intervals and independent cumulative/active counters; cancel old STREAM logical recovery only after RESET delivery.
**Tech Stack:** Existing C++20/OpenSSL/CMake sanitizer tests.
**Spec:** docs/superpowers/specs/2026-10-22-quic-stream-retirement-design.md

## Global Constraints

- Existing isolated worktree /home/huai/minnow-quic-proposal, branch quic-v1-proposal, base35b76c5.
- 128 simultaneously occupying slots per direction per initiator; cumulative max2^60, IDs never reused.
- Application must observe receive termination before reclaim; all send gates and physical flight accounting unchanged.

## Review Focus

- FIN tail ACK cannot hide missing prefix; unread data/reset cannot be reclaimed.
- Bidi requires both halves; uni only one; implicit holes cannot disappear.
- Duplicate close/late frames cannot replenish twice or resurrect heavy state.
- RESET ACK suppresses logical stale copies but leaves physical flight until ACK/loss.
- MAX_STREAMS loss, older updates and high counters cannot deadlock or wrap IDs.

### Task1: Stream state retirement and replenishment

Files: quic/application_streams.hh/.cc, tests/quic_application_streams.cc.
Interfaces: existing API; add private retire_ready(id), retired(id) and four merged ordinal maps/retired counts; Stream adds reset_acked/receive_observed.
- [x] Write behavioral tests for uni/bidi terminal conditions, active-count reopening, late/implicit frames and >128 sequential streams; run existing target RED.
- [x] Implement retirement with merged ranges and reliable coalesced MAX_STREAMS; run GREEN.

### Task2: Reset delivery cleanup and protected connection

Files: quic/packet_recovery.cc, tests/quic_packet_recovery.cc, tests/quic_stream_connection.cc.
- [x] Add RESET ACK cancellation/physical-flight test and protected1-credit sequential stream/lost-update regression; observe RED.
- [x] Implement post-ACK cancellation of old logical STREAM records; prove no obsolete retransmission/callback while physical flight remains.
- [x] Run new and existing QUIC tests.

### Task3: Verify and document

- [x] Independent review, regression/fix findings.
- [x] Full CTest --timeout30 -j2, format/whitespace/link checks, actual failure report.
- [x] Update project and local notes, branch commit, confirm clean VM status; no push/merge.

## Execution evidence

Behavior RED observed: "send-only terminal state retained"; stream retirement/replenishment GREEN. RESET recovery RED "RESET delivery left obsolete STREAM probe"; post-ACK cancellation GREEN. Independent review replay overflow RED "retired STREAM bypassed offset validation"; validation moved before shortcut then GREEN. Large peer credit accepted, implicit holes and receive-observation monotonicity covered. Combined connection test timed out at30sec; isolated140-round case measured33.07sec initially,26.33sec after emptyFIN/periodicpayload. Final129-round case runs independently via quic_stream_retirement CTest argv mode; existing data tests remain unchanged in the default mode. This still crosses the old128-stream limit; explicit TIMEOUT 30 overrides the normal test target’s global12sec default, retaining the chosen30sec cap. A focused run with --timeout12 verifies that property. Final suite outcome in docs/quic-v1/stream-retirement.md. Boundary near2^60 reviewed arithmetically; no fabricated near-end state injection.
