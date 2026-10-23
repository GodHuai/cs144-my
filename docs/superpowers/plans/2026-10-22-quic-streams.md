# QUIC Application Streams Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline and test-driven-development. Continue existing isolated worktree; native implementation, independent final review.

**Goal:** Reliable bounded application streams with negotiated flow control in the existing connection.
**Architecture:** ApplicationStreams owns flow/state/buffers and peek/commit scheduling; connection integrates authenticated transactional receive and recovery delivery callbacks.
**Tech Stack:** Existing C++20/OpenSSL/CMake/CTest sanitizers.
**Spec:** docs/superpowers/specs/2026-10-22-quic-streams-design.md

## Global Constraints

- Worktree /home/huai/minnow-quic-proposal, branch quic-v1-proposal, base dd15e0d.
- Receive and send memory windows 1 MiB, stream counts <=128 per direction per initiator; default negotiated credit zero.
- Fresh STREAM payload <=600 bytes; all existing send gates precede handoff/PN allocation.
- No stream-count replenishment, 0-RTT, migration or crypto-buffer changes.

## Review Focus

- Holes and RESET final sizes consume credit; duplicate data and retransmission cannot consume it twice.
- FIN gaps, late data, and reset/stop do not change final size or falsely deliver EOF.
- Illegal direction and unopened local IDs fail without acknowledging dropped application bytes.
- ACK of any copy releases only delivered bytes once, preserves unacknowledged ranges and bounded buffering.
- New stream/control candidates survive congestion/pacing blockage and lost MAX updates recover.

### Task 1: Independent stream/flow engine

Files: quic/application_streams.hh/.cc, tests/quic_application_streams.cc, quic/CMakeLists.txt, tests/CMakeLists.txt, etc/tests.cmake.
Interfaces: StreamRead{data,eof,reset_error}; ApplicationStreams(bool server,local,peer), open(bool)->optional<uint64_t>, write(id,data,fin)->bool, read(id,max)->StreamRead, ids(), reset(id,error), stop(id,error), pending()->optional<Frame>, sent(Frame), acknowledged(Frame), receive(vector<Frame>)->optional<uint64_t>, buffered().
- [x] Write unit tests covering design's receive/send/control/limit boundaries; observe missing interface RED.
- [x] Implement engine; run sanitized test GREEN. Any newly discovered edge gets its own RED/GREEN cycle.

### Task 2: Protected connection integration

Files: quic/handshake_connection.hh/.cc, quic/packet_recovery.hh/.cc, tests/quic_handshake_connection.cc.
Interfaces: HandshakeConnection open_stream/write_stream/read_stream/stream_ids/reset_stream/stop_sending/stream_send_buffered; PacketRecovery::acknowledged optional logical-delivery callback.
- [x] Write TLS-connected data/loss/window/cancellation regression, run behavioral RED.
- [x] Integrate application creation on TLS completion, atomic preflight, optional delivery callback, non-consuming candidate and handoff commit. Preserve ACK fallback and all existing gates.
- [x] Run direct sanitized tests and QUIC CTest.

### Task 3: Review and ship milestone

- [x] Independent final review; regressions for actionable findings.
- [x] Full CTest --timeout 30 -j2, format/diff/link checks; report failures by name.
- [x] Update docs/quic-v1 and local QUIC notes with scope, examples, tests and remaining limits.
- [x] Commit intended files on existing branch; no push/merge; verify clean VM status.

## Execution evidence and review

Observed missing ApplicationStreams header RED, then unit GREEN; protected connection API missing RED, then 9 KB loss/reorder plus tiny-window integration GREEN. Regression FIN ACK with unacknowledged prefix failed before correcting terminal send-state check. Review resource regression failed on reset incorrectly releasing inflight admission; fixed to preserve committed charges until ACK. Asymmetric credit mappings, lifetime count, aggregate admission/ACK reopen and explicit exactly-once recovery callback tests passed. Independent recheck reports no remaining blocker. Final suite results and commit recorded in docs/quic-v1/application-streams.md. Local notes synchronized with this milestone; no push/merge.
