# QUIC acknowledgments implementation plan

Continue the approved QUIC v1 design in the existing isolated worktree, starting at e6d4028. Execute inline using executing-plans and TDD. As in preceding milestones, use build/quic-ack-progress.md as a manual ignored ledger. No merge or push.

Scope: immediate ACK scheduling in all three spaces, bounded receive ranges and outstanding ack-eliciting send history, authenticated duplicate re-ACK, validation of ACKs against actual handoffs, and observable outstanding counts. RTT sampling, loss detection, retransmission, congestion control and ACK ECN validation remain separate milestones. ECN counters are parsed but not used for congestion control.

Interfaces: PacketAcknowledgments tracks contiguous handed-off packet numbers per space, stores at most 4096 outstanding ack-eliciting packets per space, retains a 4096-number receive window and emits at most 32 newest ACK ranges. Full send history applies backpressure to ack-eliciting sends; ACK-only output remains possible. Sending is contiguous because preparation is retained until handoff, or discarded only when its packet number space is retired. ACK application is idempotent. ACK delay is elapsed monotonic microseconds shifted by the advertised exponent; Initial and Handshake delay is zero. A prepared ACK clears pending state only if its receive generation still matches.

- [x] Task 1: Add deterministic PacketAcknowledgments unit tests, observe missing API RED, implement and run GREEN. Cover gaps/duplicates, independent spaces, ACK-only input, delay, history capacity, repeated ACK and unsent ACK rejection.
- [x] Task 2: Add connection integration regression, observe RED, connect authenticated receive and handoff paths, verify all existing connection tests. ACK-only input must not create an ACK loop; retired spaces release all ACK state. Expose packets_awaiting_ack(kind).
- [x] Task 3: Document behavior and limits, format, run QUIC and full CTest (30-second timeout), obtain one fresh read-only review of the whole milestone, fix Important findings with RED/GREEN regressions, and commit locally.

Expected commands: cmake --build build --target quic_acknowledgments_sanitized quic_handshake_connection_sanitized -j2; ctest --test-dir build -R quic_ --output-on-failure --timeout 30 -j2; ctest --test-dir build --output-on-failure --timeout 30 -j2. The first compile must fail for the new missing header, integration must fail for absent outstanding-count API, then QUIC must pass. Full CTest retains seven documented unrelated baseline failures.

Review Focus: prepared-but-amplification-blocked output versus sent history; ACK reception in coalesced and reordered TLS flights; bounded memory under sparse packet numbers or withheld ACKs; stale prepared ACK snapshots; authenticated duplicates versus old retired receive records; malformed/multi-ACK atomic preflight; packet-space retirement and ACK-only loops; payload size with 32 ranges and 600-byte CRYPTO; zero-delay and clock assumptions. No claim of loss recovery or RTT integration.


Verification: QUIC CTest 20/20 passed (14.94 seconds); full CTest 51/58 passed (111.13 seconds). Baseline failures unchanged: wrapping_integers_roundtrip, wrapping_integers_extra, recv_transmit, recv_reorder_more, send_transmit timed out; net_interface and router had no executable. Fresh read-only review found no Critical/Important/Minor findings, independently ran both new/revised sanitized binaries, and passed diff whitespace checks.

Final ruling: recovery under loss or permanent withheld ACKs, RTT/PTO and ECN congestion processing remain future work, as the approved incremental scope states. Cost: key packet loss can stall the handshake and full outstanding history pauses further ack-eliciting traffic. The implementation is not advertised as a reliable complete transport.
