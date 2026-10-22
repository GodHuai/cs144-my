# QUIC handshake loss recovery implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline with TDD; one fresh final reviewer. Existing approved QUIC design and continuation authorize execution, without another design approval loop.

**Goal:** Recover bounded packet loss in the reusable handshake connection and connect ACKs to RTT estimation.
**Architecture:** A separate PacketRecovery owns bounded transmission metadata, shared delivery identities, loss queues and one connection-wide PTO backoff. PacketAcknowledgments retains wire ACK validity and reception state. Retransmit frames with new packet numbers, never old ciphertext or ACK frames. The sans-I/O connection exposes a deadline and explicit timeout callback, with an injectable monotonic microsecond clock.
**Tech Stack:** Existing C++20, OpenSSL 3.5.9, Linux UDP, sanitizer CTest.
**Spec:** docs/quic-v1/tasks.md items 3 and 6; RFC 9002 sections 5,6 and RFC 9000 section13.3. This is an incremental recovery foundation, not complete RFC9002 congestion control.

## Global constraints

- Worktree /home/huai/minnow-quic-proposal, branch quic-v1-proposal, BASE7abe14f. No merge/push. Preserve existing test failures separately.
- Continue the preceding milestones' manual ignored ledger in build/quic-recovery-progress.md.
- No STREAM implementation, congestion window, bytes-in-flight, pacing, persistent congestion, ECN validation, Retry/0-RTT/migration or external interoperability claim.
- Keep per-space active transmission metadata <=4096 and recent inactive metadata <=4096; sparse ACK work bounded by metadata, never by packet-number magnitude. Logical frame delivery cancels redundant queued copies. Full active history pauses new sends, as the existing connection contract does.

## Review Focus

1. ACK largest/newly-acked eligibility, ACK-only largest sample, delay exponent and units, same-tick samples, late ACK after retransmission.
2. Loss/PTO separation, per-space loss thresholds, global exponential backoff, saturation and no Application PTO before confirmation.
3. Dropped Initial/Handshake/Finished/HANDSHAKE_DONE, loss of ACKs, reordered originals and late ACK cancellation; new packet numbers and no duplicated TLS cursors.
4. Prepared output under amplification blocking, clock consistency and retired keys, queued probes after delivery; timeout callbacks without handoff cannot flood.
5. Bounded history/queues, malicious sparse ACKs, stale copies and duplicate callbacks; no event-loop busy spin on an amplification-blocked connection.

### Task 1: Recovery core

Files quic/packet_recovery.hh/.cc, tests/quic_packet_recovery.cc, CMake registrations; PacketAcknowledgments adds release(kind,packet_number) for retired transmission records.
Interfaces: RecoveryData(Frame), RecoverySend{shared_ptr<RecoveryData>,bool probe}; RecoveryContext{confirmed,peer_validated,max_ack_delay_ms,ack_delay_exponent,optional validation_probe_space}; sent(kind,pn,time,data), acknowledged(kind,ack,time,context)->released PNs; deadline(context), timeout(time,context)->per-space released PNs; take_pending(kind), discard(kind), rtt(). Shared frame identities mark logical delivery; queue at most once per identity. RTT only on newly-ACKed largest plus any newly-ACKed ack-eliciting packet. Packet loss threshold3, time9/8 max(latest,smoothed), floor1ms; PTO initial999ms, per-space last send plus global backoff. A PTO queues one probe and never declares loss. ACK-only timestamps and lost originals are retained only within bounded recent history; evicted samples are skipped.
- [x] Write deterministic tests for RTT eligibility/delay, thresholds, no false PTO loss, backoff, deadlines, pending cancellation and retirement; missing-header RED.
- [x] Implement and run sanitized executable GREEN. Validate API inputs and timer saturation.

### Task 2: Connection integration

Files quic/handshake_connection.hh/.cc and tests/quic_handshake_connection.cc.
Interfaces: ConnectionConfig::clock_us optional callback; next_timeout_us()->optional<uint64_t>, on_timeout(), rtt_estimate()->RttEstimator snapshot. Defaults remain steady_clock. Caller invokes on_timeout at deadline then drains poll_transmit. New handoffs register frames/times; ACKs apply core events before TLS level retirement. Replayed frames do not advance fresh CRYPTO cursors. Retired spaces discard all recovery state. Client anti-deadlock probes use Handshake keys when available, otherwise padded Initial. Amplification-blocked timers suspend until receive grants credit.
- [x] Add fake-clock dropped-flight tests and verify missing-API RED.
- [x] Wire recovery, verify normal/reordered/coalesced and actual UDP regression plus dropped first Initial, server Initial, middle Handshake, client Finished, HANDSHAKE_DONE and ACK-only loss. Assert both confirmed, bounded output, no retired-space timer, RTT samples and no premature probe.

### Task 3: Verification, documentation and review

- [x] Update implementation scope and event-loop API docs; format and git diff --check.
- [x] Run ctest --test-dir build -R quic_ --output-on-failure --timeout30 -j2 (actual flags --timeout 30), then full CTest with same timeout. Expect QUIC all pass and seven unchanged unrelated baseline failures.
- [x] Fresh read-only whole-milestone reviewer; one Important fix pass with RED/GREEN regressions, record rulings/minors, commit locally and preserve branch/worktree.


Final verification: QUIC21/21 passed (21.00s), full52/59 passed (107.85s). Five baseline timeouts: wrapping_integers_roundtrip,wrapping_integers_extra,recv_transmit,recv_reorder_more,send_transmit. Two missing executables: net_interface,router.

Fresh review found three Important timer bugs and no Critical/Minor. One fix pass: finished_probe_backoff RED/GREEN (idempotent key retirement); server_initial_ack_resets_backoff RED/GREEN (server recovery validation distinct from anti-amplification); early_loss_timer_callback RED/GREEN (selected-deadline guard). Focused executables and full QUIC suite then passed. Burst-loss modes6-9 supplement six single-loss scenarios. No second review or integration.

Final rulings (no deferred Minor findings):
1. Congestion control/bytes-in-flight/pacing/persistent congestion/ECN remain deferred: this milestone builds handshake recovery; cost is incomplete network control, not full RFC9002 compliance.
2. STREAM recovery/Retry/0-RTT/migration/external interoperability remain deferred: scope is handshake first; cost is unavailable features and no cross-implementation guarantee.
3. At full active history, probes also backpressure: preserve bounded memory; cost is possible stall under exhausted metadata or permanent withheld ACKs.
4. Recent history remains limited to4096 entries per space: preserve bounded memory; cost is omitted old RTT samples/delivery identity and possible redundant retransmission after eviction.
5. Seven pre-existing unrelated CTest failures remain outside scope: retain baseline evidence; cost is a non-green full suite and no integration.
