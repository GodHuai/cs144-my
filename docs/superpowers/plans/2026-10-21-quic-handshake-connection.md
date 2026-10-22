# QUIC Handshake Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline; finish with a fresh whole-milestone reviewer.

**Goal:** Move handshake orchestration from the UDP test harness into a reusable single-path connection engine.

**Architecture:** `HandshakeConnection` is a sans-I/O owner of TLS, three packet-number spaces, CIDs, amplification budget, and bounded pending ciphertext. External UDP dispatch pins one peer address. Client starts TLS with deferred peer CID; the first authenticated server Initial binds it once before TLS consumes peer parameters. Server lazily creates TLS from the actual client Initial headers. Outgoing datagrams are handed off one at a time; caller retains an emitted datagram if UDP would block.

**Tech Stack:** C++20, existing OpenSSL 3.5.9 TLS/packet primitives, Linux UDP integration, ASan/UBSan CTest.

**Spec:** docs/quic-v1/design.md, connection ownership and authenticate-before-state rules. This is the handshake portion, not a complete QUIC transport.

## Global Constraints

- Existing isolated quic-v1-proposal worktree, base dfea93f; no merge/push or dependency changes.
- QUIC v1, TLS_AES_128_GCM_SHA256, no Retry or 0-RTT.
- All Initial datagrams emitted are at least 1200 bytes; server drops smaller client Initial datagrams.
- Caller provides 8..20-byte local CIDs and client original DCID; production callers must use unpredictable values.
- One pinned UDP peer; source/CID routing before decryption, semantic state updates only after authentication.
- No stream API/flow control, ACK generation/recovery/congestion control, listener/migration, close timers or wire error-close scheduling in this milestone. Unsupported authenticated frame semantics terminate locally with INTERNAL_ERROR, not a false peer protocol violation. ACK framing is validated including unsent-largest checks, but recovery is not performed.

## Review Focus

- Spoofed source/CID, failed AEAD and undersized Initial must not create TLS or advance handshake state: test all three.
- Actual peer CID must bind transport parameters, not a configured guess: dynamic server CID, rebinding rejection, TP mismatch tests.
- Handshake packet arriving before keys must be bounded and replayed after Initial: test flight reordering, cap overflow and coalesced packets.
- Malformed/prohibited/role-invalid frames and peer close must stop processing atomically before CRYPTO or confirmation: test full-packet preflight and sticky terminal states.
- Server cap, packet duplicates and confirmation/key discard must not depend on unauthenticated input: test duplicate receives, damaged packet and server/client confirmation milestones.

### Task 1: TLS peer context and key retirement

**Files:** quic/tls_handshake.hh/.cc; tests/quic_tls_handshake.cc.

**Produces:** TlsConfig::defer_peer_initial_source_connection_id (false default); `bind_peer_initial_source_connection_id(string)->bool` only once when explicitly deferred and before peer params/error; deferred params without binding fail with 0x08. `discard_keys(PacketKind)` accepts Initial/Handshake only, clears retained CRYPTO plus Handshake directional secrets; OneRtt invalid_argument.

- [x] Write tests for deferred one-shot CID binding, invalid size/rebind, and Handshake key discard using a completed TLS pair.
- [x] Observe missing API RED, implement minimal adapter extension, verify existing TLS tests.

### Task 2: Connection engine and tests

**Files:** quic/handshake_connection.hh/.cc; tests/quic_handshake_connection.cc; CMake registrations.

**Produces:** ConnectionConfig{TlsConfig tls,string local_cid,string initial_dcid}; `HandshakeConnection(config,UdpEndpoint peer)`; `receive(const UdpDatagram&)->ConnectionReceive {Discarded,Processed,Failed}`; `poll_transmit()->optional<UdpDatagram>`; `send_ping()->bool`; state() {WaitingInitial,Handshaking,Established,Confirmed,Draining,Failed}, transport_error(), peer_cid(), peer_parameters(), negotiated_alpn(). All noncopyable, pimpl-owned.

Pending ciphertext: <=64 packets and <=65536 bytes, overflow silently drops new ciphertext; never make a peer protocol error from unauthenticated overflow. Receives process coalesced long packets and trailing short header. Pending replays do not credit datagram bytes twice. Receive replay ranges bounded by retaining the newest 4096 packet numbers (older packets discarded).

Outgoing CRYPTO fragments <=600 bytes; one prepared datagram retained while amplification-blocked. Packet numbers allocated once, outgoing cursor advances only on handoff; a pending control PING is a bool, not an unbounded queue. Use four-byte transmitted packet numbers; ACK-based packet-number width optimization belongs to recovery work.

Server confirms at TLS completion and queues HANDSHAKE_DONE; client Established at TLS completion, Confirmed only after authenticated HANDSHAKE_DONE. Client discards Initial on first Handshake handoff; server on authenticated Handshake. Both retire Handshake keys on confirmation. Received valid peer close enters terminal Draining with no response; errors terminal Failed and cleanse TLS/pending output. First local error is sticky.

- [x] Write deterministic tests for dynamic CIDs, positive flights, duplicate/tamper, wrong source/CID, undersized Initial, reordered/coalesced flights, queue pressure, illegal/malformed frames, invalid config and terminal behavior. Build RED for missing connection API.
- [x] Implement authentication, complete frame preflight before mutation, lazy TLS, pending replay, packet assembly/budget and state transitions.
- [x] Add real IPv4/IPv6 connection tests using the new production class; verify PING and HANDSHAKE_DONE.
- [x] Run all QUIC tests and full CTest (--timeout 30 -j2), retain exact baseline failures.
- [x] Fresh read-only final code review; fix Important/Critical findings by regression RED/GREEN, document boundaries/results and commit.

Execution authorization: user's repeated continue after the agreed connection -> recovery -> stream order. No renewed approval gate. Manual ledger in ignored build/quic-connection-progress.md as prior milestones. Preflight: Task 2 consumes the exact TLS API in Task 1; no legacy UDP or TLS default behavior changes.

## Completion and review record

**Produces:** TlsConfig::defer_peer_initial_source_connection_id (false default); `bind_peer_initial_source_connection_id(string)->bool` only once when explicitly deferred and before peer params/error; deferred params without binding fail with 0x08. `discard_keys(PacketKind)` accepts Initial/Handshake only, clears retained CRYPTO plus Handshake directional secrets; OneRtt invalid_argument.

Implementation and tests completed; both final Important findings reproduced and fixed in one pass. Final QUIC 19/19 including compile fixture (20.21s), full CTest 50/57 (100.79s), ordinary debug build and formatting checks pass. Exact unchanged baseline failures are recorded in docs/quic-v1/handshake-connection.md. No merge or push.

Final: fixed authenticated Initial reserved-bit error hidden by optional API: new regression RED (silently discarded), then detailed Initial result + compatible optional wrapper + engine fail path GREEN up to next regression.
Final: fixed Initial final-size padding: 1200-limited receiver regression RED (drops emitted datagram), then size header/PN/Length/tag and pad to final 1200; tests include 8 and 20-byte CIDs. Final QUIC 19/19, 20.21s; full suite 50/57, 100.79s, exit 8: baseline Timeout wrapping_integers_roundtrip/wrapping_integers_extra/recv_transmit/recv_reorder_more/send_transmit; missing executables net_interface/router. No new failures. quic_debug and clang-format/git diff --check pass.
Final: Ruling: recovery and application transport deferred — handshake engine does not promise ACK/retransmission/streams — cost if wrong: unreliable/no application transport under loss.
Final: Ruling: listener/migration and broader lifecycle deferred — one peer is pinned and peer close only terminates output without timers — cost if wrong: no general server dispatch, migration or full lifecycle.
Final: Ruling: interoperability breadth and unsupported TLS/QUIC extensions deferred — fixed TLS suite and supported handshake/control semantics, unsupported authenticated features fail locally — cost if wrong: external peers/extensions may not interoperate.
