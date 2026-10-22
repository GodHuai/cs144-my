# Handshake and 1-RTT Packet Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline with TDD, followed by one fresh final code review.

**Goal:** Protect/open QUIC v1 Handshake and 1-RTT packets using real TLS traffic secrets, and run a complete in-memory protected-packet TLS handshake plus encrypted application payload exchange.

**Architecture:** Add cipher-specific `PacketProtectionKeys` and generic key/payload/HP entry points, sharing the existing Initial AES/HKDF backend and preserving its public API. Add stateless Handshake/1-RTT seal/open functions over existing packet-header, packet-number and header-protection modules. Authentication precedes exposing plaintext, metadata or protocol errors. The test packetizer bridges TlsHandshake through protected packets without adding a production connection or UDP layer.

**Tech Stack:** C++20, existing pinned OpenSSL 3.5.9, CMake/CTest with ASan/UBSan.

**Spec:** `docs/quic-v1/requirements.md` R1/R2/R6 and `design.md`; RFC 9001 sections 5.1, 5.3–5.5; RFC 9000 sections 12.2, 17.2.4, 17.3.

## Global Constraints

- Authorized continuation on existing isolated `/home/huai/minnow-quic-proposal`, branch quic-v1-proposal, base 2414d30; no merge/push or system dependency changes.
- AES-128-GCM/SHA256 only, matching TLS adapter cipher restriction. Derive key(16), iv(12), hp(16) from exact 32-byte traffic secret using RFC QUIC labels. Do not print secrets; returned copies remain caller-owned sensitive data.
- Preserve Initial APIs and RFC vectors. Share crypto primitives; no parallel hand-written crypto.
- Caller owns unique monotonically allocated packet numbers, directional and encryption-level key selection, key lifetime, retry/key updates, duplicate tracking and authenticated CID routing. Key-phase/spin bits are authenticated metadata only, not a key-update state machine.
- Do not auto-pad; callers supply enough PADDING for HP sample (pn_offset+4, 16 bytes). Keep Initial minimum UDP datagram sizing with caller.
- Opening one packet in a coalesced datagram returns absolute layout offsets; a short-header packet consumes the remaining datagram and must be last.
- Malformed/unauthenticated input returns empty result, no plaintext/metadata/error. Authenticated nonzero reserved bits return only transport_error=0x0a for future connection close. Update largest_received only after successful packet result.
- Default current key phase false; can encode/report phase and spin but never generate or accept a key update implicitly.
- No UDP, ACK/recovery, flow control, AEAD usage counters, key discard/update, 0-RTT or independent implementation interoperability claim this milestone.

## Review Focus

- Ciphertext/tag/header tampering and wrong-direction/level keys never expose plaintext or trusted bits; tests mutate each and use wrong keys.
- Reserved bits are checked only after AEAD and distinguished from damage; test valid-tag illegal-bit packets and corrupted-tag variants.
- One coalesced packet cannot borrow another packet's HP sample or ciphertext; test truncated sample plus a following valid packet, mixed long/short packets and nonzero offsets.
- Correct packet-number recovery before nonce generation, 62-bit boundaries and minimum sample lengths; test 1–4-byte numbers, wrap, maximum PN, invalid largest and short payloads.
- Real TLS bridge only processes authenticated CRYPTO frames, isolates Initial/Handshake spaces, and uses matching directional TLS secrets; exercise complete protected TLS handshake and bidirectional encrypted STREAM bytes without sockets.

### Task 1: Protected-packet primitive and TLS integration

**Files:** new `quic/packet_keys.hh`, `quic/protected_packet.hh/.cc`, `tests/quic_protected_packet.cc`; modify `quic/initial_keys.hh/.cc`, `quic/CMakeLists.txt`, `tests/CMakeLists.txt`, `etc/tests.cmake`; update docs/quic-v1.

**Interfaces:**
- `PacketProtectionKeys { secret[32], key[16], iv[12], hp[16] }`; InitialPacketKeys remains compatible alias.
- `derive_packet_keys(array<uint8_t,32>) -> PacketProtectionKeys`; generic encrypt_packet_payload/decrypt_packet_payload/packet_header_mask with same signatures as existing Initial primitives.
- `seal_handshake_packet(keys,dcid,scid,pn,pn_length,plaintext) -> string`.
- `seal_one_rtt_packet(keys,dcid,pn,pn_length,plaintext,key_phase=false,spin=false) -> string`.
- `OpenedProtectedPacket { PacketLayout layout; uint64_t packet_number; string plaintext; bool key_phase; bool spin; }`.
- `PacketOpenResult { optional<OpenedProtectedPacket> packet; optional<uint64_t> transport_error; }`.
- `open_handshake_packet(keys,datagram,offset,largest_received) -> PacketOpenResult`; `open_one_rtt_packet(keys,datagram,offset,short_dcid_length,largest_received) -> PacketOpenResult`.

- [x] Write real tests: RFC traffic-secret key vector and independently generated full AES Handshake/1-RTT wire fixtures; negative/boundary cases above; protected-packet TLS handshake/STREAM integration with build-generated certificates. Register target. Build expecting missing header failure.
- [x] Implement generic keys API and stateless seal/open. Retain Initial compatibility. Run new sanitized test until green; run QUIC suite.
- [x] Update usage/coverage/learning docs and plan evidence. Review whole milestone with isolated reviewer; fix important findings with RED/GREEN regressions.
- [x] Verify debug+sanitized build, formatting/diff checks and full CTest with 30-second per-test budget and -j2; report old slow/missing tests by name. Commit on current branch and preserve logs under ignored build/.


## Execution Evidence

- Baseline: existing isolated worktree clean at 2414d30; QUIC 15/15 passed.
- RED: new target failed compilation because quic/packet_keys.hh did not exist.
- GREEN: new sanitized target passed with public RFC9001 key vectors, independent Python cryptography41.0.7 full-wire fixtures, malformed and boundary checks, and protected real TLS/application exchange.
- During test bring-up, corrected the out-of-range PN assertion to the existing encode_packet_number out_of_range contract (not invalid_argument), and used the real original DCID in the integration client Initial header. No production bug fix hidden in the test corrections.
- Generic crypto implementation retained in initial_keys.cc, with generic public header and old forwarding APIs, to share the tested backend and preserve existing learning-document links.
- Fresh isolated read-only review found no critical/important issue. Its small wrong-direction coverage omission was part of the planned Review Focus; added actual receiver-write-secret rejection assertions for Handshake and OneRtt. New target passed after the addition. No deferred minor findings.
- Debug and sanitized build succeeded; QUIC16/16 passed. Full CTest timeout30/-j2 completed103.82s,47/54 passed, five existing non-QUIC tests timed out and two old executables missing (names in protected-packets.md). All QUIC tests passed in full run.
- Continue native execution and manual ignored build ledger as in previous milestones; no workflow tool installation or dependency changes. No merge/push.
- Accepted review exclusions: UDP/ACK/recovery/independent interoperability, caller-owned key lifecycle/update/usage/duplicate/CID state, additional ciphers, binary ABI preservation across an unrecompiled static library. Source Initial compatibility and rebuilt old tests are preserved; this remains an unfinished connection.
