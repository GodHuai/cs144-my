# QUIC Protected Packet Header Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and parse QUIC v1 protected packet headers and boundaries for Initial, 0-RTT, Handshake and 1-RTT.

**Architecture:** `quic/packet_header.hh/.cc` owns unprotected header fields, long-header Length and CID/token bounds. The parser returns `pn_offset` and `packet_end` without reading header-protected packet-number bits. Existing packet-number and header-protection helpers remain separate.

**Tech Stack:** C++20, existing varint and packet-number helpers, CMake/CTest sanitizers.

**Spec:** `docs/superpowers/specs/2026-10-19-quic-packet-header-design.md`

## Global Constraints

- QUIC v1 connection IDs are at most 20 bytes; Initial token length is a varint.
- Long-header Length includes the packet-number field and protected payload.
- Header-protection sample requires 20 bytes from `pn_offset`.
- Do not read protected packet-number length or reserved bits before unmasking and authentication.
- Reject Version Negotiation, Retry and unknown versions in this protected-packet parser.

## Review Focus

- Malformed CID/token/Length fields never read beyond datagram bounds.
- Coalesced long packets return distinct packet ends; short packet consumes remainder.
- A masked first byte must not affect unprotected layout parsing.
- Builder validates CID, packet number length, ciphertext minimum and Length overflow.
- Parser does not reject protected reserved bits before AEAD authentication.

---

### Task 1: Long-header packet layout and builder

**Files:** `quic/packet_header.hh/.cc`, `tests/quic_packet_header.cc`, `quic/CMakeLists.txt`, `tests/CMakeLists.txt`, `etc/tests.cmake`.

**Interfaces:** `parse_protected_packet(datagram, offset, short_dcid_length) -> optional<PacketLayout>` and `build_long_header(LongPacketType, dcid, scid, token, packet_number, pn_length, protected_payload_length) -> string`.

- [x] Write RFC 9001 Appendix A.2 Initial header fixture, coalesced packet, malformed length/CID/token, and protected-bits tests.
- [x] Build and observe RED for missing implementation.
- [x] Implement minimal v1 long-header parse/build.
- [x] Build and verify GREEN.

### Task 2: Short-header packet layout and builder

**Files:** `quic/packet_header.hh/.cc`, `tests/quic_packet_header.cc`.

**Interfaces:** `build_short_header(dcid, packet_number, pn_length, spin, key_phase, protected_payload_length) -> string`.

- [x] Write 1-RTT header and malformed CID/short-sample tests.
- [x] Observe RED for missing support.
- [x] Implement short-header parse/build.
- [x] Verify focused tests and inspect whole-suite result.

### Finish

- [x] Update coverage and implementation notes with exact partial scope.
- [x] Run formatting, focused tests and diff check; commit milestone.
