# QUIC v1 Retry Integrity Plan

**Goal:** Compute and verify the RFC 9001 v1 Retry Integrity Tag against the client's original DCID before a client accepts Retry state.

**Spec:** RFC 9001 §5.8 and Appendix A.4; `docs/quic-v1/tasks.md` tasks 2 and 3.

## Task 1: Tests first

- [x] Add Appendix A.4 known Retry vector and rejection tests for changed ODCID, token, tag, malformed packet and oversized ODCID.
- [x] Run failing test before implementation.

## Task 2: Implementation

- [x] Build Retry pseudo-packet from ODCID length, ODCID and Retry bytes excluding tag.
- [x] Use fixed RFC v1 AES-128-GCM key/nonce with empty plaintext and pseudo-packet as AAD.
- [x] Validate wire layout and compare the 16-byte tag in constant time.

## Task 3: Verify and document

- [x] Build sanitized/debug and run QUIC plus available full suite (12/12 QUIC; 48/48 full available suite).
- [x] Explain the rule, security limit, code path and tests in beginner notes; review and commit.
