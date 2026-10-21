# QUIC v1 Initial Packet Plan

**Goal:** Assemble and authenticate complete QUIC v1 Initial packets from existing key, header, and packet-number primitives.

**Spec:** RFC 9000 §17.2.2; RFC 9001 §5.3–5.4 and Appendix A.3.

## Tests first

- [x] Add full RFC A.3 server Initial wire vector and open round trip.
- [x] Confirm the new test fails before implementation.
- [x] Cover changed tag/header, wrong direction key, truncation, coalesced offset and packet-number reconstruction.

## Implementation

- [x] Build Initial header and AEAD ciphertext before applying header protection.
- [x] Locate the fixed sample offset; remove masking before reconstructing and authenticating packet number.
- [x] Return no packet on malformed input or AEAD failure, and check reserved bits after authentication.

## Verification and notes

- [x] Build sanitized/debug and run the QUIC and available full suites (13/13 QUIC; 49/49 full).
- [x] Explain RFC rules, code order, tests and integration boundary in beginner notes.
