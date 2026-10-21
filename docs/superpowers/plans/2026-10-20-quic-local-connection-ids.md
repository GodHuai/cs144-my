# QUIC Local CID Issuer Plan

**Goal:** Track locally issued CIDs, reject invalid peer retirements, and expose available routing IDs and replacement demand.

**Spec:** RFC 9000 §§5.1.1, 19.15–19.16; `docs/quic-v1/tasks.md` task 9.

## Task 1: Test issuer behavior

- [x] Add failing tests for sequence allocation, peer active limit, duplicate CID/token, preferred-address reservation, retirement of current packet DCID, unsent/future sequence, duplicate retirement, zero-length mode, and replacement demand.

## Task 2: Implement local CID pool

- [x] Store initial sequence zero and issued IDs, preserve IDs until retired, and report only active IDs for packet routing.
- [x] Require caller-generated unpredictable CID/token; cap total issuance as permitted by RFC 9000 §5.1.1.
- [x] Validate RETIRE_CONNECTION_ID against the packet's DCID and actual sending before changing state.

## Task 3: Verify and document

- [x] Build sanitized/debug targets and run QUIC plus available full suite.
- [x] Explain RFC rules and source in beginner notes, update coverage, review, and commit.
