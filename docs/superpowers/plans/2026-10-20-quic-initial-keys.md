# QUIC v1 Initial Secrets Plan

**Goal:** Derive RFC 9001 Initial client/server traffic secrets and protect Initial payloads with AES-128-GCM and AES header protection.

**Spec:** RFC 9001 §§5.1–5.2, Appendix A.1; `docs/quic-v1/tasks.md` task 3.

## Task 1: Dependency and vector tests

- [x] Confirm OpenSSL 3 crypto runtime and obtain matching development headers for VM build.
- [x] Write failing tests for Appendix A.1 client/server secrets and keys, empty CID after Retry, and CID longer than 20 bytes.
- [x] Add Appendix A.2/A.3 Initial packet protection vectors and tampering tests.

## Task 2: Derivation

- [x] Implement HKDF-Extract with SHA-256 and TLS 1.3 HKDF-Expand-Label.
- [x] Derive Initial secret with QUIC v1 salt; derive client/server secret, `quic key`, `quic iv`, `quic hp`.
- [x] Use AES-128-GCM with packet-number nonce and unprotected-header AAD; use AES-ECB for Initial header mask.
- [x] Link OpenSSL libcrypto in CMake and keep the dependency documented.

## Task 3: Verify and explain

- [x] Build sanitized/debug targets, run QUIC and available full suite.
- [x] Explain derivation from RFC to code in beginner notes and coverage matrix; review and commit.
