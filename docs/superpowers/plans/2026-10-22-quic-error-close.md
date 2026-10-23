# QUIC error close implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for native inline execution.

**Goal:** authenticated transport errors and handshake multi-level close notification.
**Architecture:** shared close sealer before cleanup, RAII outgoing-secret cache via TLS observer, preserved receive Failed status distinct from Closing lifecycle.
**Tech Stack:** C++20/OpenSSL, sanitized CTest and injected clock.
**Spec:** ../specs/2026-10-22-quic-error-close-design.md

## Global constraints
Base b14b00b; worktree /home/huai/minnow-quic-proposal; no push/merge. Coalesced close<=1200; Initial-containing exactly1200. Existing immutable first error,3PTO limits and secret() failure behavior retained.

## Review focus
First Initial routing never trusts unauthenticated headers. Newly generated write key must survive TLS alert only in transport cache. Lowerlevel app close must hide reason/code. Retired keys cannot return. Receive status must still report automatic error even when state Closing.

## Task1: authenticated protocol close
- [x] Add Initial error decryption and AEAD discard regressions to tests/quic_connection_lifecycle.cc, run behavioral RED.
- [x] Refactor shared cached close builder in handshake_connection.cc, bind minimum authenticated error route, route preflight/packet errors through transport fail(code,frame), adapt prior handshake error expectations; run GREEN.

## Task2: TLS/handshake protection levels
- [x] Add Established-before-Finished close delivery and same-advance TLS cert rejection regressions, run RED.
- [x] Add optional WriteSecretObserver to tls_handshake.hh/.cc, connection RAII write cache; coalesce available levels with exact1200 Initial padding and app fallback0x0c/empty reason; run GREEN.

## Task3: final integration
- [x] Confirmed errors only1RTT, immutable diagnostics/cleanup, retire boundaries, TLS observer/no secret exposure tests; review whole diff with fresh reviewer and fix regression findings.
- [x] Full CTest --timeout30 -j2, clang-format/diff/link checks; update actual result, design/plan, implementation docs/local notes; commit branch only.

## Execution ledger
Native continued execution authorized by user next-step request. Existing isolated worktree kept. Design/skill questions skipped under persisted continue instruction; implementation choices documented as agent decisions.

RED/GREEN ledger: Initial error produced no close -> GREEN protectedInitial; early app close omitted Handshake fallback -> GREEN coalescedlevels; TLS failure lost same-advance Handshake write key -> GREEN observercache. Review RED Initial close wrong diagnostic -> GREEN per-frame allowed check/type0x1e. Certificate/SNI and Initial8/20CID, confirmedonly1RTT, reservedbitclose decryption, observerexception containment all GREEN. Focused lifecycle/TLS/handshake binaries passed. Fresh independent review found no blockers; minor knownframe finding fixed and rechecked read-only. Constructor unwind/cleansing verified by RAII declaration order review, not destroyed-memory probes. Full suite running; actual result recorded in docs/quic-v1/error-close.md.

Full first run57/65 in163.43sec: original7 plus retirement30sec timeout. Isolated newcode retirement31.18sec CPU30.93; sameflags b14b00b two-object baseline28.47sec CPU28.28. New hot-path authenticated_route string copy found; limited snapshot to unboundfirstInitial only, reviewer confirmed safe. Rebuilt unchanged129round test26.75sec CPU26.51. No timeout increase/coverage reduction. Final whole-suite rerun required after hotpathfix.

Final full CTest58/65 in156.85sec, QUIC27/27 including fixture. Retirement29.29s, handshake29.10s, lifecycle4.69s. Seven prior nonQUIC failures unchanged. Final format/diff/local-link checks PASS. Native branch commit only, no push/merge.
