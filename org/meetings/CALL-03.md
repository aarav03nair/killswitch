# Call #3: Sprint 3 build kickoff

**Date:** 19 Nov 2026 (IST) · **Chair:** Claude (PMO) · **Attendees:** Maya (plan), The Panel (skeleton review), Kabir (open security items), Vikram (estimate) · **Inputs:** SKEL-01, org/reports/PANEL-SKEL-01.md, org/meetings/CALL-03/maya-plan.md

## Where we are
- The walking skeleton works end to end. Agents run as separate processes under their own uids, a gateway stub admits their actions, the record is hash-chained, the witness runs as its own process, and `ks verify` checks it all. 329 tests pass.
- The Panel ran 40 tamper cases. Every one gave the right reason and exit code.
- A real rogue agent (arbitrary Python) was refused on every run-dir file, on sibling /proc, and on ptrace and kill. A fork bomb was capped at 62 processes.

## Decisions
1. **Maya's build plan is adopted:** 35 issues B3-01…B3-35, each a day or less. Plus two follow-ups from the Panel's skeleton review:
   - **B3-36 (arjun):** fix the late final-ack anchor bug (M1), cap the signer flood (M2), check that an envelope's agent_id matches its connection (S3), and run `--shared-uid` as an unprivileged uid (S2).
   - **B3-37 (maya):** refactor before parallel build. A `Gateway.tick()` seam, a tool dispatch interface, and the RNG moved to `ks.rng`, so owners don't collide in one file.
2. **The 12 SKEL-01 findings are decided** (maya-plan §1). Errata landed in B3-02. ADR-04's step-number reference was fixed after the ADR-03 renumbering.
3. **Contracts 1.2 (B3-01) is additive only.** It adds witness link frames, a `SignRefusal` frame, `RunConfig.isolation` echoed by verify (Panel S1: a degraded-isolation run must never verify as if fully isolated), `decisions_from`, and `reexec_invalid`.
4. **The critical path** runs B3-03 → 04 → 18 → 21 → 24 → **27 (hero e2e, D5 = 24 Nov)** → 30 → 33 → 35, then code freeze on D7 (26 Nov, 18:00 IST). D8 is buffer.
5. **Slip rule:** if re-run simulation (B3-24) is not green by D5 18:00, Maya pairs with Vikram and F2+x (B3-29) moves to Sprint 4.
6. **Review load:** Kabir reviews 19 issues, in two batches a day. Reviews run on Sonnet unless the item is security-critical.
7. **Jury question to prepare** (Panel): agents can reach each other through /tmp, abstract sockets and loopback. The threat model makes no claim about this (covert channels are out of scope). Anaya adds it to Jury Q&A.

## Day 1 wave (started)
B3-01 contracts 1.2 (maya) · B3-02 ADR errata (done, in review) · B3-03 state store (vikram) · B3-07 detectors on fixtures (nisha).
