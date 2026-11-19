# THREAT-MODEL changes (internal; not part of the jury copy)

Footnote to org/adr/THREAT-MODEL.md. The issue log (org/issues/SEC-01.json) keeps the full review history.

**v2 (panel):** C6 reworded; Live setup + shared-uid consequence; witness head store + record-and-heads truncation row; stall/resource row; Control/recovery-key row, operator trusted; TERMS fixes (suspension, record); side store → F3.

**v3 (panel):** one numeric uid per agent (60001 + index) + agent template sets `PR_SET_DUMPABLE=0`, feasibility checked in this container 19 Nov (distinct uids work without passwd entries; cross-uid `ptrace`/`pidfd_getfd` → EPERM; same-uid hijack of a dumpable sibling succeeds, confirming the finding); new RT3b sibling-hijack row; per-agent uid failure voids per-agent attribution for that run; insider reworded (printed head is the anchor, head store is defence in depth); "Detect, not exclude" paragraph folded into the record+heads row; this changes note moved out of the jury copy.
