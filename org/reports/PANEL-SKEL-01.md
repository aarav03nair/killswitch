# PANEL review of SKEL-01 (walking skeleton)

Reviewer: panel · 19 Nov · Verdict: **changes** (two small must-fixes; the rest goes to Sprint 3).

## 1. What held
Suite 329 passed. A 2×10 run takes 0.9 s and a 10×50 run 2.8 s; both verify `OK; anchored`. I ran 40 tamper cases (`/tmp/panel_skel/tamper.py`), each with and without `--head`. All gave the right reason and exit code:
- Records: field edit `hash_mismatch` k. Whitespace, `\u` escapes, CRLF, blank line and missing LF all `parse_error`. Deleted, swapped or duplicated line `seq_gap`. Tail cut `truncated` n+1.
- Witness: missing `witness_missing`. Dropped or duplicated checkpoint `count_mismatch`. Edited head `witness_sig_invalid`.
- An agent key swap is caught even unanchored. A full re-forge (new gateway and witness keys), a dir swap from another run, config edits, a consistent prefix cut and a dropped last checkpoint are caught **only** with `--head`, as THREAT-MODEL says.

Rogue agent (arbitrary Python inside a real agent, uid 60001): EACCES on the run dir, the repro secret and gateway/sibling `/proc/*/{environ,mem,fd}`. Ptrace and kill of siblings are denied. A double-fork survivor was killed by uid, and NPROC capped forks at 62.

## 2. Must-fix
**M1. An honest run can fail anchored verify.** If the witness acks the last tick late, the anchor is printed from tick n-1 while `witness.jsonl` holds tick n. `verify --head` then gives `WITNESS head_mismatch` (`late_ack.py`: anchor at seq 8, witness at seq 10). Fix: drain the link after `close` and anchor the newest verified checkpoint, or take ADR-02's final checkpoint. Add a test.

**M2. The signer handle is unbounded.** A junk-line flood from a rogue thread left 752k refusals in memory (96 MB in 6 ticks) and stretched ticks from ms to 0.8 s, on a gateway set to `oom_score_adj -1000`. Fix: count refusals instead of listing them, and give each handle a per-tick line budget, then EOF the connection.

## 3. Sprint 3 should-fix
- S1: a `--shared-uid` run verifies `OK; anchored`. Bind the isolation mode into `RunConfig` (1.2).
- S2: `--shared-uid` as root runs agents as uid 0. Use one shared unprivileged uid.
- S3: the gateway does not check `agent_id` against the connection's principal, although D7 assumes 1:1. Add the check.
- S4: verify should check records against config (ticks, agents, `ts_us`). Today a `ticks` edit verifies OK unanchored.
- Covert channels between agents (`/tmp`, abstract sockets, loopback) are open. That is in scope as "no claim"; prepare the jury answer.

## 4. Maya's ADR findings
Her summary and code notes give 10 items. The "SKEL-01 notes" they cite are not in the repo; put them in the ADR amendments.
- **Real:** dumpable reset by execve (solved in BOOT; amend ADR-00/01). The missing sign-refusal frame is the most consequential: a refused honest agent hangs, misses 3 ticks and gets EOF, and refusals never reach the record. Also real: `action_id` vs nonce window (keep action ids for the whole run). `no_state` is a contract bug (ADR says ok=true, contract maps it to exit 4). Degraded isolation invisible (S1). Final checkpoint vs increasing ticks is worse than stated (M1).
- **Docs only:** the tail-truncation reason. Keep the contract's `truncated` and amend ADR-02 RT8.
- **Fine for now:** run_id vs determinism (the keyring hash separates runs), the missing readiness handshake, and the untyped witness protocol (canonical but untyped; type it in contracts 1.2 to close the acceptance criterion 3 gap).

## 5. Code and boundaries
High quality: small, fail-closed and ADR-cited. Canonical strictness holds, and `verify` never imports the recorder. Modules map 1:1 onto the Call #3 ownership table. Before the owners start:
1. Keep `runtime/barrier.py` to I/O and timing, behind `Gateway.tick()`. Otherwise control, view, dispatch and monitor land there and it becomes a maya/nisha hotspot.
2. Move `TOOLS` behind a world/state dispatch interface.
3. Move rng out of `ks.runtime`; `ks.world` should not import it.
