# Project Kill Switch — SEED Hackathon 2026, Sub-theme 03 (Agent Safety)

You are continuing a project run as a simulated engineering org. Read `HANDOFF.md` first: it says exactly where work stopped and what to do next.

## What we're building
An accountability layer for ~10 autonomous agents sharing a workspace. Every action is identity-signed and recorded with read/write sets. A separate witness anchors the record. Detectors find a bad write, containment suspends one agent and holds tainted outbound effects, and recovery reverts only that agent's landed writes and repairs the work that read them. The jury scores **time-to-identify, time-to-contain, clean recovery**, and will try to break it.

- **Frame (Call #1):** the problem is that "undo one agent without discarding others' work" is undefined once honest agents read the bad write. The fix is provenance (every write has an author, every read a source). The payoff is selective undo. Why it matters: an agent's own log is testimony, not evidence.
- **Closest prior art:** Airlock (arXiv 2611.06727) does *forward* containment. We are the *backward* half plus an authenticated record plus oracle-scored recovery. Never claim "first" (see `abstract/GUARDRAILS.md`).

## Hard rules
1. **The abstract must be written by Aarav himself.** SEED checks for AI-written text. Never produce abstract prose; give notes, facts, rules and comment-only reviews (ABS-07).
2. Binding decisions live in `org/meetings/CALL-01.md` and `org/meetings/CALL-02.md` (+ `CALL-02/resolutions.md`, the design freeze). Don't silently contradict them; raise a decision instead.
3. Contracts in `src/ks/contracts/` are the single source of truth for data shapes. One canonical serializer (`ks.contracts.canonical`). Records hold hashes, never raw values.
4. Code: Python ≥3.12, offline, no API keys. Deps: cryptography, pydantic, jsonschema, pytest. `python3 -m pytest -q` must stay green.
5. Claims about security use the exact wording in `org/adr/THREAT-MODEL.md` (e.g. "tamper-evident up to the last witnessed head").

## How the org works
- **Every unit of work is an issue** in `org/issues/*.json`, managed only via the CLI:
  ```
  python3 org/issue.py list [--sprint N]
  python3 org/issue.py create --id X --sprint N --track eng --title "..." --owner <id> --reviewer <id> --model sonnet --by <id> --outcome "..." --accept "..." --deliverable path
  python3 org/issue.py status X in_progress|in_review|done|changes --who <id> --msg "..."
  python3 org/issue.py summary X --who <id> --text "..."
  python3 org/issue.py review X --who <id> --verdict done|changes --text "..."
  ```
  Team ids: pmo aarav maya anaya kabir zoya panel meera rohan leela sameer arjun nisha vikram tara ishaan.
- **Flow:** leads open small issues with testable acceptance criteria → owner does the work → reviewer gives a verdict → after a batch, a **team call** (minutes in `org/meetings/`) decides the next sprint.
- **Board:** `python3 board/render.py` writes `board/index.html` (open it in a browser). `python3 board/kit.py` renders the Abstract Kit to `board/kit.html`.
- **Subagents** for each team member are in `.claude/agents/` with their model assigned. Leads and reviewers are on Opus; most developers and researchers are on Sonnet; Vikram (rollback engine) is on Opus.
- Commit after each wave: `git add -A && git commit -m "..."`.

## Map
| Path | What |
|---|---|
| `org/CHARTER.md` | Brief, constraints, working agreement |
| `research/` | RES-01..11 reports, `SYNTHESIS.md`, `REVIEW-S1.md` |
| `org/adr/` | STRAWMAN, ADR-00..07 (+ `ADR-06-metrics.md`), `THREAT-MODEL.md` |
| `org/reports/` | Panel review, SEC-03 contract security review, CON-02 change requests |
| `org/meetings/` | Call #1 and Call #2 minutes and each lead's position |
| `abstract/` | Abstract Kit: FACT-CARD, GUARDRAILS, SKELETON, TERMS, JURY-QA, how-it-works.html |
| `src/ks/contracts/` | Contracts C1–C6 v1.0.0 (README is the dev reference) |
| `tests/contracts/`, `tests/redteam/` | 231 contract tests; red-team spec RT1–RT12 + uid isolation check |

## Key dates
Abstract 22 Nov 2026 (Aarav writes) · shortlist 24 Nov · prototyping 25 Nov–2 Dec · mentorship 3–7 Dec · finale 9 Dec.
