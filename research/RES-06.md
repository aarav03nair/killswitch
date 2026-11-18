# RES-06: OSS survey of checkpointing, time-travel and versioned stores for per-agent rollback

Owner: leela. Reviewer: anaya. Read on 19 Nov 2026. Repos shallow-cloned to /tmp/oss6 and read only, nothing executed. The Git demo in Finding 5 was run locally with plain `git`.

## 1. TL;DR

- **Hypothesis H6 holds, with one correction.** No surveyed tool rolls back "agent X" as such. LangGraph, Temporal, Replit snapshots and DeltaBox all restore to an earlier point, which drops everything after it, including other actors' work. [Fact]
- **The correction:** the tools built on a commit graph (Dolt, lakeFS, Git) already have a **"revert one commit, keep later commits"** primitive. It is a reverse patch applied as a new commit. Per-author rollback therefore means "revert every commit tagged with author X". [Fact]
- **Where it breaks is dependent work.** If agent B edited the same data after agent A, the revert conflicts. Git showed this in a local run, and Dolt and lakeFS document conflict handling for revert. None of them can tell you that B *read* A's output. [Fact, Our view]
- **Recommendation: Dolt as the shared-state substrate** (row/cell-level three-way revert, SQL, Apache-2.0). A Git working tree is the fallback for file artefacts. lakeFS is a poor fit (object-level, server needed, BSL licence). Put the provenance graph on top, because that is where the real differentiator lies. [Our view]

## 2. Findings

**F1. LangGraph checkpointers and time travel restore a thread to a checkpoint; they do not do selective undo.** [Fact]
- Replay runs a prior checkpoint again. "Nodes before the checkpoint are not re-executed… Nodes after it run again", so LLM calls and API requests can return different results [1].
- Fork (`update_state`) "creates a new branch from a past checkpoint with modified state" and leaves the original history intact [1].
- The checkpoint is per *thread* and holds graph state. It does not hold the external side effects of tools. Source has `get_state_history`, `update_state` and `bulk_update_state` in `libs/langgraph/langgraph/pregel/main.py`, plus sqlite and postgres checkpointers (MIT licence) [2]. Verified in the repo layout and code.
- [Our view] It is useful for one agent's reasoning state. It is the wrong layer for shared-world rollback.

**F2. Temporal Reset is a whole-execution rewind.** [Fact]
- "A Reset terminates a Workflow Execution and creates a new Workflow Execution with the same Workflow Type and Workflow ID. The Event History is copied from the original execution up to and including the reset point" [3].
- The server proto defines `ResetWorkflowExecution` by event batch (verified in `proto/internal/.../historyservice/v1/service.proto`; MIT) [4].
- [Our view] Reset rewinds one workflow's history. It does not undo side effects in other systems; that needs saga-style compensations (RES-02's scope). Event sourcing gives you the log but not the dependency graph.

**F3. Replit snapshots and DeltaBox are whole-sandbox checkpoints.** [Fact]
- Replit: block devices are split into "16 MiB chunks", and a manifest lists the chunks for one disk version. Restoring a checkpoint swaps in an earlier manifest. Code is tracked in Git and the Postgres database is captured with the disk. Checkpoints are taken at a "doneness" state, not per change. Parallel agent sandboxes appear only as future work [5]. (Read through a summarising fetch, so quotes should be re-checked against the page.)
- DeltaBox (arXiv 2605.22781; the page I read showed v3, submitted 13 Nov 2026, SJTU and Huawei authors): saves only the deltas between checkpoints. Checkpoint work took 10.83 ms and mean rollback 1.86 ms on SWE-bench. DeltaFS makes rollback a layer switch [6]. The abstract page does not say whether selective rollback is supported, and I did not read the full paper. Not found.
- [Our view] Fast and good for one agent's own sandbox, e.g. "retry from before the bad step". Both are all-or-nothing at the point of restore.

**F4. Dolt has the right primitive, at row level.** [Fact]
- `CALL DOLT_REVERT('HEAD~2')` "creates a new commit from the current HEAD that reverses the changes in all the specified commits" and `--author=` sets the revert's author [7]. Source and tests are in the repo (Apache-2.0) [8].
- Verified in Dolt's own engine tests (`dolt_queries_revert.go`): after seed, a commit setting `pk=2` to 42, and a commit setting `pk=3` to 23, `dolt_revert('HEAD~1')` returns `pk=2` to 2 while `pk=3` stays 23. That is revert-one-keep-later.
- Conflicts: when two commits touched the same row (`pk=2` changed twice) the revert returns conflict counts and leaves the working set conflicted, with no new commit. `--continue` and `--abort` resolve it [8]. The CLI doc says the revert "requires a clean working set" [8].
- Cherry-pick "preserves the original commit's author identity" [7]. That gives us per-agent attribution by commit author.
- [Our view] Dolt conflicts are per cell/row, so two agents touching different rows of the same table do not conflict. This is the main advantage over Git's line hunks.

**F5. Git: same primitive, coarser conflicts; tested locally.** [Fact, local run]
- Setup: seed, then agent3 commits a bad write to `cfg_a`, then agent5 commits a write to `cfg_b`. With the lines three apart, `git revert <agent3 commit>` applied cleanly, leaving `cfg_a=1 … cfg_b=2` (agent5's work kept).
- With *adjacent* lines, the same revert conflicted even though the edits were logically independent.
- Dependent case: agent3 writes `cfg_a=BAD2`, agent7 edits that line to `cfg_a=BAD2+derived`. Reverting agent3's commit gives `CONFLICT (content)`.
- [Our view] Git suits file artefacts (code, configs). It cannot model a database or knowing *why* B changed the line.

**F6. lakeFS: same primitive, object granularity, licence and server caveats.** [Fact]
- `Graveler.Revert` "creates a reverse patch to the commit given as 'ref', and applies it as a new commit on the given branch", implemented as a merge with the reverted commit as base; it can return `ErrConflictFound` [9] (verified in `pkg/graveler/graveler.go` and `errors.go`).
- The repo LICENSE is **Business Source License 1.1** (version 1.87.0 at read time), not OSI open source [9]. It runs as a server over object storage, so it is heavier offline.
- [Our view] Object-level conflicts mean two agents editing one file collide. Skip it for the prototype.

## 3. Comparison table

| Tool (repo/docs) | Rollback granularity | Keeps others' later work? | Conflict handling | Python / offline usable |
|---|---|---|---|---|
| LangGraph time-travel [1][2] | Whole thread state (checkpoint); fork = new branch | No: later nodes re-run or branch away | None; re-execution is non-deterministic | Yes, pip lib with sqlite checkpointer. MIT |
| Temporal Reset [3][4] | Whole workflow execution to an event | No: later events dropped | N/A (side effects need compensation) | Server needed (dev server possible). MIT |
| Replit snapshots [5] | Whole disk + DB to a checkpoint | No | N/A | Proprietary, not usable |
| DeltaBox [6] | Whole sandbox (FS + process) to a checkpoint | No (selective not stated) | N/A | Research paper; code not checked |
| Git [local run] | Per commit; filter by author | Yes if no overlap | Line-level 3-way; conflict markers; adjacent lines conflict | Yes, stdlib subprocess, fully offline |
| Dolt [7][8] | Per commit; **per row/cell diff** | Yes if no same-cell overlap | 3-way; conflict count, `--continue`/`--abort` | Single Go binary + MySQL-compatible SQL, offline (Python via a MySQL client). Apache-2.0 |
| lakeFS [9] | Per commit; object level | Yes if no same-object overlap | `ErrConflictFound` | Server + object store. BSL 1.1 |

## 4. Implications for our design

- **Recovery substrate (decision): Dolt for structured shared state.** Each agent writes under its own identity, and each logical action is a commit with `author = agent_id` and the action ID in the message. Rolling back agent X means reverting its commits, newest first, with `dolt_revert`. [Our view] Caveat: I have not run Dolt myself (downloaded binaries were not executed, per task rules). Day 1 of prototyping should run the engine-test scenario in F4 and a Python MySQL-client check.
- **Fallback: Git** for file artefacts and as the zero-dependency demo path, since it was verified here and needs no install. [Our view]
- **Build, do not reuse: the dependency layer.** None of these tools records reads. A revert is only safe when no later commit *depends on* the reverted one. We need a Recorder-side provenance graph (write set, read set, per RES-04) to find "dependents of X's commits" and decide: revert cleanly, quarantine, or flag for review. Conflicts from Dolt/Git then become a *signal* that an agent built on bad work, not an error. [Our view]
- **Avoid** LangGraph time-travel or Temporal Reset or VM snapshots as the *shared-state* recovery path; they discard other agents' work. They remain fine per-agent "retry" tools. [Our view]
- **Irreversible effects** (email, payment) are not covered by any substrate here; route them to the compensation/gating design (RES-02). [Our view]
- **Evaluation harness:** the clean/dependent/conflicting scenarios in F4 and F5 are ready-made test cases for "collateral loss" and "residual damage" (RES-08). [Our view]

## 5. Implications for framing

- Commit-graph stores can already "revert one commit and keep later ones" (Dolt tests, lakeFS code comment, Git). The unsolved problem is knowing which later work *depends* on the bad commit. That supports the thesis "dependency problem, not snapshot problem" [Our view]; the evidence is the conflict behaviour above and the checkpoint-only semantics of the agent-framework tools.
- Concrete demo number to reuse: the local Git run shows revert succeeds for non-adjacent independent edits and conflicts for dependent ones. (A single toy example, not a benchmark.)

## 6. Open questions

- Run Dolt for real (offline, embedded or server) and time a revert across ~10 agents' commits. Prototype sprint.
- Does DeltaBox's full paper support partial or selective rollback? Not stated on the abstract page. RES-01/RES-02 could check.
- Dolt cell-level conflict rules when two agents insert rows with the same primary key or add rows under unique constraints: not tested.
- Automatic merge of dependents (re-execution under a different agent output) is non-deterministic: RES-01.
- Other candidates not surveyed: event-sourcing libraries (e.g. Axon, EventStoreDB), TerminusDB, Datomic, git-annex. Skipped for time.

## 7. Sources

1. LangGraph, "Use time-travel" docs, LangChain. Primary (official docs, via summarising fetch). https://docs.langchain.com/oss/python/langgraph/use-time-travel
2. langchain-ai/langgraph repo, MIT, shallow clone read 19 Nov 2026. Primary (code). https://github.com/langchain-ai/langgraph
3. Temporal docs, "Event" (Reset). Primary (official docs). https://docs.temporal.io/workflow-execution/event
4. temporalio/temporal repo, MIT, `ResetWorkflowExecution` in history service proto. Primary (code). https://github.com/temporalio/temporal
5. Replit, "Inside Replit's Snapshot Engine". Primary (vendor first-hand engineering blog). https://blog.replit.com/inside-replits-snapshot-engine
6. DeltaBox: Millisecond-Scale Sandbox Checkpoint and Rollback for Stateful AI Agents (arXiv 2605.22781), via alphaxiv page. Secondary view of a primary paper; full text not read. https://www.alphaxiv.org/abs/2605.22781
7. DoltHub docs, SQL procedures (DOLT_REVERT, DOLT_CHERRY_PICK). Primary. https://www.dolthub.com/docs/sql-reference/version-control/dolt-sql-procedures/
8. dolthub/dolt repo, Apache-2.0: `go/cmd/dolt/commands/revert.go` and `go/libraries/doltcore/sqle/enginetest/dolt_queries_revert.go`. Primary (code and tests, read not run). https://github.com/dolthub/dolt
9. treeverse/lakeFS repo: `pkg/graveler/graveler.go` (`Revert`), `errors.go`, `LICENSE` (BSL 1.1). Primary (code). https://github.com/treeverse/lakeFS (docs page for revert could not be fetched).
