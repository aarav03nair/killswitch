# RES-01: Selective undo and intrusion recovery prior art (Retro, Warp, Aire, Taser)

Owner: meera. Read 19 Nov 2026. All papers read via the PDF URLs in Sources (full text fetched, summarised by tool; numbers below are as extracted and quoted from the papers, please spot-check before they go in front of a jury).

## 1. TL;DR

- The thesis holds for the *mechanism*: four systems (Taser 2005, Retro 2010, Warp 2011, Aire 2013) undo one actor's damage while keeping later legitimate work, using a recorded dependency graph plus selective rollback and re-execution of only the affected actions. [Fact]
- Their key assumption is **deterministic, re-runnable actors** (or recorded non-determinism). An LLM agent is neither, so "re-execute the benign agents on repaired inputs" cannot be done the same way. [Our view]
- The transferable part is the **graph and the taint/repair planning**. The part that does not transfer is **replay**: for agents the repair step should be "re-plan and re-approve", not "replay and compare". [Our view]
- Every system hits the same wall at **external effects** (network, terminal, other services): they flag them and ask a human or send a compensating message. This links straight to RES-02. [Fact]
- None of these systems covers a multi-agent setting, and all assume the log itself is trusted. [Fact, see limitations in 2.1-2.4]

## 2. Findings

### 2.1 Retro (Kim, Wang, Zeldovich, Kaashoek; OSDI 2010) [1]
1. [Fact] Records a system-wide **action history graph**: data objects (files) and actor objects (processes) with actions inside actors; object state is kept as checkpoints (can reuse btrfs snapshots); read data is stored as SHA-1 hashes [1].
2. [Fact] Repair replaces the attack action with a benign one (no-op, zero-byte write, `/bin/true`), rolls back affected objects, and re-executes only actions whose inputs changed. Each action has an `equiv()` check to decide whether re-execution is needed [1].
3. [Fact] Dependencies can be refined to finer-grained objects (a directory entry vs its inode) to avoid false dependencies such as on `/tmp` [1].
4. [Fact] When a re-executed process diverges, syscalls are matched greedily in order; new ones become new actions, missing ones become no-ops. Worst case is more re-execution, correctness preserved [1]. Where no compensating action exists, repair pauses and asks the administrator [1].
5. [Fact] Limits: single machine; admin must identify the intrusion point; logs/checkpoints must not be compromised or garbage-collected before detection [1].
6. [Fact] Overhead: "89-127% runtime overhead" and "100-150 GB of log space per day" on extreme workloads; HotCRP 35% CPU and about 4 GB/day [1].

### 2.2 Warp (Chandra, Kim, Shah, Narula, Zeldovich; SOSP 2011) [2]
1. [Fact] Records a **time-travel database** (every row version with start/end time), HTTP requests/responses with the PHP files each run loaded, and browser DOM events via an extension [2].
2. [Fact] Dependencies: read queries are re-run only if they touch partitions changed by rollback; if a WHERE clause cannot limit partitions it is assumed to read all. A re-executed query whose results change causes the page visit that issued it to be re-executed [2].
3. [Fact] **Retroactive patching**: admin supplies a patch and time; runs whose output changes under the patched code are treated as attacks and re-executed. Repair runs in a new "repair generation" so the site stays online [2].
4. [Fact] Non-determinism (time, random, session IDs) is **recorded with return values** and matched to the original call from the same call site, in order. The paper says this matching is "strictly an optimization" [2].
5. [Fact] User-level conflicts are queued and shown at that user's next login, where they can cancel the page visit [2].
6. [Fact] Cannot undo data disclosure; attacks on the HTTP server, DB, runtime and log tampering are out of scope [2].
7. [Fact] Overhead: throughput 8.46 to 6.43 page visits/s (24%) reading and 7.19 to 5.26 (27%) editing; 3.71 KB/visit read, 7.34 KB/visit edit (about 2 GB/day and 3.2 GB/day at 100% load) [2]. Repair of an isolated attack on 100 users takes "an order of magnitude less time" than original execution; when everything must be re-executed it takes about an order of magnitude longer [2].

### 2.3 Aire (Chandra, Kim, Zeldovich; SOSP 2013) [3]
1. [Fact] Extends Warp-style repair across **interconnected services**. Every HTTP request/response in and out gets an identifier in a header so later repair can name it [3].
2. [Fact] Repair is **asynchronous**: a service repairs local state immediately and queues repair messages to others, without a central coordinator. Four repair operations: replace/delete request, create request, replace_response [3].
3. [Fact] Consistency model: repair should be "indistinguishable from concurrent requests issued by some client on the present state of the system" [3].
4. [Fact] **Repair is authorized**: each repair call carries credentials and a service-defined `authorize` function decides; the example policy allows repair only on behalf of the same user who made the original request [3].
5. [Fact] Overhead: "CPU overhead of 19% and 30%", 5.52 KB and 9.24 KB per request; unoptimised repair about 10x slower per request than normal execution [3].

### 2.4 Taser (Goel, Po, Farhadi, Li, de Lara; SOSP 2005) [4]
1. [Fact] Auditor logs names and arguments of syscalls for processes, files and sockets to a **separate backend**, so logged information "cannot be destroyed easily" [4].
2. [Fact] Taint analysis from detection points: backward to find attack sources, forward to mark affected objects; the resolver reverts only tainted objects and replays legitimate operations on them [4].
3. [Fact] **Policy tradeoff**: optimistic policies have few false positives but can miss attacker operations; conservative ones have few false negatives. Conflicts are isolated for manual review rather than deleted [4].
4. [Fact] The paper does not discuss non-determinism directly; the resolver "does not know the semantics of the processes that issued the legitimate operations" [4].
5. [Fact] Overhead: kernel compile 0.6%; Webstone 258.3 to 239.2 Mbs; backend about 1.9 GB/day; propagation and recovery under 5 minutes one day after an attack but possibly over an hour after a week [4].

### 2.5 GoEx (Patil et al., arXiv 2404.06921, Apr 2024) [5]
1. [Fact] Argues post-facto validation of LLM actions depends on "an intuitive undo feature, and establishing a damage confinement" [5]. The abstract page I read gives no detail on what is recorded or on dependency tracking; I did not read the full paper or blog. Not found: any record of other-agent dependencies.
2. [Our view] GoEx undoes a single action; it has no graph, so it cannot answer "what did others build on this".

## 3. Comparison table

| System | What is recorded | Dependency tracking | Legitimate work preserved by | Non-determinism | Overhead (as reported) |
|---|---|---|---|---|---|
| Taser [4] | Syscall names and args (process, file, socket) in a remote audit log | Taint rules over kernel objects, backward then forward | Revert tainted objects only, replay legit ops; optimistic/conservative policies | Not discussed; no process semantics | Kernel build 0.6%; ~1.9 GB/day; recovery under 5 min a day after attack |
| Retro [1] | Per-syscall action history graph, SHA-1 of reads, checkpoints | Object/actor graph, refined to fine-grained objects | Selective re-execution of actions whose `equiv()` fails | Greedy syscall matching; compensating actions; ask admin | 89-127% runtime and 100-150 GB/day worst case; HotCRP 35% CPU, ~4 GB/day |
| Warp [2] | Row-versioned DB, HTTP I/O, browser DOM events | Partition-level query deps; global graph | Re-run only affected page visits in a repair generation; 3-way merge of user input | Record return values of time/random/session ID and match by call site | 24-27% throughput drop; 3.7-7.3 KB/visit |
| Aire [3] | Warp logs plus a message ID on every cross-service request/response | Message IDs across services | Async repair messages, each authorized | Record and replay as in Warp | 19-30% CPU; 5.5-9.2 KB/request |
| GoEx [5] | Not stated in material I read | None described | Per-action undo / damage bound | n/a | Not found |

## 4. What breaks when the re-executed actor is a non-deterministic LLM agent

Everything below is [Our view] unless tagged.

1. **Replay equivalence is gone.** Retro's `equiv()` and Warp's "re-run only if inputs changed" assume the same inputs give the same outputs. [Fact: Aire states local repair is stable only if re-execution is deterministic, and gets this by recording sources of non-determinism [3]]. An LLM re-run with identical inputs can emit different tool calls, so "unchanged" cannot be proved by replay.
2. **Recording sampling is not enough.** Warp records return values of time/random calls [2]; an LLM call is far larger and its output depends on the whole context. Recording and replaying the model's *outputs* is possible, but only reproduces the old (possibly poisoned) behaviour, so it is no use for "what would B have done without A's bad write".
3. **Divergence cascades.** Retro/Warp divergence costs only extra re-execution and keeps correctness [1][2]. An agent that re-plans may take new actions with new side effects, so repair itself can cause damage.
4. **Dependencies are semantic, not data-flow.** Syscall and SQL reads give exact read sets. For an agent, the context window mixes everything; B "read" A's output could mean a tool call we logged, or text pasted through memory/summary. Over-approximation (taint everything B saw after A's write) is the safe default and is the same trade as Taser's conservative policy [4].
5. **No trusted semantics for the resolver.** Taser's resolver cannot predict what a process would have done without tainted operations [4]; for agents, only a human or another model could.
6. **Repair actions need authority.** Aire's authorized-repair idea [3] carries over; otherwise a repair is just another agent action.
7. **Log trust.** Warp excludes log tampering [2] and Retro assumes logs are not compromised [1]. An agent writing to its own log breaks this; Taser's separate backend [4] is the precedent to follow.

Net: [Our view] treat undo as **taint, quarantine, revert, then re-plan** (H1 is half right: graph and selective rollback transfer; selective re-execution does not).

## 5. Implications for our design

**Recorder (build):** the minimal dependency data per action record:
- `action_id`, `agent_id`, `parent_action_id` / delegation chain and `authority` (token/scope) used (Aire's authorize needs it [3]).
- **Write set**: object IDs and before/after versions or content hashes (Retro hashes [1], Warp row versions [2]); object granularity as fine as the store allows (Retro/Warp refinement).
- **Read set**: object IDs and the **version read** (hash), including tool outputs and messages from other agents. This is the edge that makes "B depended on A" computable.
- **Message IDs** on every inter-agent and tool call, stored by both sides (Aire [3]).
- **Effect class** and compensation handle for external effects (feeds RES-02; Retro/Aire both queue these for a human or peer).
- Recorded non-deterministic inputs (model ID/params, timestamps, random seeds) so a replay is at least possible (Warp [2]), and a hash of the model output.
- Append-only, stored outside the agents' write reach (Taser backend [4]); tamper evidence is RES-04's job.

**Recovery (build):** from the quarantined agent's writes, taint forward through read-set edges (Taser/Retro style), revert only tainted object versions, keep untouched versions. Offer **conservative vs optimistic** policy as a switch and report the false-positive/negative trade [4]. Do not re-run agents; hand "tainted work items" to the owning agents to re-plan, with human approval (Warp's conflict queue [2]).

**Avoid:** LLM-judge replay equivalence; reusing OS-level syscall tracing (overhead and wrong abstraction level).

**Evaluation harness:** the old papers report log bytes per unit work and time-to-repair vs original time; copy those metrics (e.g. KB per action, repair time vs tainted fraction).

## 6. Implications for framing
- [Fact] Selective recovery with legitimate work preserved was demonstrated in 2005-2013 for OS and web apps [1]-[4]; not found: a published equivalent for LLM agent networks in the sources I read.
- [Fact] Costs on record: Warp about 24-27% throughput drop [2], Aire 19-30% CPU [3]; logging is not free but was accepted for repair.
- [Our view] "Kill switch is easy; selective undo needs a dependency graph" is supported by what these systems had to record.

## 7. Open questions
- Whether GoEx's full paper or blog describes anything beyond single-action undo (I read only the arXiv abstract page). RES-02.
- Dare and other follow-ups named in PLAN.md were not read; not needed for the table, not verified.
- Retro venue: PLAN.md says OSDI'10; the PDF I fetched did not state a venue. Title confirmed as "Intrusion Recovery Using Selective Re-execution". Check the ACM/USENIX listing before citing the venue.
- How to bound read sets for LLM context (what counts as "B read A")? RES-04 / Sprint 2 ADR.
- Evidence on LLM failure attribution accuracy: RES-07.

## 8. Sources (all primary papers)
1. Kim, Wang, Zeldovich, Kaashoek, "Intrusion Recovery Using Selective Re-execution" (Retro), OSDI 2010 (venue per PLAN.md). https://people.csail.mit.edu/nickolai/papers/kim-retro.pdf
2. Chandra, Kim, Shah, Narula, Zeldovich, "Intrusion Recovery for Database-backed Web Applications" (Warp), SOSP 2011. https://people.csail.mit.edu/nickolai/papers/chandra-warp.pdf
3. Chandra, Kim, Zeldovich, "Asynchronous intrusion recovery for interconnected web services" (Aire), SOSP 2013. https://people.csail.mit.edu/nickolai/papers/chandra-aire.pdf  (note: PLAN.md did not give the year; first page says SOSP '13)
4. Goel, Po, Farhadi, Li, de Lara, "The Taser Intrusion Recovery System", SOSP 2005. https://www.eecg.utoronto.ca/~ashvin/publications/sosp-2005.pdf
5. Patil et al., "GoEX: Perspectives and Designs Towards a Runtime for Autonomous LLM Applications", arXiv:2404.06921, 10 Apr 2024 (abstract page only). https://arxiv.org/abs/2404.06921
