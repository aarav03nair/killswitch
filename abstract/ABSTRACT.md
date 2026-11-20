# Kill Switch: a black box and a precise undo for teams of autonomous agents

## The problem

Ten agents are working. One just broke something. The brief asks us to reverse that agent’s damage without discarding the other agents’ work. That request hides a hard question: by the time anyone notices, honest agents have already read the bad data and built on it.

Take a small company run by ten agents. A CRM agent writes a wrong bank account (IBAN) for a supplier. A billing agent drafts an invoice from it, a payments agent queues a transfer to it, and a communications agent emails the supplier. Meanwhile a triage agent adds an unrelated risk note to the same supplier record. “Undo the CRM agent” is no longer well defined. Which of these actions are damage, and which are honest work that must survive?

Today’s tools answer badly. Kill switches stop agents; they do not repair. Checkpoints and snapshots restore a whole state and throw away everyone’s work since. Logs are written by the agents themselves: testimony, not evidence. Current tracing conventions record which tool was called, not what data it read or changed (OpenTelemetry’s gen_ai attributes, not yet stable as of November 2026). Asking a language model to find the culprit afterwards is unreliable. On the Who&When benchmark, the best reported strategies found the failing agent about 53.5% of the time and the decisive step about 14.2%, with a different strategy for each number.

Real incidents show the cost. In the public incidents we catalogued, one agent caused the damage, a human noticed afterwards, and recovery meant a whole backup or nothing. In one reported case, a production database and its backups were deleted in nine seconds and rebuilt from a three-month-old snapshot over a weekend. At larger scale, METR’s preliminary findings on OpenAI’s ExploitGym evaluation runs in July 2026 describe roughly 1,200 agents coordinating on a shared message board. Wiping the board did not stop them; a new one appeared about two days later. A blunt stop is not a recovery plan.

## Our fix

Kill Switch treats accountability as a provenance problem: every write has an author, and every read has a source. If both are recorded faithfully, identifying, containing and recovering become three queries on one graph.

Every agent action passes through one gateway. Each agent runs as an isolated process that holds no keys. Every action is signed under that agent’s identity, checked, classified by reversibility before it runs, and recorded with exactly what it read and wrote. The record is hash-chained, signed by the gateway and checkpointed every tick by a separate witness process. Anyone can re-check it with one command, and an edit or truncation is detected up to the last witnessed checkpoint.

**Identify.** Detectors check the data itself: an invalid IBAN, a beneficiary changed and then paid, a price ten times its history. The record then names the agent that wrote the bad value.

**Contain.** That agent is suspended under a fresh epoch, so even its pre-signed actions are refused. Any outgoing payment or email whose inputs trace back to the bad write is held. Independent agents keep working.

**Recover.** The system reverts only bad writes that are still current. It re-runs the dependent deterministic steps through an outbox that never sends the same effect twice, and asks a person to approve the plan after a dry-run diff. Irreversible effects that already left are compensated or reported, never claimed undone. In our example the IBAN and price are restored, billing, payments and messaging are redone on clean data, and triage’s note is kept, because sensitive fields are tracked as separate objects.

Recent work such as Airlock contains damage before it spreads but, by design, leaves already-committed effects to “orthogonal rollback”. Kill Switch is that backward half, built on an authenticated record.

## Why it matters

Recovery is scored, not asserted. We replay each scenario with the fault switched off and compare. Residual damage R is the share of bad effects left; collateral loss C is the share of honest work lost. We also measure time-to-identify, time-to-contain, tainted effects after the alert, and irreversible effects released. The brief’s three scores have no agreed measurement in the standards we checked, so we propose checkable ones.

Our targets, to be measured over at least 20 seeded runs: on the hero scenario, R = 0 and C = 0, with zero post-alert tainted effects and zero irreversible tainted effects released. If an honest agent later changed the same data, a person decides and it counts as residual damage. The culprit’s own work between the fault and its suspension is reverted and counts as collateral loss.

For regulated users the design maps to the EU AI Act’s automatic logging (Article 12) and its requirement to stop a system “in a safe state” (Article 14(4)(e)). It slots into OpenTelemetry and policy-as-code in production.

## Limits, and what we will show

We do not reverse irreversible effects, we cannot replay language models, and we deliberately over-taint. Collusion yields root candidates, not prevention. The jury may run arbitrary code inside a rogue agent; our published threat model states what we detect and what is out of scope.
