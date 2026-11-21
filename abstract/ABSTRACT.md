**Working draft for Aarav to rewrite in his own words. Do not submit as is.** SEED requires the abstract to be written by the entrant and runs AI-text checks. Every number below is from `abstract/ALLOWED-NUMBERS.md` (BENCH-S3, T = 40 ticks, 20 seeded runs); keep the conditions next to each one when you rewrite.

# Kill Switch: undo one agent's damage without losing everyone else's work

## The problem

Ten AI agents share one workspace. One of them writes something wrong. The obvious response is to stop that agent and undo what it did. But by the time anyone notices, other agents have already read the bad data and built on it, so "undo that agent" no longer has a clear meaning.

A small example. Ten agents run a small company. The CRM agent writes a wrong bank account number for a supplier. The billing agent drafts an invoice from it, the payments agent queues a transfer to it, and the messaging agent emails the supplier. Meanwhile the triage agent adds an unrelated note to the same supplier record. Which of these actions are damage, and which are honest work that must survive?

Today's options are blunt. A kill switch stops agents but repairs nothing. A snapshot restores everything and throws away every agent's work since. And the logs are usually written by the agents themselves, so they are testimony, not evidence: a misbehaving agent can write whatever it likes about itself.

## Our fix

We treat this as a provenance problem: every write has a known author, and every read has a known source. If both are recorded in a way no agent can quietly change, then finding the culprit, stopping it and repairing its damage become questions you can answer from the record.

Every agent action goes through one gateway. Each agent runs as its own isolated process and holds no keys. Each action is signed under that agent's identity, checked against policy, classed by whether it can be reversed, and recorded together with exactly what it read and wrote. The record is hash-chained, and a separate witness process signs its head every tick. One command re-checks the whole record, so it is tamper-evident up to the last witnessed head.

**Identify.** Detectors look at the data itself, such as a bank account that fails its check or a price ten times its history. The signed record then names the agent that wrote the bad value.

**Contain.** That agent is suspended, and even actions it signed in advance are refused. Any payment or email whose inputs trace back to the bad write is held before it leaves. The other agents keep working.

**Recover.** The system reverts only the bad writes and re-runs the honest steps that depended on them, using an outbox that never sends the same payment twice. A person approves the plan after seeing a dry-run diff. In the example, the bank account and price are restored, the invoice, payment and email are redone on clean data, and triage's note is kept. Effects that already left are reported or compensated, never claimed undone.

When two honest edits collide on the same record, the system flags the conflict for a person by default. An optional resolver can settle simple cases itself; every resolution is signed, re-checked by the verify command, and can be undone as a recorded step until a payment or email that depended on it is released.

## Why it matters

Recovery is scored, not asserted. For every run we replay the same scenario with the fault switched off and compare the two end states. Residual damage R is the share of bad effects left behind; collateral loss C is the share of honest work lost. The scorer applies the rules itself and does not trust our own record.

We measured this over 20 seeded runs of our simulated ten-agent company, 40 ticks each. Recovery is not told which agent is at fault or when. On our main fault scenario (median over 20 seeds): the alert came within 2 ticks of the bad write, the culprit was named from the signed record at the same tick, and it was suspended 1 tick later. Residual damage was 0 on all 20 runs, after the operator released a median of 5 held items. Collateral loss was 0 in this scenario, where the culprit makes no other writes before suspension. No tainted payment or email left after the alert.

We compared this with our own baselines, which were told the culprit. Restoring a snapshot left 3/5 of the damage and lost honest work. Reverting only the culprit also left 3/5. Holding dependent payments matters too: when we paused the culprit without recovery and without that hold, a median of 12 tainted payments went out; with the hold, none did.

When honest agents edit the same record as the culprit, the default run leaves residual damage of 1/5 for a person to decide. With the resolver on, residual damage was 0 after a median of 5 operator releases, and every run passed verification.

We also tried to break it ourselves: we switched off each of 12 defences one at a time, and our red-team tests caught all 12.

## Limits, and what we will show

Our agents are deterministic programs, not language models, so every run can be replayed and scored; the gateway does not depend on what kind of agent sits behind it. We cannot reverse a payment or email that has already left. We hold more than strictly necessary, which costs a median of 3 honest items held per run. Agents that collude can be named as suspects, not prevented.

At the finale we will run the scenario live and invite the jury to break it: run arbitrary code inside a rogue agent, edit the record, or change the database behind the gateway, and watch the verify command catch it.
