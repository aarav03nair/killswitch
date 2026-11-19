"""B3-24 world fixture: the real ks.world F2+ run driven through the real ``ks.gateway.Gateway``, in process.

Same code path as ``ks.runtime.run`` (``Gateway`` + ``Recorder`` + ``RunDir`` + ``ks.state`` store + seed record
D-SEQ1 + ``WorldPolicy`` + ``WorldDispatcher`` as tools and view provider), minus sockets, agent subprocesses,
uids and the witness. Each tick, exactly like the runtime barrier and ``ks.runtime.agent_template``:

    Gateway.open(t)        seed record (t = 0), outbox release phase (ks.dispatch / ks.control hold), views
    agent step             ks.world.agents.step(agent, seed, t, TickFrame.view, Schedule(h)); epoch None -> no-op
    sign + frame           Envelope signed with the agent's key, nonce draw_hex(seed, "nonce/<agent>", t),
                           expiry t + 2, SubmitFrame on the agent's own connection c-<i+1>
    Gateway.tick(t)        admission in agent_id order, state txn, read set = merge_read_set(view, tool),
                           Outbox.create (id, idempotency_key, lineage, G3 release_tick), hold at creation

So outbox items, their lineage, release ticks and every hold/dispatch are the gateway's, not this file's.

Containment stand-in (ks.containment B3-19/B3-20 is not wired into the gateway yet): at ``contain_at`` (before
``open``) this file appends the ``ks.control`` suspend record signed by ``ks.monitor`` on c-0, sets crm's epoch to
``None`` in the gateway's ``StaticControl`` and installs a ``TaintView`` on the gateway's outbox that recomputes
``ks.taint.taint_from_alerts`` over the record as it grows (one alert: crm's IBAN version). From then on the
release phase holds every due item whose lineage touches a tainted version (``lineage_hold``) and items created
with a tainted lineage are held at creation.

``hold`` = ``RunConfig.hold_window_ticks``. Default 3 with 40 ticks (h + QUIET_TICKS): the tainted payment of
h + 2 is due at max(h+2+3, h+2*3) = h + 6 inside the run, so the test sees the release phase hold it. At the demo
H = 6 it is due at h + 12 = 42, after crm's quiet window ends; a run that long cannot be compared object by object
with S* (crm is suspended in F2+ but keeps working in S*), so ``test_rerun`` checks H = 6 for holds only.
``sstar`` = the same seed with the fault off and no containment (S*, the oracle).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ks.contracts import (CONTRACTS_VERSION, CONTROL_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS, ActionClass, Alert,
                          AlertKind, Control, ControlOp, Decision, Envelope, ObjVer, OutboxItem, Reason, Record,
                          RunConfig, RunDir, SubmitFrame, args_hash, encode_frame)
from ks.gateway import Gateway, InFrame, StaticControl
from ks.identity import KeyStore, sign_hex
from ks.policy import WorldPolicy
from ks.recorder import Recorder
from ks.rng import draw_hex
from ks.taint import Taint, taint_from_alerts
from ks.world.agents import AGENT_IDS, QUIET_TICKS, Schedule, step
from ks.world.registry import SENSITIVE_FIELDS
from ks.world.scenario import open_world_store, seed_state
from ks.world.tools import WorldDispatcher

H = 30
SEED = 11
HOLD = 3
TICKS = H + QUIET_TICKS
CONTAIN_AT = H + 3
IBAN = "suppliers:S-17.iban"
S22 = "suppliers:S-22"
CULPRIT = "crm"
EXPIRY_TICKS = 2  # as ks.runtime.agent_template
SECRET = b"b3-24 test secret, not a security run"


def alert(evidence: list[ObjVer], seq: int) -> Alert:
    return Alert(alert_id="a-000001", tick=1, seq=seq, detector="inv.beneficiary_changed_then_paid",
                 kind=AlertKind.INVARIANT, hard=True, evidence_seqs=(seq,),
                 evidence_versions=tuple(sorted(evidence, key=lambda v: (v.obj, v.ver))), root_candidates=(),
                 conn_id=None)


class LiveTaint:
    """``TaintView`` for the gateway's outbox: the forward closure over the record so far (recomputed when a record
    lands), seeded by one alert. Conservative: a version read by a tainted reader is tainted as soon as it lands."""

    def __init__(self, recorder: Recorder, al: Alert):
        self.recorder, self.alert = recorder, al
        self._at, self._t = -1, None

    def taint(self) -> Taint | None:
        if self._at != self.recorder.seq:
            self._t = taint_from_alerts(list(self.recorder.rundir.records()), [self.alert])
            self._at = self.recorder.seq
        return self._t

    def is_tainted(self, obj: str, ver: int) -> bool:
        t = self.taint()
        return t is not None and t.is_tainted(obj, ver)


@dataclass
class World:
    gateway: Gateway
    store: Any
    rundir: RunDir
    args: dict[str, dict[str, Any]]
    hold: int
    taint: Taint | None = None
    log: dict[tuple[int, str], Record] = field(default_factory=dict)
    """(tick, agent) -> that agent's exec record."""

    @property
    def records(self) -> list[Record]:
        return list(self.rundir.records())

    @property
    def next_seq(self) -> int:
        return self.gateway.recorder.seq + 1

    def items(self) -> dict[str, OutboxItem]:
        return {d.item.outbox_id: d.item for d in self.gateway.outbox.items()}

    @property
    def payloads(self) -> dict[str, str]:
        """action_id -> payload hash of its first outbox item (the gateway's ``OutboxItem.payload_hash``)."""
        out: dict[str, str] = {}
        for it in sorted(self.items().values(), key=lambda i: i.outbox_id):
            out.setdefault(it.action_id, it.payload_hash)
        return out


def _suspend(g: Gateway, keys: KeyStore, tick: int, agent: str) -> Record:
    """The containment record ks.containment will write (B3-19/20): ks.monitor suspend of agent:<agent> on c-0."""
    c = Control(control_id="k-000001", op=ControlOp.SUSPEND, target=f"agent:{agent}", epoch=1,
                alert_id="a-000001", issued_by="ks.monitor", auto=True, reason="hard_alert")
    env = Envelope(agent_id="ks.monitor", action_id=c.control_id, parent_action_id=None, act_chain=(),
                   tool=CONTROL_TOOL, args=c.to_obj(), nonce="1" * 32, expiry_tick=tick, epoch=0,
                   claimed_ts_us=None, claimed_seq=None, sig=None)
    env = env.with_sig(sign_hex(keys.private("ks.monitor"), env.signing_bytes()))
    cfg = g.config
    return g.recorder.append(tick=tick, ts_us=cfg.start_ts_us + tick * cfg.tick_us, conn_id=SYSTEM_CONN,
                             envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True,
                             decision=Decision.EXEC, reason=Reason.OK, policy_rule="hard_alert_suspend",
                             action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                             control=c, reexec_of=None)


def run(path: Path, *, fault: str | None = "f2plus", ticks: int = TICKS, contain_at: int | None = CONTAIN_AT,
        hold: int = HOLD) -> World:
    """``path`` is the state db; the run dir is ``<path>.run``. ``fault=None`` is S* (no containment)."""
    cfg = RunConfig(run_id=f"b324-{fault or 'sstar'}", contracts_version=CONTRACTS_VERSION, seed=SEED,
                    scenario="world", fault=None, culprit=None, fault_tick=None, key_mode="repro",
                    decision_latency_ticks=0, ticks=ticks + 1, tick_us=1000, start_ts_us=0, hold_window_ticks=hold,
                    sensitive_fields=SENSITIVE_FIELDS, agents=AGENT_IDS)
    keys = KeyStore.create(sorted(SYSTEM_PRINCIPALS | set(AGENT_IDS)), key_mode="repro", seed=SEED,
                           secret=SECRET)  # repro keys: two runs give byte-identical records
    ring = keys.keyring({})
    rd = RunDir.create(Path(f"{path}.run"), cfg, ring)
    ctl = StaticControl({a: 0 for a in AGENT_IDS})
    store = open_world_store(path)
    g = Gateway(cfg, ring, Recorder(rd, keys.signer("ks.gateway")), control=ctl, dispatcher=WorldDispatcher(),
                store=store, seed=lambda s, q: seed_state(s, seq=q), sign=keys.signer("ks.gateway"),
                policy=WorldPolicy())
    conn = {a: f"c-{i + 1}" for i, a in enumerate(AGENT_IDS)}
    w = World(gateway=g, store=store, rundir=rd, args={}, hold=hold)
    sched = Schedule(H, fault)
    al = None
    for t in range(ticks + 1):
        if fault is not None and contain_at is not None and t == contain_at:
            al = alert([ObjVer(obj=IBAN, ver=store.history(IBAN)[-1].ver)], seq=g.recorder.seq)
            _suspend(g, keys, t, CULPRIT)
            ctl.epochs[CULPRIT] = None
            ctl.agents[CULPRIT] = Reason.SUSPENDED
            g.outbox.taint = LiveTaint(g.recorder, al)
        tf = g.open(t, AGENT_IDS)
        frames = []
        for a in AGENT_IDS:
            f = tf[a]
            act = step(a, SEED, t, f.view, sched)
            if act is None or f.epoch is None:  # agent_template: no action, or no live credential -> no-op
                continue
            env = Envelope(agent_id=a, action_id=act.action_id, parent_action_id=None, act_chain=(), tool=act.tool,
                           args=act.args, nonce=draw_hex(SEED, f"nonce/{a}", t), expiry_tick=t + EXPIRY_TICKS,
                           epoch=f.epoch, claimed_ts_us=None, claimed_seq=None, sig=None)
            env = env.with_sig(sign_hex(keys.private(a), env.signing_bytes()))
            w.args[args_hash(act.args)] = act.args
            frames.append(InFrame(a, conn[a], encode_frame(SubmitFrame(tick=t, envelope=env))))
        g.tick(t, frames)
    for r in w.records:
        e = r.envelope
        if e is not None and e.agent_id in AGENT_IDS and r.decision == Decision.EXEC:
            w.log[(r.tick, e.agent_id)] = r
    if al is not None:
        w.taint = taint_from_alerts(w.records, [al])
    return w
