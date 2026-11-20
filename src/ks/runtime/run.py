"""``ks run``: build config and keys, spawn the witness and the agents, drive the tick barrier, tear down by
uid, print the RunAnchor (ADR-00, ADR-02 §4)."""

from __future__ import annotations

import os
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ks.contracts import (CONTRACTS_VERSION, SYSTEM_PRINCIPALS, RunAnchor, RunConfig, RunDir, canonical)
from ks.contracts.rundir import ALERTS, STATE_DB, TIMING, WITNESS, WITNESS_HEADS_DIR
from ks.gateway import Gateway
from ks.gateway.control import FoldedControl
from ks.gateway.system import SystemQueue
from ks.identity import KeyStore, SignerService, derive_key_bytes, load_repro_secret
from ks.recorder import Recorder
from ks.witness import WitnessLink, open_witness_fds

from .barrier import AgentConn, TickBarrier
from .operator import OperatorServer
from .options import RunOptions
from .spawn import (WITNESS_UID, agent_uid, kill_uids, pids_with_uids, plan_agent_uids, proc_uid, set_nondumpable,
                    set_oom_score_adj, spawn_child)
from .setup import (IsolationError, check_run_id, default_run_id, isolation_problems, refuse_existing,
                    scenario as _scenario)

__all__ = ["Isolation", "RunResult", "AlertTaint", "DEMO_HOLD", "run", "agent_ids", "pause_ticks", "STARTUP_GRACE_S"]

STARTUP_GRACE_S = 15.0
"""Tick 0 waits at least this long: there is no readiness handshake, and an agent's first frame comes only
after its interpreter has imported the contracts (ADR-00 gap, see SKEL-01 notes)."""
TICK_US = 1000
SYSTEM_SLOTS = 32 + 32
"""Control-phase plus dispatch records per tick (ADR-00 C7 cap)."""


def agent_ids(n: int) -> tuple[str, ...]:
    return tuple(f"agent_{i:02d}" for i in range(n))


@dataclass
class Isolation:
    """What the uid boundary actually gave this run (read back from /proc, not assumed)."""

    separate_uids: bool
    agent_uids: dict[str, int | None] = field(default_factory=dict)
    witness_uid: int | None = None

    @property
    def agents_unprivileged(self) -> bool:
        """Every agent verifiably runs under a non-root uid different from ours (shared among them is fine)."""
        uids = list(self.agent_uids.values())
        return bool(uids) and None not in uids and 0 not in uids and os.geteuid() not in uids

    @property
    def per_agent_attribution(self) -> bool:
        uids = list(self.agent_uids.values())
        return (self.separate_uids and None not in uids and 0 not in uids and len(set(uids)) == len(uids)
                and self.witness_uid not in uids)

    def banner(self) -> list[str]:
        uids = " ".join(f"{a}={u}" for a, u in self.agent_uids.items())
        if self.per_agent_attribution:
            return [f"isolation: per-agent uids ({uids}), witness uid {self.witness_uid}"]
        out = [f"isolation: DEGRADED ({uids}, witness uid {self.witness_uid})",
               "  per-agent attribution is VOID for this run (shared or unverified agent uids, RT3b)"]
        if self.agents_unprivileged:
            out.append("  agents share one unprivileged uid; the gateway keeps its own (never uid 0 for agents)")
        else:
            out.append("  gateway uid shared with agents: C1/C4 degrade (key reads are the admitted gap, RT2)")
        return out


@dataclass
class RunResult:
    rundir: RunDir
    anchor: RunAnchor | None
    isolation: Isolation
    stalls: int
    misses: int


def run(*, agents: int | None, ticks: int, seed: int, key_mode: str, out: str | os.PathLike[str],
        repro_secret: str | os.PathLike[str] | None = None, tick_deadline_ms: int = 2000,
        separate_uids: bool | None = None, run_id: str | None = None, scenario: str = "skeleton",
        say: Callable[[str], None] = lambda s: print(s, flush=True),
        options: RunOptions | None = None, _force_agent_uids: list[int] | None = None) -> RunResult:
    """Run ``scenario`` (``skeleton`` or the 10-agent ``world``, B3-10). ``separate_uids=None`` means "if root".
    Raises ValueError on bad arguments, FileExistsError if ``out`` exists, RuntimeError if the environment refuses
    (stray processes under our uids) and IsolationError if the /proc readback contradicts RunConfig.isolation
    (before tick 0). ``_force_agent_uids`` is a test hook that spawns agents under other uids than planned, to
    prove the readback abort; it is not reachable from the CLI. ``options`` carries the scenario knobs (B3-12);
    any field not yet served raises NotImplementedError before anything is created or spawned."""
    if options is not None and not isinstance(options, RunOptions):
        raise TypeError("options must be a ks.runtime.RunOptions")
    if options is not None and (todo := options.unserved()):
        raise NotImplementedError(f"runtime does not serve {', '.join(todo)} yet")
    if (agents is not None and agents < 1) or ticks < 1:
        raise ValueError("need at least one agent and one tick")
    replay = _load_replay(options)  # R3 (B3-20/B3-30): refused before anything is created or spawned
    sc = _scenario(scenario, agents=agents, seed=seed, ticks=ticks)
    spec = _fault_spec(options, sc.name, seed, ticks)  # B3-27; scorer-only ground truth (A3)
    rogue = _rogue(options, sc, key_mode)  # B3-35: (slot, source) or None; refused before anything is created
    hold = (options.hold if options is not None and options.hold is not None
            else (DEMO_HOLD if spec or rogue else 0))
    agent_argv = list(sc.agent_argv) + (["--variant", spec.variant] if spec and spec.variant != "f2plus" else [])
    ids = sc.agent_ids
    agents = len(ids)
    check_run_id(run_id)
    out = Path(out)
    refuse_existing(out)  # before anything is spawned
    secret = None
    if key_mode == "repro":
        if repro_secret is None:
            raise ValueError("--key-mode repro needs --repro-secret FILE")
        sp = Path(repro_secret).resolve()
        if sp == out.resolve() or out.resolve() in sp.parents:
            raise ValueError("the repro secret must live outside the run dir")
        secret = load_repro_secret(sp)
    elif key_mode != "fresh":
        raise ValueError(f"unknown key mode {key_mode!r}")
    root = os.geteuid() == 0 and sys.platform == "linux"  # per-agent uids are Linux-only; else degraded
    separate = root if separate_uids is None else (separate_uids and root)
    # contracts 1.2: isolation is fixed before spawn and covered by config_hash (SKEL-01 finding 4); a /proc
    # readback that contradicts it aborts before tick 0 (B3-10, isolation_problems below).
    config = RunConfig(run_id=run_id or default_run_id(sc.name, seed), contracts_version=CONTRACTS_VERSION,
                       seed=seed, scenario=sc.name,
                       fault=_config_fault(spec.fault) if spec else ("rogue" if rogue else None),
                       culprit=spec.culprit if spec else (rogue[0] if rogue else None),
                       fault_tick=spec.t_inject if spec else (ticks // 4 if rogue else None),
                       key_mode=key_mode, decision_latency_ticks=0, ticks=ticks, tick_us=TICK_US, start_ts_us=0,
                       hold_window_ticks=hold,
                       lineage_hold=not (options is not None and options.no_lineage_hold),  # B3-51 D10 contrast
                       sensitive_fields=sc.sensitive_fields, agents=ids, isolation="per_agent_uid" if separate else "degraded",
                       decisions_from=replay.anchor_hash if replay is not None else None)
    if config.tick_us <= SYSTEM_SLOTS + agents:
        raise ValueError("tick_us must exceed the records-per-tick cap (C7)")
    a_uids = plan_agent_uids(root, separate, agents)  # root never runs an agent as uid 0 (S2)
    spawn_uids = list(_force_agent_uids) if _force_agent_uids is not None else a_uids
    our_uids = ([WITNESS_UID] if separate else []) + sorted({u for u in a_uids if u is not None})
    if root and pids_with_uids(our_uids):
        raise RuntimeError(f"processes already run under uids {our_uids[0]}..{our_uids[-1]} (K2): refusing")
    set_nondumpable()
    if root:
        set_oom_score_adj("self", -1000)

    keys = KeyStore.create(sorted((SYSTEM_PRINCIPALS - {"ks.witness"}) | set(ids)), key_mode=key_mode, seed=seed,
                           secret=secret)
    control = FoldedControl(ids)  # B3-13: epochs and deny-lists are the fold of executed ks.control records
    system = SystemQueue({p: keys.signer(p) for p in ("ks.gateway", "ks.monitor", "ks.operator", "ks.recovery")})
    conns: list[AgentConn] = []
    rogue_log: RogueLog | None = None
    store = None
    operator: OperatorServer | None = None
    witness: WitnessLink | None = None
    iso = Isolation(separate_uids=separate)
    try:
        # witness first: its public key goes into keys.json, so it exists before the run dir
        w_parent, w_child = socket.socketpair()
        wproc = spawn_child("ks.witness.server", [str(w_child.fileno())], uid=WITNESS_UID if separate else None,
                            pass_socks=[w_child], agent=False)
        w_child.close()
        if root:
            set_oom_score_adj(wproc.pid, -1000)
        witness = WitnessLink(w_parent, wproc)
        wpub = witness.init(derive_key_bytes(secret, seed, "ks.witness") if secret is not None else None)
        iso.witness_uid = proc_uid(wproc.pid)
        keyring = keys.keyring({"ks.witness": wpub})
        rd = RunDir.create(out, config, keyring, witness_uid=WITNESS_UID if separate else None,
                           witness_gid=WITNESS_UID if separate else None)
        wfd, hfd = open_witness_fds(rd.path / WITNESS, rd.path / WITNESS_HEADS_DIR)
        witness.attach(wfd, hfd)  # closes both of the gateway's descriptors
        dispatcher = sc.dispatcher()
        recovery = None
        if sc.name == "world":  # B3-30: ks.recover.<op> on c-0, bound to the operator's recorded ks.approve
            from .recover import RecoveryService
            recovery = RecoveryService(rd.path, keys.signer("ks.recovery"), dispatcher=dispatcher)
        operator = OperatorServer(rd.path, system, ids,  # J1; before any agent exists
                                  recover=recovery.requests if recovery is not None else None).start()

        say(f"ks run: run_id={config.run_id} seed={seed} agents={agents} ticks={ticks} key_mode={key_mode}")
        if key_mode == "repro":
            say("NOT A SECURITY RUN: repro keys (never anchored)")
        say(f"keyring_hash={keyring.content_hash()} config_hash={config.content_hash()}")
        say(f"operator socket: {operator.path} (peer uid {operator.allowed_uid} only)")

        for i, a in enumerate(ids):
            g_parent, g_child = socket.socketpair()
            s_parent, s_child = socket.socketpair()
            if rogue is not None and a == rogue[0]:  # B3-35: the jury's file in this slot, same uid, same handles
                x_parent, x_child = socket.socketpair()
                proc = spawn_child("ks.runtime.rogue",
                                   ["--agent", a, "--seed", str(seed), "--gw-fd", str(g_child.fileno()),
                                    "--signer-fd", str(s_child.fileno()), "--aux-fd", str(x_child.fileno())],
                                   uid=spawn_uids[i], pass_socks=[g_child, s_child, x_child], agent=True)
                x_child.close()
                rogue_log = RogueLog(x_parent, rogue[1], rd.path / ROGUE_LOG)
            else:
                proc = spawn_child("ks.runtime.agent_template",
                                   ["--agent", a, "--seed", str(seed), "--gw-fd", str(g_child.fileno()),
                                    "--signer-fd", str(s_child.fileno()), "--behaviour", sc.behaviour, *agent_argv],
                                   uid=spawn_uids[i], pass_socks=[g_child, s_child], agent=True,
                                   env={"KS_FAULT": spec.fault} if spec is not None and a == spec.culprit else None)
            g_child.close()
            s_child.close()
            conns.append(AgentConn(index=i, agent_id=a, conn_id=f"c-{i + 1}", gw=g_parent, signer=s_parent,
                                   proc=proc, uid=spawn_uids[i]))
            iso.agent_uids[a] = proc_uid(proc.pid)
        for line in iso.banner():
            say(line)
        problems = isolation_problems(config.isolation, a_uids, iso.agent_uids, iso.witness_uid,
                                      WITNESS_UID if separate else None, our_uid=os.geteuid())
        if problems:  # findings 1/12: never run a tick under an isolation the config does not describe
            raise IsolationError("isolation readback contradicts RunConfig.isolation="
                                 f"{config.isolation}, aborting before tick 0: " + "; ".join(problems))

        recorder = Recorder(rd, keys.signer("ks.gateway"))
        gkw: dict = {}
        if sc.name == "world":  # B3-41: the world runs over ks.state, with the seed record (D-SEQ1) and WorldPolicy
            from ks.policy import WorldPolicy
            from ks.world.scenario import open_world_store, seed_state
            store = open_world_store(rd.path / STATE_DB)
            gkw = dict(store=store, seed=lambda s, q: seed_state(s, seq=q), sign=keys.signer("ks.gateway"),
                       policy=WorldPolicy())
        gateway = Gateway(config, keyring, recorder, control=control, system=system, dispatcher=dispatcher,
                          **gkw)
        gateway.recovery = recovery
        signer = SignerService({a: keys.private(a) for a in ids}, control.epoch_of)
        barrier = TickBarrier(conns, gateway, signer, witness, tick_deadline_ms / 1000)
        timing, stalls, misses = [], 0, 0
        mon = None
        if options is not None and options.monitor:  # B3-19: alert -> suspend on c-0 inside the tick that raised it
            if store is None:
                raise ValueError("monitor needs the world scenario (a state store)")
            from ks.containment import MonitorLoop
            mon = MonitorLoop(gateway, keys.signer("ks.monitor"), state=store, side=store.side)
            gateway.outbox.taint = AlertTaint(recorder, mon)  # ADR-04 §5: tainted lineage is held from the alert on
        pauses = set(pause_ticks(options, ticks))
        pace = options is not None and options.pause_on_alert
        on_alert, n_applied = pace, 0
        if (pauses or pace) and sys.stdin is not None and sys.stdin.isatty():
            _keypress_resumes(operator.wake)
        for t in range(ticks):
            if replay is not None:  # R3: the source's operator decisions land in the control phase of their tick
                for req in replay.at(t):
                    system.put(req)
            if t in pauses and len(system) == 0:  # ADR-07 L1; a request already queued lands now, no pause (B3-19)
                operator.wake.clear()
                say(f"paused before tick {t}: press Enter, or ks contain / ks recover {rd.path}")
                operator.wake.wait()
                say(f"resumed at tick {t}")
            o = barrier.run_tick(t, deadline_s=max(STARTUP_GRACE_S, barrier.deadline_s) if t == 0 else None)
            if mon is not None:
                n_alerts = len(mon.alerts)
                adms = mon.step()
                if len(mon.alerts) > n_alerts:  # F6: alerts.jsonl is the monitor's copy of the chained ks.alert bodies
                    with open(rd.path / ALERTS, "ab") as f:
                        f.write(b"".join(a.to_canonical() + b"\n" for a in mon.alerts[n_alerts:]))
                if on_alert and t + 1 < ticks and any(
                        a.record is not None and a.record.control is not None and a.record.control.op.value == "suspend"
                        for a in adms):  # B3-27 pacing: the operator gets the run paused right after containment
                    on_alert = False
                    pauses.add(t + 1)
            if pace and recovery is not None and len(recovery.applied) > n_applied:
                n_applied = len(recovery.applied)  # B3-27 pacing: pause again after a recovery applied (unhold beat)
                if t + 1 < ticks:
                    pauses.add(t + 1)
            stalls += o.checkpoint is None and recorder.seq > 0
            misses += len(o.missed)
            timing.append(canonical.dumps_line({"tick": t, "wall_us": o.wall_us, "missed": o.missed,
                                                "witness_ack": o.checkpoint is not None}))
        rd.write(TIMING, b"".join(timing))
    finally:
        if operator is not None:
            operator.close()  # first: no operator request is admitted after the last tick
        _teardown(conns, witness, our_uids)
        if rogue_log is not None:
            rogue_log.close()
        if store is not None:
            store.close()

    last = witness.newest if witness is not None else None  # newest verified ack, late ones drained at close (M1)
    anchor = RunAnchor.of(last, keyring, config) if last is not None else None
    if stalls or misses:
        say(f"warnings: {misses} deadline misses, {stalls} witness stalls")
    if operator is not None:  # RT3c evidence (kabir, B3-13): refused peers live in memory only, never on c-0
        n_peer = sum(1 for _, why in operator.refused if why == "peer_uid")
        say(f"operator socket: {n_peer} refused peers, {len(operator.refused) - n_peer} refused requests")
    if anchor is None:
        say("no witnessed head: nothing to anchor")
    else:
        say("RunAnchor (copy into ks verify --head):")
        say(anchor.to_canonical().decode())
    return RunResult(rd, anchor, iso, stalls, misses)


ROGUE_LOG = "rogue.jsonl"
"""Harness-side attempt log of the rogue slot (SPEC §3 ``ctx.report``/``ctx.dump``): 0600, capped, outside every
TCB read path and every deterministic-file list. Present only in ``--rogue`` runs."""


def _rogue(options: RunOptions | None, sc, key_mode: str) -> tuple[str, bytes] | None:
    """``(slot, source)`` of a ``--rogue`` run (B3-35), or None. Raises ValueError before anything is created."""
    if options is None or options.rogue is None:
        return None
    if sc.name != "world":
        raise ValueError("a rogue needs the world scenario")
    if key_mode != "fresh":
        raise ValueError("a rogue run uses fresh keys (X7)")
    slot = options.slot or "docs"
    if slot not in sc.agent_ids:
        raise ValueError(f"--slot {slot!r} is not an agent of the scenario")
    return slot, Path(options.rogue).read_bytes()


class RogueLog:
    """Sends the rogue its source, then appends its report lines to ``<run>/rogue.jsonl`` (cap REPORT_CAP)."""

    def __init__(self, sock: socket.socket, source: bytes, path: Path):
        import threading
        from .rogue import REPORT_CAP
        self.sock, self.path, self.cap = sock, path, REPORT_CAP
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.f = os.fdopen(fd, "wb")
        sock.sendall(str(len(source)).encode() + b"\n" + source)
        self.t = threading.Thread(target=self._pump, daemon=True)
        self.t.start()

    def _pump(self) -> None:
        n = 0
        try:
            for line in self.sock.makefile("rb"):
                if n + len(line) <= self.cap and line.endswith(b"\n"):
                    self.f.write(line)
                    self.f.flush()
                    n += len(line)
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        self.t.join(2.0)  # the rogue is dead by now: drain to EOF first, then cut
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.t.join(1.0)
        self.sock.close()
        self.f.close()


DEMO_HOLD = 6
"""``hold_window_ticks`` of a fault run when ``--hold`` is not given (ADR-06-metrics: demo H=6)."""


def _fault_spec(options: RunOptions | None, scenario_name: str, seed: int, ticks: int):
    """``ks.inject`` spec of ``options.fault`` (B3-27), or None. Raises ValueError before anything is created."""
    if options is None or options.fault is None:
        return None
    if scenario_name != "world":
        raise ValueError("a fault needs the world scenario")
    from ks.inject import make_spec, world_fault
    return make_spec(world_fault(options.fault), seed, ticks=ticks, culprit=options.culprit)


def _config_fault(internal: str) -> str:
    """World fault name -> ``RunConfig.fault`` id: ``f2plus`` -> ``F2+``, ``f2plus_x`` -> ``F2+x``, ``f1`` -> ``F1``."""
    f = internal.upper().replace("PLUS_", "+").replace("PLUS", "+")
    return f[:-1] + f[-1].lower() if f[-1].isalpha() and "+" in f else f


class AlertTaint:
    """The gateway outbox's ``TaintView`` in a monitored run (ADR-04 §5): the forward closure
    (``ks.taint.taint_from_alerts``) over the record so far, seeded by the monitor's alerts; nothing is tainted
    before the first alert or without a suspended suspect. Recomputed when a record lands."""

    def __init__(self, recorder: Recorder, mon) -> None:
        self.recorder, self.mon = recorder, mon
        self._at: tuple[int, int] = (-1, -1)
        self._t = None

    def is_tainted(self, obj: str, ver: int) -> bool:
        if not self.mon.alerts:
            return False
        key = (self.recorder.seq, len(self.mon.alerts))
        if key != self._at:
            from ks.taint import taint_from_alerts
            self._t = taint_from_alerts(list(self.recorder.rundir.records()), list(self.mon.alerts))
            self._at = key
        return self._t is not None and self._t.is_tainted(obj, ver)


@dataclass(frozen=True)
class _Replay:
    """Operator decisions of an anchored source run (``ks.verify.decisions``), as control-phase requests by tick."""

    anchor_hash: str
    by_tick: dict[int, list]

    def at(self, tick: int) -> list:
        return self.by_tick.get(tick, [])


def _load_replay(options: RunOptions | None) -> _Replay | None:
    """``--decisions SRC --decisions-head ANCHOR`` (R3, B3-20 library, wired in B3-30): refuse an unanchored, repro,
    or non-verifying source (``DecisionsRefused`` -> ValueError); replay its ``ks.operator`` Controls (same op,
    target, epoch, reason, auto, alert) and approvals (same args, read from the source's side store) at the tick
    they landed in the source, so ``verify_replay`` compares them one to one."""
    if options is None or options.decisions is None:
        return None
    from ks.contracts import CONTROL_TOOL, APPROVE_TOOL, CanonicalError, SideEntry, sidestore_relpath
    from ks.gateway.system import SystemRequest
    from ks.verify.decisions import DecisionsRefused, load_decisions

    src = Path(options.decisions)
    try:
        anchor = RunAnchor.from_canonical(options.decisions_head.strip().encode()) \
            if options.decisions_head is not None else None
    except CanonicalError as e:
        raise ValueError(f"--decisions-head is not a RunAnchor line: {e}") from None
    try:
        sd = load_decisions(src, anchor)
    except DecisionsRefused as e:
        raise ValueError(str(e)) from None
    by_tick: dict[int, list] = {}
    for rc in sd.controls:
        c = rc.control

        def build(gw, tick, seq, c=c):
            return c.model_copy(update={"control_id": f"k-{seq:06d}"}).to_obj()
        by_tick.setdefault(rc.tick, []).append(SystemRequest("ks.operator", CONTROL_TOOL, build=build, _n=rc.seq))
    for ra in sd.approvals:
        try:
            args = SideEntry.from_canonical((src / sidestore_relpath(ra.args_hash)).read_bytes()).value
        except (OSError, CanonicalError) as e:
            raise ValueError(f"approval at seq {ra.seq}: args unreadable in the source side store ({e})") from None
        by_tick.setdefault(ra.tick, []).append(SystemRequest("ks.operator", APPROVE_TOOL,
                                                             build=lambda gw, tick, seq, a=args: a, _n=ra.seq))
    for reqs in by_tick.values():
        reqs.sort(key=lambda r: r._n)  # source record order (put() renumbers _n)
    return _Replay(sd.anchor_hash, by_tick)


def pause_ticks(options: RunOptions | None, ticks: int) -> frozenset[int]:
    """Ticks the gateway pauses before: ``--pause-at`` as given (within the run), ``--step`` every tick after 0.
    Pausing changes no record (ts_us is logical, ADR-02), so paused and unpaused runs give identical records."""
    if options is None:
        return frozenset()
    if options.step:
        return frozenset(range(1, ticks))
    return frozenset(t for t in options.pause_at or () if t < ticks)


def _keypress_resumes(wake) -> None:
    """A daemon thread that resumes a paused run on every line typed at the terminal (Enter)."""
    import threading

    def loop() -> None:
        for _line in sys.stdin:
            wake.set()
    threading.Thread(target=loop, name="ks-keypress", daemon=True).start()


def _teardown(conns: list[AgentConn], witness: WitnessLink | None, uids: list[int]) -> None:
    """EOF to agents, SIGKILL, kill by uid (forks included), then close the witness (final ack already in)."""
    for c in conns:
        c.close()
    for c in conns:
        try:
            c.proc.wait(0.5)
        except Exception:
            pass
        if c.proc.poll() is None:
            c.proc.kill()
            c.proc.wait()
    if witness is not None:
        witness.close()
    if uids:
        left = kill_uids(uids)
        if left:
            print(f"ks run: WARNING: pids {left} survived kill-by-uid", file=sys.stderr)
