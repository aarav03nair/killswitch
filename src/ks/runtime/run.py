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
from ks.contracts.rundir import TIMING, WITNESS, WITNESS_HEADS_DIR
from ks.gateway import Gateway
from ks.identity import KeyStore, SignerService, derive_key_bytes, load_repro_secret
from ks.recorder import Recorder
from ks.witness import WitnessLink, open_witness_fds

from .barrier import AgentConn, TickBarrier
from .spawn import (WITNESS_UID, agent_uid, kill_uids, pids_with_uids, plan_agent_uids, proc_uid, set_nondumpable,
                    set_oom_score_adj, spawn_child)
from .setup import IsolationError, default_run_id, isolation_problems, refuse_existing, scenario as _scenario

__all__ = ["Isolation", "RunResult", "run", "agent_ids", "STARTUP_GRACE_S"]

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
        _force_agent_uids: list[int] | None = None) -> RunResult:
    """Run ``scenario`` (``skeleton`` or the 10-agent ``world``, B3-10). ``separate_uids=None`` means "if root".
    Raises ValueError on bad arguments, FileExistsError if ``out`` exists, RuntimeError if the environment refuses
    (stray processes under our uids) and IsolationError if the /proc readback contradicts RunConfig.isolation
    (before tick 0). ``_force_agent_uids`` is a test hook that spawns agents under other uids than planned, to
    prove the readback abort; it is not reachable from the CLI."""
    if (agents is not None and agents < 1) or ticks < 1:
        raise ValueError("need at least one agent and one tick")
    sc = _scenario(scenario, agents=agents, seed=seed, ticks=ticks)
    ids = sc.agent_ids
    agents = len(ids)
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
                       seed=seed, scenario=sc.name, fault=None, culprit=None, fault_tick=None, key_mode=key_mode,
                       decision_latency_ticks=0, ticks=ticks, tick_us=TICK_US, start_ts_us=0, hold_window_ticks=0,
                       sensitive_fields=sc.sensitive_fields, agents=ids, isolation="per_agent_uid" if separate else "degraded",
                       decisions_from=None)
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
    epochs: dict[str, int | None] = {a: 0 for a in ids}
    conns: list[AgentConn] = []
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

        say(f"ks run: run_id={config.run_id} seed={seed} agents={agents} ticks={ticks} key_mode={key_mode}")
        if key_mode == "repro":
            say("NOT A SECURITY RUN: repro keys (never anchored)")
        say(f"keyring_hash={keyring.content_hash()} config_hash={config.content_hash()}")

        for i, a in enumerate(ids):
            g_parent, g_child = socket.socketpair()
            s_parent, s_child = socket.socketpair()
            proc = spawn_child("ks.runtime.agent_template",
                               ["--agent", a, "--seed", str(seed), "--gw-fd", str(g_child.fileno()),
                                "--signer-fd", str(s_child.fileno()), "--behaviour", sc.behaviour, *sc.agent_argv],
                               uid=spawn_uids[i], pass_socks=[g_child, s_child], agent=True)
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
        gateway = Gateway(config, keyring, recorder, epochs.get, dispatcher=sc.dispatcher())
        signer = SignerService({a: keys.private(a) for a in ids}, epochs.get)
        barrier = TickBarrier(conns, gateway, signer, witness, tick_deadline_ms / 1000)
        timing, stalls, misses = [], 0, 0
        for t in range(ticks):
            o = barrier.run_tick(t, deadline_s=max(STARTUP_GRACE_S, barrier.deadline_s) if t == 0 else None)
            stalls += o.checkpoint is None and recorder.seq > 0
            misses += len(o.missed)
            timing.append(canonical.dumps_line({"tick": t, "wall_us": o.wall_us, "missed": o.missed,
                                                "witness_ack": o.checkpoint is not None}))
        rd.write(TIMING, b"".join(timing))
    finally:
        _teardown(conns, witness, our_uids)

    last = witness.newest if witness is not None else None  # newest verified ack, late ones drained at close (M1)
    anchor = RunAnchor.of(last, keyring, config) if last is not None else None
    if stalls or misses:
        say(f"warnings: {misses} deadline misses, {stalls} witness stalls")
    if anchor is None:
        say("no witnessed head: nothing to anchor")
    else:
        say("RunAnchor (copy into ks verify --head):")
        say(anchor.to_canonical().decode())
    return RunResult(rd, anchor, iso, stalls, misses)


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
