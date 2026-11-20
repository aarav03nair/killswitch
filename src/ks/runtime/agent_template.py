"""The agent template: what runs inside each agent subprocess (own uid, non-dumpable via BOOT).

It holds two socket ends and nothing else: the gateway (TickFrame in, Submit/Noop out, Reply in) and its
signer handle (SignRequest out, SignReply or SignRefusal in). No keys, no paths, no record access.

    main(["--agent", ID, "--seed", N, "--gw-fd", F, "--signer-fd", G, "--behaviour", MODULE, ["--hero-tick", H]])

``MODULE.step(agent_id, seed, tick)`` returns an action (``tool``, ``args``, ``action_id``) or ``None``. With
``--hero-tick`` (the ADR-06 world, B3-10) it is ``MODULE.step(agent_id, seed, tick, view, MODULE.Schedule(H))``:
the agent decides from the ``TickFrame.view`` the gateway sent, nothing else. ``--variant`` is the honest-world
variant (F2+x / F2+c); the fault itself reaches only the culprit's process, as env ``KS_FAULT`` (B3-27, A3).
"""

from __future__ import annotations

import argparse
import os
import importlib
import socket

from ks.contracts import (Envelope, NoopFrame, SignRefusal, SignReply, SignRequest, SubmitFrame, TickFrame,
                          decode_frame, encode_frame)
from ks.rng import draw_hex

EXPIRY_TICKS = 2
"""How far ahead the template sets ``expiry_tick`` (<= MAX_EXPIRY_TICKS)."""


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ks-agent")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--gw-fd", type=int, required=True)
    ap.add_argument("--signer-fd", type=int, required=True)
    ap.add_argument("--behaviour", default="ks.world.skeleton")
    ap.add_argument("--hero-tick", type=int, default=None)
    ap.add_argument("--variant", default=None)
    a = ap.parse_args(argv)
    behaviour = importlib.import_module(a.behaviour)
    sched = None
    if a.hero_tick is not None:
        kw = {"variant": a.variant} if a.variant else {}
        sched = behaviour.Schedule(a.hero_tick, os.environ.get("KS_FAULT") or None, **kw)
    gw = socket.socket(fileno=a.gw_fd)
    signer = socket.socket(fileno=a.signer_fd)
    gw_in, signer_in = gw.makefile("rb"), signer.makefile("rb")

    def signed(act, tick: int, epoch: int):
        """Sign ``act`` as of ``tick`` (nonce and expiry from ``tick``); None if the signer refuses."""
        env = Envelope(agent_id=a.agent, action_id=act.action_id, parent_action_id=None, act_chain=(),
                       tool=act.tool, args=act.args, nonce=draw_hex(a.seed, f"nonce/{a.agent}", tick),
                       expiry_tick=tick + EXPIRY_TICKS, epoch=epoch, claimed_ts_us=None, claimed_seq=None, sig=None)
        signer.sendall(encode_frame(SignRequest(header=env.header())))
        reply = decode_frame(signer_in.readline())
        if isinstance(reply, SignRefusal):
            return None
        if not isinstance(reply, SignReply):
            raise ConnectionError("signer protocol")
        return env.with_sig(reply.sig)

    # TTC probe (ADR-06-metrics: one culprit envelope per tick from t_alert, B3-27): only the culprit's process (it
    # alone gets KS_FAULT) presigns its next tick's action while it is live. If that next frame says suspended
    # (epoch None) it submits the presigned envelope, as an attacker holding a signature would; the gateway must
    # deny it (suspended / stale_epoch), which is the record ks.score reads time-to-contain from. Unused otherwise.
    # With nothing scheduled next tick (crm's quiet window) the probe is a retry of its last action.
    culprit = sched is not None and bool(os.environ.get("KS_FAULT"))
    probe = None  # (tick, envelope)
    last = None  # the culprit's most recent action
    try:
        for line in gw_in:
            frame = decode_frame(line)
            if not isinstance(frame, TickFrame):
                continue  # ReplyFrame: nothing to do with it yet
            if frame.epoch is None:
                if probe is not None and probe[0] == frame.tick:
                    gw.sendall(encode_frame(SubmitFrame(tick=frame.tick, envelope=probe[1])))
                else:
                    gw.sendall(encode_frame(NoopFrame(tick=frame.tick)))
                probe = None
                continue
            act = (behaviour.step(a.agent, a.seed, frame.tick) if sched is None
                   else behaviour.step(a.agent, a.seed, frame.tick, frame.view, sched))
            env = signed(act, frame.tick, frame.epoch) if act is not None else None
            probe = None
            if act is not None:
                last = act
            if culprit:  # signed before this tick's frame goes out: the signer serves a handle only until then
                nxt = behaviour.step(a.agent, a.seed, frame.tick + 1, frame.view, sched)
                if nxt is None and last is not None:  # nothing scheduled: the probe retries its last action
                    nxt = type(last)(last.tool, last.args, f"{a.agent}-probe-t{frame.tick + 1}")
                penv = signed(nxt, frame.tick + 1, frame.epoch) if nxt is not None else None
                probe = (frame.tick + 1, penv) if penv is not None else None
            # refused or nothing to do: no-op now, don't wait the deadline
            gw.sendall(encode_frame(SubmitFrame(tick=frame.tick, envelope=env) if env is not None
                                    else NoopFrame(tick=frame.tick)))
    except ConnectionError:
        return 3
    return 0
