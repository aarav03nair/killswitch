"""The agent template: what runs inside each agent subprocess (own uid, non-dumpable via BOOT).

It holds two socket ends and nothing else: the gateway (TickFrame in, Submit/Noop out, Reply in) and its
signer handle (SignRequest out, SignReply in). No keys, no paths, no record access.

    main(["--agent", ID, "--seed", N, "--gw-fd", F, "--signer-fd", G, "--behaviour", MODULE])

``MODULE.step(agent_id, seed, tick)`` returns an action (``tool``, ``args``, ``action_id``) or ``None``.
"""

from __future__ import annotations

import argparse
import importlib
import socket

from ks.contracts import (Envelope, NoopFrame, SignReply, SignRequest, SubmitFrame, TickFrame, decode_frame,
                          encode_frame)

from .rng import draw_hex

EXPIRY_TICKS = 2
"""How far ahead the template sets ``expiry_tick`` (<= MAX_EXPIRY_TICKS)."""


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ks-agent")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--gw-fd", type=int, required=True)
    ap.add_argument("--signer-fd", type=int, required=True)
    ap.add_argument("--behaviour", default="ks.world.skeleton")
    a = ap.parse_args(argv)
    behaviour = importlib.import_module(a.behaviour)
    gw = socket.socket(fileno=a.gw_fd)
    signer = socket.socket(fileno=a.signer_fd)
    gw_in, signer_in = gw.makefile("rb"), signer.makefile("rb")

    for line in gw_in:
        frame = decode_frame(line)
        if not isinstance(frame, TickFrame):
            continue  # ReplyFrame: nothing to do with it yet
        act = behaviour.step(a.agent, a.seed, frame.tick)
        if act is None or frame.epoch is None:
            gw.sendall(encode_frame(NoopFrame(tick=frame.tick)))
            continue
        env = Envelope(agent_id=a.agent, action_id=act.action_id, parent_action_id=None, act_chain=(),
                       tool=act.tool, args=act.args, nonce=draw_hex(a.seed, f"nonce/{a.agent}", frame.tick),
                       expiry_tick=frame.tick + EXPIRY_TICKS, epoch=frame.epoch, claimed_ts_us=None,
                       claimed_seq=None, sig=None)
        signer.sendall(encode_frame(SignRequest(header=env.header())))
        reply = decode_frame(signer_in.readline())
        if not isinstance(reply, SignReply):
            return 3
        gw.sendall(encode_frame(SubmitFrame(tick=frame.tick, envelope=env.with_sig(reply.sig))))
    return 0
