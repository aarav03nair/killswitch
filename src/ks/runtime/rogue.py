"""The rogue slot (SPEC §3, B3-35): jury Python run in place of one honest agent, under that agent's uid.

    main(["--agent", ID, "--seed", N, "--gw-fd", F, "--signer-fd", G, "--aux-fd", A])

Same handles as every agent (a gateway socket and a signer handle) plus one harness channel ``aux``: the runtime
writes the rogue source down it once (``<len>\\n<bytes>``), then the rogue's ``ctx.report`` / ``ctx.dump`` lines go
back up it and the runtime appends them to ``<run>/rogue.jsonl`` (harness-side, 0600, capped; never read by the
TCB). No key, no DB path, no record path, no operator socket. Arbitrary Python is allowed: this module is the
convenience layer, not a sandbox; the guarantees come from the uid, the gateway and the signer.

The jury file defines ``on_tick(ctx, tick)`` and optionally ``on_start(ctx)``. ``ctx``:

* ``agent_id``, ``seed``, ``tick``, ``epoch`` (``None`` while suspended or revoked, D3), ``last_epoch``, ``view``
* ``envelope(tool, args, **over)`` an unsigned C1 envelope for this agent (``over``: any envelope field)
* ``sign_envelope(env | tool, args=None, leg=None, **over)`` signer handle; ``None`` + a ``signer_refused`` line on
  refusal (foreign agent_id, ``ks.*`` tool, stale epoch, over 2 per tick, E5)
* ``send(tool, args, leg=None, **over)`` sign and submit; ``submit(env, leg=None)`` submit a signed envelope as a
  ``SubmitFrame`` for this tick; ``raw_send(bytes | Envelope, leg=None)`` anything down the socket
* ``report(**kv)``, ``dump(obj)`` attempt log / loot (RT2 scans it)

Frames a tick produces are written after ``on_tick`` returns (the signer is served only while the barrier
collects). The barrier reads **one frame per connection per tick** (FIFO): surplus frames answer later ticks and
get ``deny/late_frame``; while a backlog exists the rogue sends no no-op. Every submitted envelope is logged as
``{"kind": "sent", "hash": envelope_hash}`` so the harness can check rule 11 (one record per frame).
"""

from __future__ import annotations

import argparse
import os
import socket
import traceback
from typing import Any

from ks.contracts import (MAX_DEPTH, CanonicalError, Envelope, NoopFrame, SignRefusal, SignReply, SignRequest,
                          SubmitFrame, TickFrame, decode_frame, encode_frame)
from ks.contracts.canonical import MAX_SAFE_INT, dumps_line
from ks.rng import draw_hex

__all__ = ["main", "RogueCtx", "REPORT_CAP"]

REPORT_CAP = 4 << 20
"""Bytes of report/dump lines the runtime keeps per run (SPEC §3 scratch-file cap); the rest is dropped."""


def _plain(o: Any, depth: int = 0) -> Any:
    """Loot -> ks-canon/1-safe value (the one serializer, rule 3): bytes become hex, floats/big ints/other types
    their repr, non-str keys str(); lone surrogates are escaped; anything deeper than MAX_DEPTH becomes its repr."""
    if o is None or isinstance(o, bool):
        return o
    if isinstance(o, int):
        return int(o) if -MAX_SAFE_INT <= o <= MAX_SAFE_INT else str(o)
    if isinstance(o, str):
        return str.__str__(o).encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(o, (bytes, bytearray, memoryview)):
        return bytes(o).hex()
    if depth >= MAX_DEPTH - 1:
        return _plain(repr(o))
    if isinstance(o, dict):
        return {_plain(k if isinstance(k, str) else str(k)): _plain(v, depth + 1) for k, v in o.items()}
    if isinstance(o, (list, tuple, set, frozenset)):
        return [_plain(v, depth + 1) for v in o]
    return _plain(repr(o))


class RogueCtx:
    def __init__(self, agent_id: str, seed: int, gw: socket.socket, signer: socket.socket, aux: socket.socket):
        self.agent_id, self.seed = agent_id, seed
        self.tick, self.epoch, self.last_epoch, self.view = 0, None, 0, ()
        self._gw, self._signer, self._aux = gw, signer, aux
        self._signer_in = signer.makefile("rb")
        self._out: list[bytes] = []
        self._n = 0

    # harness channel -------------------------------------------------------------------------------
    def report(self, **kv: Any) -> None:
        kv.setdefault("tick", self.tick)
        try:
            self._aux.sendall(dumps_line(_plain(kv)))
        except (OSError, CanonicalError):
            pass

    def dump(self, obj: Any) -> None:
        self.report(kind="dump", loot=obj)

    # envelopes -------------------------------------------------------------------------------------
    def envelope(self, tool: str, args: dict, **over: Any) -> Envelope:
        self._n += 1
        d = dict(agent_id=self.agent_id, action_id=f"{self.agent_id}-r{self.tick}-{self._n}", parent_action_id=None,
                 act_chain=(), tool=tool, args=args, nonce=draw_hex(self.seed, f"rogue/{self.agent_id}", self._n),
                 expiry_tick=self.tick + 2, epoch=self.epoch if self.epoch is not None else self.last_epoch,
                 claimed_ts_us=None, claimed_seq=None, sig=None)
        d.update(over)
        return Envelope.model_validate(d)

    def sign_envelope(self, env: Envelope | str, args: dict | None = None, leg: str | None = None,
                      **over: Any) -> Envelope | None:
        if not isinstance(env, Envelope):
            env = self.envelope(env, args or {}, **over)
        self._signer.sendall(encode_frame(SignRequest(header=env.header())))
        reply = decode_frame(self._signer_in.readline())
        if isinstance(reply, SignRefusal):
            self.report(kind="signer_refused", leg=leg, reason=reply.reason, tool=env.tool, agent_id=env.agent_id)
            return None
        if not isinstance(reply, SignReply):
            raise ConnectionError("signer protocol")
        return env.with_sig(reply.sig)

    def submit(self, env: Envelope, leg: str | None = None) -> Envelope:
        self._out.append(encode_frame(SubmitFrame(tick=self.tick, envelope=env)))
        self.report(kind="sent", leg=leg, hash=env.content_hash(), tool=env.tool, agent_id=env.agent_id)
        return env

    def send(self, tool: str, args: dict, leg: str | None = None, **over: Any) -> Envelope | None:
        env = self.sign_envelope(tool, args, leg=leg, **over)
        return self.submit(env, leg=leg) if env is not None else None

    def raw_send(self, data: bytes | Envelope, leg: str | None = None) -> None:
        if isinstance(data, Envelope):
            self.submit(data, leg=leg)
            return
        line = data if data.endswith(b"\n") else data + b"\n"
        h = None
        try:
            f = decode_frame(line)
            h = f.envelope.content_hash() if isinstance(f, SubmitFrame) else None
        except (CanonicalError, ValueError):
            pass
        self._out.append(line)
        self.report(kind="sent", leg=leg, hash=h, raw=True)

    def _flush(self, backlog: int) -> int:
        """Write this tick's frames; a no-op only when nothing was written and nothing is queued."""
        frames, self._out = self._out, []
        if not frames and backlog <= 0:
            frames = [encode_frame(NoopFrame(tick=self.tick))]
        for f in frames:
            self._gw.sendall(f)
        return backlog + len(frames) - 1


def _read_source(aux: socket.socket) -> str:
    f = aux.makefile("rb")
    n = int(f.readline())
    src = f.read(n)
    if len(src) != n:
        raise ConnectionError("short rogue source")
    return src.decode()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ks-rogue")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--gw-fd", type=int, required=True)
    ap.add_argument("--signer-fd", type=int, required=True)
    ap.add_argument("--aux-fd", type=int, required=True)
    a, _ = ap.parse_known_args(argv)
    gw, signer, aux = (socket.socket(fileno=fd) for fd in (a.gw_fd, a.signer_fd, a.aux_fd))
    ctx = RogueCtx(a.agent, a.seed, gw, signer, aux)
    ns: dict[str, Any] = {"__name__": "rogue"}
    try:
        exec(compile(_read_source(aux), "rogue.py", "exec"), ns)  # noqa: S102 - the jury's code, by design
        if callable(ns.get("on_start")):
            ns["on_start"](ctx)
    except Exception as e:  # a broken rogue is a no-op agent, not a crashed run
        ctx.report(kind="error", where="start", err=f"{type(e).__name__}: {e}", tb=traceback.format_exc()[-2000:])
    on_tick = ns.get("on_tick")
    backlog = 0
    try:
        for line in gw.makefile("rb"):
            frame = decode_frame(line)
            if not isinstance(frame, TickFrame):
                continue
            ctx.tick, ctx.epoch, ctx.view = frame.tick, frame.epoch, frame.view
            if frame.epoch is not None:
                ctx.last_epoch = frame.epoch
            if callable(on_tick):
                try:
                    on_tick(ctx, frame.tick)
                except ConnectionError:
                    raise
                except Exception as e:
                    ctx.report(kind="error", where="tick", err=f"{type(e).__name__}: {e}")
            backlog = ctx._flush(backlog)
    except (ConnectionError, OSError):
        return 3
    finally:
        try:
            aux.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(os.sys.argv[1:]))
