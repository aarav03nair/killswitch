"""Tick barrier (ADR-00, gateway = scheduler): open -> collect one frame per connection (FIFO, deadline)
-> execute in agent_id order -> replies -> checkpoint. Arrival order is discarded, so a slow or noisy agent
delays only itself. Control phase, view, dispatch and monitor are Sprint 3.
"""

from __future__ import annotations

import selectors
import socket
import subprocess
import time
from dataclasses import dataclass, field

from ks.contracts import MAX_FRAME_BYTES, TickFrame, WitnessCheckpoint, encode_frame
from ks.gateway import Gateway
from ks.identity import SignerService
from ks.witness import WitnessLink

__all__ = ["AgentConn", "TickBarrier", "TickOutcome", "MAX_MISSES", "OUT_QUEUE_CAP"]

MAX_MISSES = 3
"""Consecutive deadline misses before the connection gets EOF (K4): an anomaly, never a suspend."""
OUT_QUEUE_CAP = 64 * 1024
"""Outbound bytes queued per connection before it gets EOF (K1)."""


@dataclass(eq=False)
class AgentConn:
    """Gateway side of one agent: its gateway socket, its signer handle, its process."""

    index: int
    agent_id: str
    conn_id: str
    gw: socket.socket
    signer: socket.socket
    proc: subprocess.Popen
    uid: int | None
    alive: bool = True
    misses: int = 0
    _in: bytearray = field(default_factory=bytearray)
    _out: bytearray = field(default_factory=bytearray)
    _sig_in: bytearray = field(default_factory=bytearray)

    def __post_init__(self) -> None:
        self.gw.setblocking(False)
        self.signer.setblocking(False)

    # gateway socket ------------------------------------------------------------------------------
    def pop_frame(self) -> bytes | None:
        """One buffered frame (incl. LF), or an oversize prefix of MAX_FRAME_BYTES + 1 bytes, or None."""
        i = self._in.find(b"\n")
        if 0 <= i < MAX_FRAME_BYTES:
            line = bytes(self._in[:i + 1])
            del self._in[:i + 1]
            return line
        if len(self._in) > MAX_FRAME_BYTES or i >= MAX_FRAME_BYTES:
            line = bytes(self._in[:MAX_FRAME_BYTES + 1])
            self._in.clear()
            return line
        return None

    def fill(self) -> bool:
        """Read what is available, never more than one frame's worth buffered. False on EOF."""
        want = MAX_FRAME_BYTES + 1 - len(self._in)
        if want <= 0:
            return True
        try:
            chunk = self.gw.recv(want)
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not chunk:
            return False
        self._in += chunk
        return True

    def send(self, data: bytes) -> None:
        """Queue and flush without blocking; a full queue means the agent is not reading: EOF."""
        if not self.alive:
            return
        self._out += data
        try:
            while self._out:
                n = self.gw.send(self._out)
                del self._out[:n]
        except BlockingIOError:
            pass
        except OSError:
            self.close()
            return
        if len(self._out) > OUT_QUEUE_CAP:
            self.close()

    # signer handle -------------------------------------------------------------------------------
    def signer_lines(self) -> list[bytes] | None:
        """Complete request lines now available on the signer handle; None on EOF."""
        try:
            chunk = self.signer.recv(65536)
        except BlockingIOError:
            return []
        except OSError:
            return None
        if not chunk:
            return None
        self._sig_in += chunk
        lines = []
        while (i := self._sig_in.find(b"\n")) >= 0:
            lines.append(bytes(self._sig_in[:i + 1]))
            del self._sig_in[:i + 1]
        if len(self._sig_in) > MAX_FRAME_BYTES:
            self._sig_in.clear()
        return lines

    def reply_signer(self, data: bytes) -> None:
        try:
            self.signer.send(data)  # small reply to a request the agent is blocked on
        except OSError:
            pass

    def close(self) -> None:
        """EOF to the agent: no-op from then on."""
        if self.alive:
            self.alive = False
            for s in (self.gw, self.signer):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()


@dataclass
class TickOutcome:
    tick: int
    records: int
    missed: list[str]
    checkpoint: WitnessCheckpoint | None
    wall_us: int


class TickBarrier:
    def __init__(self, conns: list[AgentConn], gateway: Gateway, signer: SignerService, witness: WitnessLink,
                 epochs: dict[str, int | None], deadline_s: float):
        self.conns = sorted(conns, key=lambda c: c.index)  # index order == agent_id order (agents are sorted)
        self.gateway = gateway
        self.signer = signer
        self.witness = witness
        self.epochs = epochs
        self.deadline_s = deadline_s
        self.last_checkpoint: WitnessCheckpoint | None = None

    def run_tick(self, tick: int, *, deadline_s: float | None = None) -> TickOutcome:
        t0 = time.monotonic()
        deadline = t0 + (self.deadline_s if deadline_s is None else deadline_s)
        self.signer.begin_tick(tick)
        self.gateway.begin_tick(tick)
        seq0 = self.gateway.recorder.seq
        # 2. open
        for c in self.conns:
            if c.alive:
                c.send(encode_frame(TickFrame(tick=tick, epoch=self.epochs[c.agent_id], view=())))
        # 3. collect
        frames, missed = self._collect(deadline)
        # 4. execute in agent_id order, then reply
        replies = []
        for c in self.conns:
            if c in frames:
                c.misses = 0
                line = frames[c]
                adm = self.gateway.admit(c.conn_id, line)
                if adm.reply is not None:
                    replies.append((c, adm.reply))
                if len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
                    c.close()  # oversize closes the connection (SEC-03 F8)
        for c, reply in replies:
            c.send(encode_frame(reply))
        for c in missed:
            c.misses += 1
            if c.misses >= MAX_MISSES:
                c.close()
        # 6. checkpoint (records are already flushed: one append per record)
        cp = None
        rec = self.gateway.recorder
        if rec.seq > 0:
            cp = self.witness.push(rec.seq, rec.head, tick, self.deadline_s)  # F6: wait up to the deadline
            if cp is not None:
                self.last_checkpoint = cp
        return TickOutcome(tick, rec.seq - seq0, [c.conn_id for c in missed], cp,
                           int((time.monotonic() - t0) * 1e6))

    def _collect(self, deadline: float) -> tuple[dict[AgentConn, bytes], list[AgentConn]]:
        frames: dict[AgentConn, bytes] = {}
        waiting: set[AgentConn] = set()
        for c in self.conns:
            if not c.alive:
                continue
            f = c.pop_frame()  # FIFO: a frame queued earlier answers this tick (wrong tag -> late_frame)
            if f is not None:
                frames[c] = f
            else:
                waiting.add(c)
        sel = selectors.DefaultSelector()
        for c in self.conns:
            if c.alive:
                sel.register(c.signer, selectors.EVENT_READ, ("signer", c))
            if c in waiting:
                sel.register(c.gw, selectors.EVENT_READ, ("gw", c))
        try:
            while waiting:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                for key, _ in sel.select(left):
                    kind, c = key.data
                    if kind == "signer":
                        lines = c.signer_lines()
                        if lines is None:
                            sel.unregister(c.signer)
                            continue
                        for line in lines:
                            c.reply_signer(self.signer.handle(c.agent_id, line))  # SignReply | SignRefusal
                        continue
                    if c not in waiting:
                        continue
                    if not c.fill():  # EOF: no-op from now on
                        waiting.discard(c)
                        for s in (c.gw, c.signer):
                            if s.fileno() >= 0 and s in sel.get_map():
                                sel.unregister(s)
                        c.close()
                        continue
                    f = c.pop_frame()
                    if f is not None:
                        frames[c] = f
                        waiting.discard(c)
                        sel.unregister(c.gw)
        finally:
            sel.close()
        return frames, [c for c in self.conns if c in waiting and c.alive]
