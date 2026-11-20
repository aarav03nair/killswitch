"""Gateway-side end of the witness socket: push ``(seq, head, tick)``, wait for the signed checkpoint up to a
deadline, then proceed (F6: a late ack is a stall, never a hang)."""

from __future__ import annotations

import os
import select
import socket
import subprocess
import time

from ks.contracts import (WITNESS_FILES_FDS, CanonicalError, WitnessCheckpoint, WitnessClose, WitnessFiles,
                          WitnessHead, WitnessInit, WitnessPub, WitnessReady, decode_witness_frame, encode_frame)
from ks.identity import verify_hex

__all__ = ["WitnessLink", "WitnessError"]


class WitnessError(RuntimeError):
    pass


class WitnessLink:
    def __init__(self, sock: socket.socket, proc: subprocess.Popen):
        self.sock = sock
        self.proc = proc
        self.pub: str | None = None
        self._buf = bytearray()
        self.newest: WitnessCheckpoint | None = None
        """Newest checkpoint whose signature verified **and** whose ``(seq, head)`` is what this link pushed for
        that tick, from any ack, late ones included (SKEL-01 M1). The anchor is taken from this after ``close``, so
        an honest run always verifies with ``--head``; a forged or mismatched ack never moves it (S4-01)."""
        self._pushed: dict[int, tuple[int, str]] = {}
        """tick -> (seq, head) this link pushed: the only checkpoints ``_ingest`` accepts (S4-01)."""

    def _readline(self, timeout_s: float) -> bytes | None:
        """Next line, or ``None`` at the deadline. EOF raises WitnessError."""
        end = time.monotonic() + timeout_s
        while b"\n" not in self._buf:
            left = end - time.monotonic()
            if left <= 0 or not select.select([self.sock], [], [], left)[0]:
                return None
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WitnessError("witness closed its socket")
            self._buf += chunk
        i = self._buf.index(b"\n")
        line = bytes(self._buf[:i + 1])
        del self._buf[:i + 1]
        return line

    def init(self, key_seed: bytes | None, timeout_s: float = 30.0) -> str:
        """Hand over the repro key seed (``None`` in fresh mode) and get the witness public key."""
        self.sock.sendall(encode_frame(WitnessInit(key_seed=None if key_seed is None else key_seed.hex())))
        line = self._readline(timeout_s)
        if line is None:
            raise WitnessError("witness did not start")
        try:
            reply = decode_witness_frame(line)
        except CanonicalError as e:
            raise WitnessError(f"bad witness reply: {e}") from None
        if not isinstance(reply, WitnessPub):
            raise WitnessError(f"unexpected witness reply {reply.type!r}")
        self.pub = reply.pub
        return self.pub

    def attach(self, witness_fd: int, heads_dir_fd: int, timeout_s: float = 10.0) -> None:
        """Pass the open ``witness.jsonl`` and ``witness-heads/`` descriptors (no path access needed) and
        **close the gateway's copies** whatever happens: after attach the gateway holds no write fd (SKEL-01 #5)."""
        fds = [witness_fd, heads_dir_fd]
        assert len(fds) == WITNESS_FILES_FDS
        try:
            socket.send_fds(self.sock, [encode_frame(WitnessFiles())], fds)
        finally:
            for fd in fds:
                os.close(fd)
        line = self._readline(timeout_s)
        try:
            ok = line is not None and isinstance(decode_witness_frame(line), WitnessReady)
        except CanonicalError:
            ok = False
        if not ok:
            raise WitnessError("witness did not accept its files")

    def push(self, seq: int, head: str, tick: int, timeout_s: float) -> WitnessCheckpoint | None:
        """Push one head; the verified checkpoint, or ``None`` on stall (deadline, bad or regressing ack)."""
        self._pushed.setdefault(tick, (seq, head))  # the witness never signs a 2nd head for a tick
        self.sock.sendall(encode_frame(WitnessHead(seq=seq, head=head, tick=tick)))
        end = time.monotonic() + timeout_s
        while True:
            line = self._readline(max(0.0, end - time.monotonic()))
            if line is None:
                return None
            cp = self._ingest(line)
            if cp is None:
                return None
            if cp.tick < tick:
                continue  # late ack of an earlier, stalled tick (still recorded in ``newest``)
            return cp if (cp.seq, cp.head, cp.tick) == (seq, head, tick) else None

    def _ingest(self, line: bytes) -> WitnessCheckpoint | None:
        """Parse and verify one ack line; keep it as ``newest`` if it is newer. ``None`` if bad: unparsable, bad or
        missing signature, or not the ``(seq, head)`` this link pushed for its tick (S4-01)."""
        try:
            cp = WitnessCheckpoint.from_canonical(line[:-1])
        except CanonicalError:
            return None
        if cp.sig is None or not verify_hex(self.pub or "", cp.sig, cp.signing_bytes()):
            return None
        if self._pushed.get(cp.tick) != (cp.seq, cp.head):
            return None
        if self.newest is None or cp.count > self.newest.count:
            self.newest = cp
        return cp

    def close(self, timeout_s: float = 5.0) -> WitnessCheckpoint | None:
        """Send Close, wait for the witness to exit, then drain every ack still on the socket (a late final ack
        is the newest checkpoint). Returns ``newest``."""
        try:
            self.sock.sendall(encode_frame(WitnessClose()))
        except OSError:
            pass
        try:
            self.proc.wait(timeout_s)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        while True:  # the witness has exited: whatever it acked is already buffered on the socket
            try:
                line = self._readline(0.2)
            except (WitnessError, OSError):
                break
            if line is None:
                break
            self._ingest(line)
        self.sock.close()
        return self.newest


def open_witness_fds(witness_path: os.PathLike[str] | str, heads_dir: os.PathLike[str] | str) -> tuple[int, int]:
    """Gateway side: open ``witness.jsonl`` for append and ``witness-heads/`` as a directory fd."""
    return (os.open(witness_path, os.O_WRONLY | os.O_APPEND),
            os.open(heads_dir, os.O_RDONLY | os.O_DIRECTORY))
