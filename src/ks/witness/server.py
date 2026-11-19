"""The witness process (ADR-02 §3): its own uid (60000), its own key, its own files. It signs what it is
pushed, ``WitnessCheckpoint(seq, head, tick, count)``, and never reads ``record.jsonl``.

Started by ``ks.runtime`` through the non-dumpable bootstrap: ``main([sock_fd])``.
"""

from __future__ import annotations

import os
import socket
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ks.contracts import (WITNESS_FILES_FDS, CanonicalError, WitnessCheckpoint, WitnessClose, WitnessFiles,
                          WitnessHead, WitnessInit, WitnessPub, WitnessReady, decode_witness_frame, encode_frame)
from ks.identity import pub_hex, sign_hex

from .protocol import HEADS_FILE


class Witness:
    """The witness's state: signs and appends at most one checkpoint per tick (SKEL-01 #11).

    ``push`` returns the checkpoint to ack, or ``None`` (no ack, the gateway sees a stall) for a regressing or
    conflicting head. A repeated push of the last ``(seq, head, tick)`` returns the existing checkpoint and
    writes nothing, so ``witness.jsonl`` ticks strictly increase and ``count`` rises by exactly 1 per line."""

    def __init__(self, key: Ed25519PrivateKey, fds: list[int]):
        self._key = key
        self._out_fd, self._heads_fd = fds
        self.last: WitnessCheckpoint | None = None

    def push(self, m: WitnessHead) -> WitnessCheckpoint | None:
        last = self.last
        if last is not None:
            if (m.seq, m.head, m.tick) == (last.seq, last.head, last.tick):
                return last
            if m.tick <= last.tick or m.seq < last.seq:
                return None  # never anchor a regressing head, nor a second head for one tick
            if m.seq == last.seq and m.head != last.head:
                return None  # equivocation: a seq already signed with one head never gets a second (B3-42)
        cp = WitnessCheckpoint(witness_id="ks.witness", seq=m.seq, tick=m.tick, head=m.head,
                               count=1 if last is None else last.count + 1, sig=None)
        cp = cp.with_sig(sign_hex(self._key, cp.signing_bytes()))
        data = cp.to_canonical() + b"\n"
        os.write(self._heads_fd, data)
        os.write(self._out_fd, data)
        self.last = cp
        return cp


def main(argv: list[str]) -> int:
    sock = socket.socket(fileno=int(argv[0]))
    rd = sock.makefile("rb")
    try:
        init = decode_witness_frame(rd.readline())
    except CanonicalError:
        return 2
    if not isinstance(init, WitnessInit):
        return 2
    seed = init.key_seed
    key = Ed25519PrivateKey.generate() if seed is None else Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    del init, seed
    sock.sendall(encode_frame(WitnessPub(pub=pub_hex(key))))
    # Strict request/reply: the read buffer is empty here, so the fds can be taken off the socket directly.
    data, fds, _, _ = socket.recv_fds(sock, 4096, WITNESS_FILES_FDS)
    try:
        files = decode_witness_frame(data)
    except CanonicalError:
        files = None
    if not isinstance(files, WitnessFiles) or len(fds) != WITNESS_FILES_FDS:
        for fd in fds:
            os.close(fd)
        return 2
    out_fd, heads_dir = fds
    heads_fd = os.open(HEADS_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600, dir_fd=heads_dir)
    os.close(heads_dir)
    sock.sendall(encode_frame(WitnessReady()))

    w = Witness(key, [out_fd, heads_fd])
    for line in rd:
        try:
            m = decode_witness_frame(line)
        except CanonicalError:
            continue  # garbage gets no ack: the gateway raises a stall
        if isinstance(m, WitnessClose):
            break
        if not isinstance(m, WitnessHead):
            continue
        cp = w.push(m)
        if cp is not None:
            sock.sendall(cp.to_canonical() + b"\n")
    os.close(out_fd)
    os.close(heads_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
