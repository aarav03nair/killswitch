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

    count, last_tick, last_seq = 0, -1, 0
    for line in rd:
        try:
            m = decode_witness_frame(line)
        except CanonicalError:
            continue  # garbage gets no ack: the gateway raises a stall
        if isinstance(m, WitnessClose):
            break
        if not isinstance(m, WitnessHead) or m.tick <= last_tick or m.seq < last_seq:
            continue  # never anchor a regressing head; the gateway sees no ack and raises a stall
        count += 1
        cp = WitnessCheckpoint(witness_id="ks.witness", seq=m.seq, tick=m.tick, head=m.head, count=count, sig=None)
        cp = cp.with_sig(sign_hex(key, cp.signing_bytes()))
        data = cp.to_canonical() + b"\n"
        os.write(heads_fd, data)
        os.write(out_fd, data)
        sock.sendall(data)
        last_tick, last_seq = cp.tick, cp.seq
    os.close(out_fd)
    os.close(heads_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
