"""RT8b forged or mismatched witness ack (S4-01, kabir's B3-35 mutation review: with the ack signature check in
``WitnessLink._ingest`` deleted, 0 tests failed).

Attacker: whoever can write the gateway end of the witness socket (a compromised witness process, or a bug that
crosses the channel). An agent cannot: the link is a path-less socketpair between the gateway and the witness uid.
The attacker plays the witness side of the protocol here, byte for byte, so the gateway's real ``WitnessLink`` is
what is under test.

THREAT-MODEL claim defended: "tamper-evident up to the last witnessed head". The anchor (``newest``) only ever
holds a checkpoint the witness key signed for the exact ``(seq, head, tick)`` the gateway pushed; anything else is
a stall (``push`` -> ``None``, F6) and ``newest`` does not move.
"""

from __future__ import annotations

import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ks.contracts import WitnessCheckpoint
from ks.identity import pub_hex, sign_hex
from ks.witness import WitnessLink

H1, H2, H3 = "11" * 32, "22" * 32, "33" * 32
WITNESS, ATTACKER = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


class _Proc:
    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


def _cp(seq, head, tick, count, key=WITNESS):
    cp = WitnessCheckpoint(witness_id="ks.witness", seq=seq, tick=tick, head=head, count=count, sig=None)
    return cp if key is None else cp.with_sig(sign_hex(key, cp.signing_bytes()))


@pytest.fixture
def chan():
    gw, wit = socket.socketpair()
    lk = WitnessLink(gw, _Proc())
    lk.pub = pub_hex(WITNESS)  # as after init(): the key the real witness announced
    yield lk, wit
    gw.close()
    wit.close()


def _ack(wit, *lines: bytes):
    wit.sendall(b"".join(x + b"\n" for x in lines))


def _honest_first(lk, wit):
    a = _cp(1, H1, 1, 1)
    _ack(wit, a.to_canonical())
    assert lk.push(1, H1, 1, timeout_s=2) == a and lk.newest == a
    return a


def test_rt8b_ack_signed_by_another_key_is_a_stall(chan):
    lk, wit = chan
    a = _honest_first(lk, wit)
    _ack(wit, _cp(2, H2, 2, 2, key=ATTACKER).to_canonical())
    assert lk.push(2, H2, 2, timeout_s=0.3) is None
    assert lk.newest == a  # mutation: drop the verify_hex check in _ingest -> newest becomes the forged ack


def test_rt8b_ack_edited_after_signing_is_a_stall(chan):
    lk, wit = chan
    a = _honest_first(lk, wit)
    good = _cp(2, H2, 2, 2)
    bumped = WitnessCheckpoint.model_validate({**good.model_dump(), "count": 99})  # witness sig over count 2
    _ack(wit, bumped.to_canonical())
    assert lk.push(2, H2, 2, timeout_s=0.3) is None and lk.newest == a


def test_rt8b_unsigned_or_garbage_ack_is_a_stall(chan):
    lk, wit = chan
    a = _honest_first(lk, wit)
    _ack(wit, _cp(2, H2, 2, 2, key=None).to_canonical(), b'{"contract":"ks.witness/1"')
    assert lk.push(2, H2, 2, timeout_s=0.3) is None and lk.newest == a


def test_rt8b_validly_signed_but_mismatched_ack_does_not_move_the_anchor(chan):
    """A real witness signature over a head the gateway never pushed (wrong head, wrong seq, or a forged late ack for
    an earlier tick) is not this run's checkpoint: stall, and ``newest`` stays put."""
    lk, wit = chan
    a = _honest_first(lk, wit)
    _ack(wit, _cp(2, H3, 2, 2).to_canonical())                         # same tick, other head
    assert lk.push(2, H2, 2, timeout_s=0.3) is None and lk.newest == a
    _ack(wit, _cp(7, H2, 3, 3).to_canonical())                         # same tick, other seq
    assert lk.push(2, H2, 3, timeout_s=0.3) is None and lk.newest == a
    honest = _cp(2, H2, 4, 4)
    _ack(wit, _cp(5, H3, 1, 9).to_canonical(), honest.to_canonical())  # "late ack" of tick 1, wrong head
    assert lk.push(2, H2, 4, timeout_s=0.3) is None and lk.newest == a  # a bad ack fails closed: stall
    wit.close()
    assert lk.close(timeout_s=0.5) == honest                            # the genuine ack still lands; count 9 never


def test_rt8b_honest_late_ack_still_moves_the_anchor(chan):
    """Control (SKEL-01 M1): a late but genuine ack of an earlier stalled tick is still recorded in ``newest``."""
    lk, wit = chan
    _honest_first(lk, wit)
    assert lk.push(2, H2, 2, timeout_s=0.2) is None                    # stall: no ack yet
    late, now = _cp(2, H2, 2, 2), _cp(3, H3, 3, 3)
    _ack(wit, late.to_canonical(), now.to_canonical())
    assert lk.push(3, H3, 3, timeout_s=2) == now and lk.newest == now


def test_rt8b_forged_ack_drained_at_close_is_not_the_anchor(chan):
    lk, wit = chan
    a = _honest_first(lk, wit)
    _ack(wit, _cp(1, H1, 1, 50, key=ATTACKER).to_canonical(), _cp(9, H3, 9, 51).to_canonical())
    wit.close()
    assert lk.close(timeout_s=0.5) == a
