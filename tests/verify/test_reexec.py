"""B3-25: reexec_of cross-record check (F9, reexec_invalid)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
from test_contracts_13 import _rechain, _seal  # noqa: E402
from .test_window import _ctl, _rec  # noqa: E402

from ks.contracts import ControlOp, Decision, Reason, Record  # noqa: E402
from ks.verify.reexec import reexec_pass  # noqa: E402
from ks.verify.window import Violation  # noqa: E402


def replace(r, **over):
    f = {k: v for k, v in r.__dict__.items() if k not in ("prev_hash", "hash", "gw_sig", "contract")}
    return Record.seal(prev_hash="0" * 64, **{**f, **over})


def _hold(seq, reason=Reason.NEEDS_APPROVAL):
    return replace(_rec(seq, 5, "docs", "docs.purge", {"d": 1}, conn="c-3"), decision=Decision.HOLD, reason=reason)


def _re(seq, of, agent="docs", args=None, conn="c-3"):
    r = _rec(seq, 6, agent, "docs.purge", {"d": 1} if args is None else args, conn=conn)
    h = _hold(of)
    if agent == "docs" and args is None:
        return replace(r, reexec_of=of, envelope=h.envelope, envelope_hash=h.envelope_hash)
    return replace(r, reexec_of=of, envelope_hash=h.envelope_hash)  # same claimed hash, different envelope/agent


def _unhold(seq, target="action:r-000001"):
    return _ctl(seq, 6, ControlOp.UNHOLD, target)


def _check(*recs):
    reexec_pass(_rechain(*recs))


def _bad(*recs):
    with pytest.raises(Violation) as e:
        _check(*recs)
    assert e.value.reason == "reexec_invalid"
    return e.value.first_bad


def test_honest_reexec_verifies():
    _check(_hold(1), _unhold(2), _re(3, 1))


def test_reexec_of_non_hold():
    assert _bad(_rec(1, 5, "docs", "docs.purge", {"d": 1}, conn="c-3"), _unhold(2), _re(3, 1)) == 3


def test_hold_reexecuted_twice():
    assert _bad(_hold(1), _unhold(2), _re(3, 1), _unhold(4), _re(5, 1)) == 5


def test_reexec_by_other_agent():
    assert _bad(_hold(1), _unhold(2), _re(3, 1, agent="billing")) == 3


def test_reexec_without_unhold():
    assert _bad(_hold(1), _re(2, 1)) == 2
    assert _bad(_hold(1), _unhold(2, "action:r-000009"), _re(3, 1)) == 3


def test_reexec_of_non_approval_hold():
    assert _bad(_hold(1, Reason.SENSITIVE_FIELD),
                _unhold(2), _re(3, 1)) == 3


def test_reexec_with_different_envelope():
    assert _bad(_hold(1), _unhold(2), replace(_re(3, 1), envelope_hash="b" * 64)) == 3
