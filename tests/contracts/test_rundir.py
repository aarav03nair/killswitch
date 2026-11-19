"""C6 run dir helper."""

import pytest

from ks.contracts import RunDir
from ks.contracts import rundir as C6

import samples as S


@pytest.fixture
def run(tmp_path):
    s = S.samples()
    rd = RunDir.create(tmp_path / "run", s["run_config"], s["keyring"])
    for r in S.chain():
        rd.append(r)
    rd.append(S.witness(S.chain()[-1]))
    rd.append(S.alert_invariant())
    rd.write_plan(S.plan())
    rd.write_side(s["side_value"])
    return rd


def test_create_and_validate(run):
    assert run.validate() == []
    assert [r.seq for r in run.records()] == [1, 2, 3, 4]
    assert list(run.alerts()) == [S.alert_invariant()]
    assert run.config().hold_window_ticks == 3
    assert run.keyring().pub("crm") == S.pub("crm")
    assert (run.path / C6.sidestore_relpath(S.H_NEW)).is_file()


def test_validate_flags_private_keys(run):
    (run.path / "oracle" / "agent.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
    assert any("private key" in p for p in run.validate())


def test_validate_flags_non_canonical_line(run):
    with open(run.path / C6.RECORD, "ab") as fh:
        fh.write(b'{"seq": 5}\n')
    assert any(p.startswith("record.jsonl:5") for p in run.validate())


def test_validate_flags_seq_gap(tmp_path):
    s = S.samples()
    rd = RunDir.create(tmp_path / "r", s["run_config"], s["keyring"])
    rd.append(S.chain()[1])  # seq 2 on line 1
    assert any("seq 2 != line 1" in p for p in rd.validate())


def test_same_inputs_byte_identical(tmp_path):
    def build(p):
        s = S.samples()
        rd = RunDir.create(p, s["run_config"], s["keyring"])
        for r in S.chain():
            rd.append(r)
        return rd
    a, b = build(tmp_path / "a"), build(tmp_path / "b")
    assert a.determinism_files() == b.determinism_files()
    for f in (C6.CONFIG, C6.KEYS, C6.RECORD):  # same keys here, so even the raw bytes match
        assert (a.path / f).read_bytes() == (b.path / f).read_bytes()
