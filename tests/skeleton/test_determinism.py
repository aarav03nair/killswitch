"""SKEL-01 / ADR-00 T1, T1b: same seed -> byte-identical (repro) or identical under determinism_view() (fresh)."""

from ks.contracts import DETERMINISTIC_FILES, Exit, RunDir

from .conftest import ks_run, ks_verify


def _raw_deterministic_files(run) -> dict[str, bytes]:
    out = {}
    for pat in DETERMINISTIC_FILES:
        if pat.endswith("/**"):
            out |= {str(p.relative_to(run)): p.read_bytes() for p in sorted((run / pat[:-3]).rglob("*")) if p.is_file()}
        elif (run / pat).is_file():
            out[pat] = (run / pat).read_bytes()
    return out


def test_repro_same_seed_byte_identical(base_dir, repro_secret):
    runs = [base_dir / f"repro-{i}" for i in (1, 2)]
    anchors = [ks_run(r, seed=11, key_mode="repro", extra=("--repro-secret", str(repro_secret)))[1] for r in runs]
    a, b = (_raw_deterministic_files(r) for r in runs)
    assert a == b and {"config.json", "record.jsonl", "witness.jsonl"} <= a.keys()
    assert any(k.startswith("sidestore/") for k in a)
    assert anchors[0] == anchors[1]
    code, rep = ks_verify(runs[0], anchors[0])  # repro is never anchored (X7), even with --head
    assert code == Exit.OK and not rep.anchored and rep.unanchored_reason == "repro_keys"


def test_fresh_same_seed_equal_under_view_but_signatures_differ(base_dir, clean_run):
    other = base_dir / "fresh-2"
    ks_run(other, seed=7)
    a, b = RunDir(clean_run[0]), RunDir(other)
    assert a.determinism_files() == b.determinism_files()
    for name in ("record.jsonl", "witness.jsonl", "keys.json"):
        assert (a.path / name).read_bytes() != (b.path / name).read_bytes()
    for ra, rb in zip(a.records(), b.records(), strict=True):
        assert ra.envelope.sig != rb.envelope.sig and ra.gw_sig != rb.gw_sig
        assert ra.envelope_hash == rb.envelope_hash  # the signed content is the same


def test_different_seed_diverges(base_dir, clean_run):
    other = base_dir / "fresh-seed8"
    ks_run(other, seed=8, extra=("--run-id", "skeleton-s7"))
    assert RunDir(clean_run[0]).determinism_files()["record.jsonl"] != RunDir(other).determinism_files()["record.jsonl"]
