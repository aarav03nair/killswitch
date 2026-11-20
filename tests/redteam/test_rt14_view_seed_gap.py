"""RT14 view-sourced seed gap (S4-20): rogue crm makes bad write 1 (S-22 price x10), then builds bad write 2
(S-17 iban -> attacker) from its *view* of write 1. The alert names write 2 only. Taint (B3-45 option C) follows self
reads through ``tool`` entries only, so t0 starts at write 2; the literal ADR-05 walk reaches write 1.

THREAT-MODEL claim defended: the limit is visible, not silent. ``ks recover --dry-run`` prints ``t0_seq_est_literal``
and a nonzero ``t0_delta`` with the review warning. Deleting that warning in ``ks.recovery.dryrun.render`` fails this test.
"""

from __future__ import annotations

import re

from ks.runtime.setup import hero_tick

from .conftest import ks, world_run

SEED, TICKS = 2, 30
T0 = hero_tick(SEED, TICKS)

RT14 = '''
from ks.world.registry import ATTACKER_IBAN
def on_tick(ctx, t):
    if t == {t0}:   # write 1: a bad price (view-delivered later)
        ctx.send("crm.update_supplier", {{"supplier": "S-22", "set": {{"price": 99999}}}})
    if t == {t1}:   # write 2: built from the view of write 1 (the S-22 row it just wrote)
        ctx.send("crm.update_supplier", {{"supplier": "S-17", "set": {{"iban": ATTACKER_IBAN}}}})
'''


def test_rt14_view_sourced_gap_is_printed(base):
    run = world_run(base, "rt14", rogue=RT14.format(t0=T0, t1=T0 + 2), slot="crm", seed=SEED, ticks=TICKS)
    recs = run.records()
    w = [r for r in recs if r.attributed_agent == "crm" and r.write_set and r.seq > 1]
    assert len(w) >= 2, [r.seq for r in w]
    assert any(e.source == "view" and e.obj.startswith("suppliers:S-22") for e in w[1].read_set), w[1].read_set
    p = ks("recover", run.dir, "--dry-run")
    out = p.stdout + p.stderr
    m = re.search(r"t0_seq_est (\d+)\s+literal walk (\d+)\s+t0_delta (\d+)", out)
    assert m, out
    assert int(m.group(3)) != 0 and int(m.group(1)) - int(m.group(2)) == int(m.group(3)), out
    assert "view-only self-reads not followed" in out, out  # the warning: delete it in dryrun.render and this fails
