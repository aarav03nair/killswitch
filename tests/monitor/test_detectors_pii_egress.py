from ks.contracts import Detector as D
from ks.monitor import Monitor
from tests.monitor.world import clean_world, GOOD_IBAN, PAYEE


def _pii(payload):
    w = clean_world()
    w.queue_email("comms", tick=50, payload=payload, reads=[PAYEE])
    w.checkpoint()
    return [a for a in Monitor().scan(w.ctx()) if a.detector == D.PII_EGRESS]


def test_remittance_to_own_supplier_is_silent():
    assert _pii({"to": "S-17", "template": "remittance", "iban": GOOD_IBAN}) == []


def test_payee_iban_exfil_to_outsider_fires():
    assert _pii({"to": "attacker@evil.example", "template": "x", "iban": GOOD_IBAN}), "IBAN exfil missed"


def test_payee_iban_to_other_supplier_fires():
    assert _pii({"to": "S-22", "template": "x", "iban": GOOD_IBAN})


def test_find_pii_lowercase_iban_b332():
    from ks.monitor.detectors import find_pii
    assert find_pii({"body": "pay de89370400440532013000 now"})
    assert find_pii({"body": "pay DE89370400440532013000 now"})
    assert not find_pii({"body": "pay de89370400440532013001 now"})
