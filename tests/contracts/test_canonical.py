"""ks-canon/1 rules."""

import pytest

from ks.contracts import canonical
from ks.contracts.canonical import MAX_SAFE_INT, CanonicalError, NonCanonicalError


def test_sorted_keys_no_whitespace_utf8():
    assert canonical.dumps({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()


def test_key_order_is_utf16_code_units():
    # U+FF61 sorts after U+1F600 in code point order, before it in UTF-16 (JCS rule)
    assert canonical.dumps({"\U0001f600": 1, "｡": 2}) == '{"\U0001f600":1,"｡":2}'.encode()


def test_string_escaping_matches_jcs():
    assert canonical.dumps("a\"\\\n\x01\x7f ") == b'"a\\"\\\\\\n\\u0001\x7f\xe2\x80\xa8"'


@pytest.mark.parametrize("bad", [1.0, float("nan"), float("inf"), b"x", bytearray(b"x"), MAX_SAFE_INT + 1,
                                 -MAX_SAFE_INT - 1, {1: "a"}, "\ud800", object()])
def test_rejects(bad):
    with pytest.raises(CanonicalError):
        canonical.dumps(bad)


def test_bool_is_not_int():
    assert canonical.dumps([True, 1]) == b"[true,1]"


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":1e3}', b"NaN", b'{"b":1,"a":2}',
                                 b'{"a": 1}', b'"\\u0041"', b"-0", b"\xef\xbb\xbf{}", b'"\\ud800"', b"\xff",
                                 b"9007199254740992"])
def test_loads_strict(raw):
    with pytest.raises(CanonicalError):
        canonical.loads(raw)


def test_loads_roundtrip():
    b = canonical.dumps({"z": [1, -2, "x"], "a": {"k": None}})
    assert canonical.dumps(canonical.loads(b)) == b


def test_non_canonical_is_subclass():
    with pytest.raises(NonCanonicalError):
        canonical.loads(b'{"b":1,"a":2}')


def test_lines():
    assert canonical.loads_line(canonical.dumps_line({"a": 1})) == {"a": 1}
    with pytest.raises(CanonicalError):
        canonical.loads_line(b'{"a":1}\r\n')
