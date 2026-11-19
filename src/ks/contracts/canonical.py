"""The ONE canonical serializer (``ks-canon/1``). Signer, gateway, recorder and verify all import it.

Rules (frozen with CON-01):

1. Output is UTF-8 JSON with no insignificant whitespace; object keys are sorted by their UTF-16
   code units (the RFC 8785 JCS rule, which equals code point order for BMP keys).
2. Strings are escaped exactly as RFC 8785 / ECMAScript: only ``"``, ``\\`` and U+0000..U+001F are
   escaped (``\\b \\f \\n \\r \\t`` short forms, otherwise lowercase ``\\u00xx``); everything else is
   literal UTF-8. Lone surrogates are rejected.
3. Integers only, in the I-JSON safe range ``[-(2**53-1), 2**53-1]``. ``seq``, ``tick``, versions,
   epochs and logical times are integers. ``bool`` is never an integer.
4. **Floats are rejected** (also NaN/Infinity). Use integers (minor units, basis points, ticks) or
   decimal strings. With no floats, our output is byte-identical to RFC 8785 JCS.
5. **Bytes are rejected.** Binary goes in as lowercase hex strings (hashes, signatures, nonces).
6. ``None`` -> ``null``; tuples and lists -> arrays; dict keys must be ``str``.
7. Parsing (:func:`loads`) is strict: valid UTF-8, no BOM, no duplicate keys, no floats, and the
   input must already be canonical (re-encoding must reproduce it byte for byte).

Contract models serialize via ``model.to_canonical()``, which calls :func:`dumps`.
"""

from __future__ import annotations

import json
from json.encoder import encode_basestring
from typing import Any

__all__ = ["MAX_SAFE_INT", "CanonicalError", "NonCanonicalError", "dumps", "loads", "dumps_line", "loads_line"]

MAX_SAFE_INT = 2**53 - 1
"""Largest integer allowed anywhere in canonical data (I-JSON / JCS safe range)."""


class CanonicalError(ValueError):
    """Value cannot be represented in ks-canon/1 (float, bytes, out-of-range int, bad key...)."""


class NonCanonicalError(CanonicalError):
    """Input parsed, but is not the canonical encoding of its own value."""


def _key(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")


def _check_str(s: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogate
        raise CanonicalError("string contains a lone surrogate") from exc


def _enc(o: Any, out: list[str]) -> None:
    if o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, int):
        v = int(o)
        if not -MAX_SAFE_INT <= v <= MAX_SAFE_INT:
            raise CanonicalError(f"integer {v} outside the safe range ±(2**53-1)")
        out.append(str(v))
    elif isinstance(o, float):
        raise CanonicalError("floats are not allowed in ks-canon/1; use integers or decimal strings")
    elif isinstance(o, str):
        s = str.__str__(o)  # plain str, also for StrEnum members
        _check_str(s)
        out.append(encode_basestring(s))
    elif isinstance(o, (bytes, bytearray, memoryview)):
        raise CanonicalError("bytes are not allowed in ks-canon/1; hex-encode them")
    elif isinstance(o, (list, tuple)):
        out.append("[")
        for i, item in enumerate(o):
            if i:
                out.append(",")
            _enc(item, out)
        out.append("]")
    elif isinstance(o, dict):
        for k in o:
            if not isinstance(k, str):
                raise CanonicalError(f"object keys must be str, got {type(k).__name__}")
            _check_str(k)
        out.append("{")
        for i, k in enumerate(sorted(o, key=_key)):
            if i:
                out.append(",")
            out.append(encode_basestring(str.__str__(k)))
            out.append(":")
            _enc(o[k], out)
        out.append("}")
    elif hasattr(o, "__ks_canonical__"):
        _enc(o.__ks_canonical__(), out)
    else:
        raise CanonicalError(f"type {type(o).__name__} is not canonically serializable")


def dumps(obj: Any) -> bytes:
    """Encode ``obj`` as ks-canon/1 bytes. Raises :class:`CanonicalError` on anything outside the rules."""
    out: list[str] = []
    _enc(obj, out)
    return "".join(out).encode("utf-8")


def _no_float(s: str) -> Any:
    raise CanonicalError(f"float literal {s!r} not allowed")


def _no_const(s: str) -> Any:
    raise CanonicalError(f"constant {s!r} not allowed")


def _int(s: str) -> int:
    v = int(s)
    if not -MAX_SAFE_INT <= v <= MAX_SAFE_INT:
        raise CanonicalError(f"integer {s} outside the safe range")
    return v


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise CanonicalError(f"duplicate key {k!r}")
        d[k] = v
    return d


def loads(data: bytes) -> Any:
    """Strictly parse canonical bytes. Raises :class:`NonCanonicalError` if ``data`` is not canonical."""
    if not isinstance(data, (bytes, bytearray)):
        raise CanonicalError("loads() takes bytes")
    data = bytes(data)
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalError("BOM not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalError("input is not valid UTF-8") from exc
    try:
        obj = json.loads(text, parse_float=_no_float, parse_int=_int, parse_constant=_no_const,
                         object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise CanonicalError(f"invalid JSON: {exc}") from exc
    if dumps(obj) != data:
        raise NonCanonicalError("input is valid JSON but not in canonical form")
    return obj


def dumps_line(obj: Any) -> bytes:
    """One JSON-lines frame: canonical bytes + ``\\n`` (record files, witness file, sockets)."""
    return dumps(obj) + b"\n"


def loads_line(line: bytes) -> Any:
    """Inverse of :func:`dumps_line`; the line must end in exactly one ``\\n``."""
    if not line.endswith(b"\n") or line.endswith(b"\r\n"):
        raise CanonicalError("frame must end with a single LF")
    return loads(line[:-1])
