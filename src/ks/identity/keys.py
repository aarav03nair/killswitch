"""Ed25519 keys held in memory on the gateway side (ADR-01 §1-2). Private keys never touch the disk.

``fresh``: a random key per principal per run (the witness makes its own in its process, E4).
``repro``: ``HKDF-SHA256(secret, salt=seed as 8 bytes big-endian, info=b"ks/key/v1/" + principal)`` gives
the 32-byte Ed25519 seed, so a replay is byte-identical. Repro is **not a security run** (X7).
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ks.contracts import KeyEntry, Keyring

__all__ = ["KEY_INFO", "derive_key_bytes", "pub_hex", "sign_hex", "verify_hex", "load_repro_secret", "KeyStore"]

KEY_INFO = b"ks/key/v1/"
MIN_SECRET_BYTES = 32


def derive_key_bytes(secret: bytes, seed: int, principal: str) -> bytes:
    """Repro-mode Ed25519 private seed for ``principal`` (ADR-00 "Keys")."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=seed.to_bytes(8, "big"),
                info=KEY_INFO + principal.encode()).derive(secret)


def pub_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_hex(priv: Ed25519PrivateKey, data: bytes) -> str:
    return priv.sign(data).hex()


def verify_hex(pub: str, sig: str, data: bytes) -> bool:
    """True iff ``sig`` (hex) is a valid Ed25519 signature of ``data`` under ``pub`` (hex). Never raises."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def load_repro_secret(path: str | os.PathLike[str]) -> bytes:
    """Read the repro secret: a regular file owned by us, mode 0600 or stricter, >= 32 bytes (ADR-00)."""
    p = Path(path)
    st = p.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{p}: not a regular file")
    if st.st_mode & 0o077:
        raise ValueError(f"{p}: mode {stat.S_IMODE(st.st_mode):o}, must be 0600")
    if st.st_uid != os.geteuid():
        raise ValueError(f"{p}: not owned by uid {os.geteuid()}")
    data = p.read_bytes()
    if len(data) < MIN_SECRET_BYTES:
        raise ValueError(f"{p}: secret shorter than {MIN_SECRET_BYTES} bytes")
    return data


class KeyStore:
    """Private keys of the gateway-side principals (gateway, monitor, operator, recovery, every agent).
    The witness key is not here in fresh mode."""

    def __init__(self, keys: dict[str, Ed25519PrivateKey]):
        self._keys = dict(keys)

    @classmethod
    def create(cls, principals: Iterable[str], *, key_mode: str, seed: int, secret: bytes | None = None) -> KeyStore:
        if key_mode == "fresh":
            return cls({p: Ed25519PrivateKey.generate() for p in principals})
        if key_mode == "repro":
            if secret is None:
                raise ValueError("repro key mode needs a secret")
            return cls({p: Ed25519PrivateKey.from_private_bytes(derive_key_bytes(secret, seed, p)) for p in principals})
        raise ValueError(f"unknown key_mode {key_mode!r}")

    def private(self, principal: str) -> Ed25519PrivateKey:
        return self._keys[principal]

    def signer(self, principal: str) -> Callable[[bytes], str]:
        """A sign(bytes) -> hex function bound to one principal (the key itself stays here)."""
        key = self._keys[principal]
        return lambda data: sign_hex(key, data)

    def keyring(self, extra: dict[str, str]) -> Keyring:
        """Public keyring: these keys plus ``extra`` (principal -> pub hex, e.g. the witness's)."""
        pubs = {p: pub_hex(k) for p, k in self._keys.items()} | extra
        return Keyring(keys=tuple(KeyEntry(principal=p, pub=pubs[p]) for p in sorted(pubs)))
