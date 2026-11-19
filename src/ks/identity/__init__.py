"""ks.identity: in-memory Ed25519 keys, key modes and the signer handle service (ADR-01). Owner: arjun."""

from .keys import KeyStore, derive_key_bytes, load_repro_secret, pub_hex, sign_hex, verify_hex
from .signer import SignerService

__all__ = ["KeyStore", "SignerService", "derive_key_bytes", "load_repro_secret", "pub_hex", "sign_hex", "verify_hex"]
