"""Thin, misuse-resistant wrappers around the primitives the protocol uses.

Everything here delegates to `cryptography` (OpenSSL). No algorithm is
implemented by hand; this module only fixes parameters and domain separation
so the rest of the code cannot pick a weak combination by accident.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

try:  # ML-KEM / ML-DSA need a recent `cryptography` built on OpenSSL 3.5+
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
except ImportError as exc:  # pragma: no cover - depends on the installed wheel
    raise ImportError(
        "PQ-Chat needs ML-KEM-768 and ML-DSA-65 support. Upgrade with: pip install -U 'cryptography>=50'"
    ) from exc

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


class CryptoError(Exception):
    """Raised for any authentication or decoding failure.

    One exception type with no detail on purpose: telling a peer *why* a
    ciphertext was rejected is how padding and format oracles are built.
    """


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(ikm: bytes, *, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """HKDF-SHA256 extract-and-expand. `info` is the domain separator."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def hkdf_expand(prk: bytes, *, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise CryptoError("authentication failed") from None


def ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison for secrets and MACs."""
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------- encoding
# Length-prefixed fields. Every variable-length value on the wire or under a
# hash goes through pack(), so two different field lists can never serialise
# to the same bytes (no ambiguity for a signature or transcript hash to hide in).


def pack(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def unpack(data: bytes, count: int) -> list[bytes]:
    """Strict inverse of pack(): exactly `count` fields and no trailing bytes."""
    fields, offset = [], 0
    for _ in range(count):
        if offset + 4 > len(data):
            raise CryptoError("truncated")
        (length,) = struct.unpack_from(">I", data, offset)
        offset += 4
        if offset + length > len(data):
            raise CryptoError("truncated")
        fields.append(data[offset : offset + length])
        offset += length
    if offset != len(data):
        raise CryptoError("trailing data")
    return fields
