"""X-Wing hybrid KEM: X25519 + ML-KEM-768.

Implements the construction from draft-connolly-cfrg-xwing-kem and is checked
against that draft's test vectors (tests/test_hybrid.py).

Why hybrid: ML-KEM (FIPS 203) is new. If lattice cryptanalysis improves, the
X25519 half still protects the session; if a quantum computer breaks X25519,
the ML-KEM half does. The shared secret is safe as long as *either* holds,
which also defeats "harvest now, decrypt later" collection of today's traffic.

Combiner:  ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || label )

ML-KEM ciphertexts are already bound to their shared secret by the FO
transform, so only the X25519 transcript needs to go into the hash.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .primitives import CryptoError

LABEL = b"\\.//^\\"  # the X-Wing label, an ASCII drawing of the ship
MLKEM_PK_LEN = 1184
MLKEM_CT_LEN = 1088
X25519_LEN = 32
PUBLIC_KEY_LEN = MLKEM_PK_LEN + X25519_LEN  # 1216
CIPHERTEXT_LEN = MLKEM_CT_LEN + X25519_LEN  # 1120
SHARED_SECRET_LEN = 32
SEED_LEN = 32

ALGORITHM = "X-Wing (X25519 + ML-KEM-768)"


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()


def _x25519(private: X25519PrivateKey, public_bytes: bytes) -> bytes:
    try:
        # `cryptography` raises on an all-zero result, which rejects the
        # small-order points an attacker could send to force a known secret.
        return private.exchange(X25519PublicKey.from_public_bytes(public_bytes))
    except ValueError:
        raise CryptoError("invalid X25519 share") from None


@dataclass(frozen=True)
class HybridPrivateKey:
    """Decapsulation key. Holds only the 32-byte seed; both halves are re-derived."""

    seed: bytes

    @classmethod
    def generate(cls) -> "HybridPrivateKey":
        return cls(os.urandom(SEED_LEN))

    def _expand(self) -> tuple[mlkem.MLKEM768PrivateKey, X25519PrivateKey]:
        if len(self.seed) != SEED_LEN:
            raise CryptoError("invalid seed")
        expanded = hashlib.shake_256(self.seed).digest(96)
        return (
            mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),
            X25519PrivateKey.from_private_bytes(expanded[64:96]),
        )

    def public_bytes(self) -> bytes:
        sk_m, sk_x = self._expand()
        return sk_m.public_key().public_bytes_raw() + sk_x.public_key().public_bytes_raw()

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != CIPHERTEXT_LEN:
            raise CryptoError("invalid ciphertext length")
        ct_m, ct_x = ciphertext[:MLKEM_CT_LEN], ciphertext[MLKEM_CT_LEN:]
        sk_m, sk_x = self._expand()
        try:
            # ML-KEM uses implicit rejection: a tampered ciphertext yields a
            # pseudorandom secret instead of an error, so there is no
            # decryption oracle. The failure shows up later as an AEAD error.
            ss_m = sk_m.decapsulate(ct_m)
        except ValueError:
            raise CryptoError("invalid ML-KEM ciphertext") from None
        ss_x = _x25519(sk_x, ct_x)
        return _combine(ss_m, ss_x, ct_x, sk_x.public_key().public_bytes_raw())


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret) for a peer's hybrid public key."""
    if len(public_key) != PUBLIC_KEY_LEN:
        raise CryptoError("invalid public key length")
    pk_m, pk_x = public_key[:MLKEM_PK_LEN], public_key[MLKEM_PK_LEN:]
    try:
        # from_public_bytes performs the FIPS 203 modulus check on the key.
        ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    except ValueError:
        raise CryptoError("invalid ML-KEM public key") from None
    ephemeral = X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes_raw()
    ss_x = _x25519(ephemeral, pk_x)
    return ct_m + ct_x, _combine(ss_m, ss_x, ct_x, pk_x)
