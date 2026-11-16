"""Long-term identities, hybrid signatures and out-of-band contact cards."""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .primitives import CryptoError, aead_decrypt, aead_encrypt, ct_equal, pack, sha256

ED_PK_LEN, ED_SIG_LEN = 32, 64
MLDSA_PK_LEN, MLDSA_SIG_LEN = 1952, 3309
IDENTITY_PK_LEN = ED_PK_LEN + MLDSA_PK_LEN
SIGNATURE_LEN = ED_SIG_LEN + MLDSA_SIG_LEN
INVITE_SECRET_LEN = 16
CARD_PREFIX = "pqchat1:"
SIGNATURE_ALGORITHM = "Ed25519 + ML-DSA-65"

_SIG_CONTEXT = b"pqchat/v1/identity-signature"


def verify(identity_pk: bytes, signature: bytes, message: bytes) -> None:
    """Verifies a hybrid signature. BOTH halves must be valid.

    An attacker therefore has to forge Ed25519 *and* ML-DSA-65 (FIPS 204) to
    impersonate someone, so authentication survives a break of either scheme.
    """
    if len(identity_pk) != IDENTITY_PK_LEN or len(signature) != SIGNATURE_LEN:
        raise CryptoError("invalid signature")
    # The signed bytes name the public key, so a signature cannot be re-used
    # under a different identity that happens to share one of the two keys.
    signed = pack(_SIG_CONTEXT, identity_pk, message)
    try:
        Ed25519PublicKey.from_public_bytes(identity_pk[:ED_PK_LEN]).verify(signature[:ED_SIG_LEN], signed)
        mldsa.MLDSA65PublicKey.from_public_bytes(identity_pk[ED_PK_LEN:]).verify(signature[ED_SIG_LEN:], signed)
    except (InvalidSignature, ValueError):
        raise CryptoError("invalid signature") from None


def fingerprint(identity_pk: bytes) -> bytes:
    return sha256(b"pqchat/v1/fingerprint", identity_pk)


class Identity:
    """A node's long-term signing identity (classical + post-quantum)."""

    def __init__(self, ed_seed: bytes, mldsa_seed: bytes) -> None:
        self._ed_seed, self._mldsa_seed = ed_seed, mldsa_seed
        self._ed = Ed25519PrivateKey.from_private_bytes(ed_seed)
        self._mldsa = mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_seed)
        self.public_bytes = self._ed.public_key().public_bytes_raw() + self._mldsa.public_key().public_bytes_raw()
        self.fingerprint = fingerprint(self.public_bytes)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(os.urandom(32), os.urandom(32))

    def sign(self, message: bytes) -> bytes:
        signed = pack(_SIG_CONTEXT, self.public_bytes, message)
        return self._ed.sign(signed) + self._mldsa.sign(signed)

    # ------------------------------------------------------------ keystore
    # scrypt is memory-hard, so guessing the passphrase offline costs RAM per
    # attempt and does not scale on GPUs the way a plain hash would.
    _SCRYPT = {"n": 2**15, "r": 8, "p": 1}
    _MAGIC = b"PQCHAT-ID-1"

    def export_encrypted(self, passphrase: str) -> bytes:
        if len(passphrase) < 8:
            raise ValueError("passphrase must be at least 8 characters")
        salt, nonce = os.urandom(16), os.urandom(12)
        key = Scrypt(salt=salt, length=32, **self._SCRYPT).derive(passphrase.encode())
        sealed = aead_encrypt(key, nonce, self._ed_seed + self._mldsa_seed, self._MAGIC)
        return self._MAGIC + salt + nonce + sealed

    @classmethod
    def load_encrypted(cls, blob: bytes, passphrase: str) -> "Identity":
        magic = len(cls._MAGIC)
        if len(blob) != magic + 16 + 12 + 64 + 16 or blob[:magic] != cls._MAGIC:
            raise CryptoError("not a PQ-Chat identity file")
        salt, nonce, sealed = blob[magic : magic + 16], blob[magic + 16 : magic + 28], blob[magic + 28 :]
        key = Scrypt(salt=salt, length=32, **cls._SCRYPT).derive(passphrase.encode())
        seeds = aead_decrypt(key, nonce, sealed, cls._MAGIC)
        return cls(seeds[:32], seeds[32:])


@dataclass(frozen=True)
class ContactCard:
    """What two people exchange out-of-band (in person, QR code, another channel).

    It pins the peer's identity (fingerprint) and carries a secret that
    authorises the holder to connect. The network path never sees either in
    the clear, so a man-in-the-middle on the TCP connection has nothing to
    substitute.
    """

    host: str
    port: int
    fingerprint: bytes
    invite_secret: bytes

    def encode(self) -> str:
        host = self.host.encode("ascii")
        body = struct.pack(">BH", len(host), self.port) + host + self.fingerprint + self.invite_secret
        # Short checksum so a mistyped card fails here with a clear message
        # instead of as an unexplained handshake error.
        checksum = sha256(b"pqchat/v1/card", body)[:4]
        return CARD_PREFIX + base64.urlsafe_b64encode(body + checksum).decode().rstrip("=")

    @classmethod
    def decode(cls, text: str) -> "ContactCard":
        text = text.strip()
        if not text.startswith(CARD_PREFIX) or len(text) > 512:
            raise ValueError("not a PQ-Chat contact card")
        encoded = text[len(CARD_PREFIX) :]
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except ValueError:
            raise ValueError("contact card is not valid base64") from None
        if len(raw) < 3 + 1 + 32 + INVITE_SECRET_LEN + 4:
            raise ValueError("contact card is too short")
        body, checksum = raw[:-4], raw[-4:]
        if not ct_equal(sha256(b"pqchat/v1/card", body)[:4], checksum):
            raise ValueError("contact card checksum mismatch (typo?)")
        host_len, port = struct.unpack_from(">BH", body)
        if len(body) != 3 + host_len + 32 + INVITE_SECRET_LEN or not 0 < port < 65536:
            raise ValueError("contact card is malformed")
        try:
            host = body[3 : 3 + host_len].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("contact card is malformed") from None
        rest = body[3 + host_len :]
        return cls(host, port, rest[:32], rest[32:])


def safety_number(fp_a: bytes, fp_b: bytes) -> str:
    """Short code both users read aloud to confirm they hold the same keys.

    Fingerprints are sorted so both sides compute the same string. 60 decimal
    digits is about 199 bits, well past what a collision search can reach.
    """
    low, high = sorted((fp_a, fp_b))
    digest = sha256(b"pqchat/v1/safety-number", low, high)
    # Twelve groups of five digits. Each group reduces a 64-bit value modulo
    # 10^5, so the modulo bias is far too small to matter.
    groups = []
    for i in range(12):
        chunk = sha256(digest, bytes([i]))[:8]
        groups.append(f"{int.from_bytes(chunk, 'big') % 100000:05d}")
    return " ".join(groups)


