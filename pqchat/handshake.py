"""Authenticated hybrid key agreement (SIGMA-I shape, X-Wing KEM, PSK-bound).

    I -> R   m1 = version || nonce_i || eph_pk_i || invite_tag
    I <- R   m2 = nonce_r || kem_ct || AEAD_kr( id_r, sig_r )
    I -> R   m3 = AEAD_ki( id_i, sig_i, ratchet_pk_i )

Properties this is designed for:
  * Hybrid secrecy   - the session key comes from X25519 + ML-KEM-768.
  * Forward secrecy  - eph_pk_i is used once and discarded.
  * Mutual auth      - hybrid signatures over the running transcript hash.
                       I checks R against the fingerprint pinned by the
                       contact card; R knows I held the invite secret.
  * Identity hiding  - long-term keys only travel encrypted. Because the
                       invite secret is mixed into the key schedule, even an
                       active attacker without the card learns no identity.
  * DoS resistance   - m1 carries a MAC under the invite secret, so a
                       stranger is dropped before any public-key operation.

The classes are sans-IO: bytes in, bytes out. The network layer only moves
frames, which keeps the state machine easy to test and hard to desync.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import PROTOCOL_VERSION, hybrid
from .identity import IDENTITY_PK_LEN, SIGNATURE_LEN, ContactCard, Identity, fingerprint, verify
from .primitives import (
    CryptoError,
    aead_decrypt,
    aead_encrypt,
    ct_equal,
    hkdf,
    hkdf_expand,
    hmac_sha256,
    pack,
    sha256,
    unpack,
)

NONCE_LEN = 32
TAG_LEN = 16
M1_LEN = 1 + NONCE_LEN + hybrid.PUBLIC_KEY_LEN + TAG_LEN
# Each handshake key encrypts exactly one message, so a fixed nonce is safe.
_ZERO_NONCE = bytes(12)
_LABEL = b"pqchat/v1/handshake"


@dataclass(frozen=True)
class HandshakeResult:
    root_key: bytes
    session_id: bytes
    peer_identity: bytes  # peer's long-term hybrid public key
    transcript_hash: bytes

    @property
    def peer_fingerprint(self) -> bytes:
        return fingerprint(self.peer_identity)


def _psk(invite_secret: bytes) -> bytes:
    return sha256(b"pqchat/v1/psk", invite_secret)


def _invite_tag(psk: bytes, m1_body: bytes) -> bytes:
    return hmac_sha256(psk, b"pqchat/v1/invite-tag" + m1_body)[:TAG_LEN]


class _Keys:
    """Key schedule shared by both roles. Every output is bound to the transcript."""

    def __init__(self, shared_secret: bytes, psk: bytes, th2: bytes) -> None:
        # The PSK is the HKDF salt: without the invite secret the handshake
        # keys cannot be derived even by someone who could break the KEM.
        self.prk = hkdf(shared_secret, salt=psk, info=_LABEL + b"/prk" + th2)
        self.k_resp = hkdf_expand(self.prk, info=b"resp")
        self.k_init = hkdf_expand(self.prk, info=b"init")

    def finish(self, th4: bytes, peer_identity: bytes) -> HandshakeResult:
        return HandshakeResult(
            root_key=hkdf_expand(self.prk, info=b"root" + th4),
            session_id=hkdf_expand(self.prk, info=b"sid" + th4, length=16),
            peer_identity=peer_identity,
            transcript_hash=th4,
        )


class Initiator:
    def __init__(self, identity: Identity, card: ContactCard) -> None:
        self._identity = identity
        self._card = card
        self._psk = _psk(card.invite_secret)
        self._ephemeral = hybrid.HybridPrivateKey.generate()
        # First ratchet key. Sent inside m3 rather than re-using the handshake
        # key, so each key pair has exactly one job.
        self.ratchet_key = hybrid.HybridPrivateKey.generate()
        self._th1: bytes | None = None

    def message1(self) -> bytes:
        body = bytes([PROTOCOL_VERSION]) + os.urandom(NONCE_LEN) + self._ephemeral.public_bytes()
        m1 = body + _invite_tag(self._psk, body)
        self._th1 = sha256(_LABEL, m1)
        return m1

    def process_message2(self, m2: bytes) -> tuple[bytes, HandshakeResult]:
        if self._th1 is None:
            raise CryptoError("handshake out of order")
        fixed = NONCE_LEN + hybrid.CIPHERTEXT_LEN
        if len(m2) <= fixed:
            raise CryptoError("malformed message")
        nonce_r, kem_ct, sealed = m2[:NONCE_LEN], m2[NONCE_LEN:fixed], m2[fixed:]

        th2 = sha256(self._th1, nonce_r, kem_ct)
        keys = _Keys(self._ephemeral.decapsulate(kem_ct), self._psk, th2)
        id_r, sig_r = unpack(aead_decrypt(keys.k_resp, _ZERO_NONCE, sealed, th2), 2)

        # Pin first, then verify: the signature only means something if it is
        # from the identity the user was given out-of-band.
        if len(id_r) != IDENTITY_PK_LEN or not ct_equal(fingerprint(id_r), self._card.fingerprint):
            raise CryptoError("peer identity does not match the contact card")
        verify(id_r, sig_r, pack(b"resp", th2))

        th3 = sha256(th2, sealed)
        ratchet_pk = self.ratchet_key.public_bytes()
        sig_i = self._identity.sign(pack(b"init", th3, ratchet_pk))
        m3 = aead_encrypt(keys.k_init, _ZERO_NONCE, pack(self._identity.public_bytes, sig_i, ratchet_pk), th3)
        return m3, keys.finish(sha256(th3, m3), id_r)


class Responder:
    def __init__(self, identity: Identity, invite_secret: bytes) -> None:
        self._identity = identity
        self._psk = _psk(invite_secret)
        self._keys: _Keys | None = None
        self._th3: bytes | None = None

    def process_message1(self, m1: bytes) -> bytes:
        if len(m1) != M1_LEN or m1[0] != PROTOCOL_VERSION:
            raise CryptoError("malformed message")
        body, tag = m1[:-TAG_LEN], m1[-TAG_LEN:]
        # Cheap symmetric check before any asymmetric work or signature.
        if not ct_equal(_invite_tag(self._psk, body), tag):
            raise CryptoError("unknown invite")
        eph_pk_i = body[1 + NONCE_LEN :]

        kem_ct, shared = hybrid.encapsulate(eph_pk_i)
        nonce_r = os.urandom(NONCE_LEN)
        th2 = sha256(sha256(_LABEL, m1), nonce_r, kem_ct)
        self._keys = _Keys(shared, self._psk, th2)

        sig_r = self._identity.sign(pack(b"resp", th2))
        sealed = aead_encrypt(self._keys.k_resp, _ZERO_NONCE, pack(self._identity.public_bytes, sig_r), th2)
        self._th3 = sha256(th2, sealed)
        return nonce_r + kem_ct + sealed

    def process_message3(self, m3: bytes) -> tuple[HandshakeResult, bytes]:
        """Returns the session result and the initiator's first ratchet public key."""
        if self._keys is None or self._th3 is None:
            raise CryptoError("handshake out of order")
        id_i, sig_i, ratchet_pk = unpack(aead_decrypt(self._keys.k_init, _ZERO_NONCE, m3, self._th3), 3)
        if len(id_i) != IDENTITY_PK_LEN or len(sig_i) != SIGNATURE_LEN or len(ratchet_pk) != hybrid.PUBLIC_KEY_LEN:
            raise CryptoError("malformed message")
        verify(id_i, sig_i, pack(b"init", self._th3, ratchet_pk))
        result = self._keys.finish(sha256(self._th3, m3), id_i)
        self._keys = None  # one handshake per object
        return result, ratchet_pk
