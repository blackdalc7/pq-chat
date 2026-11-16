"""Post-quantum double ratchet.

Signal's Double Ratchet with the Diffie-Hellman step replaced by an X-Wing
encapsulation, so every asymmetric ratchet step mixes fresh X25519 *and*
fresh ML-KEM-768 entropy into the root key.

  Symmetric ratchet   every message gets its own key, derived from a chain
                      key that is immediately replaced (forward secrecy:
                      stealing today's state does not decrypt yesterday).
  KEM ratchet         each time the conversation changes direction, the
                      sender generates a new key pair and encapsulates to
                      the peer's latest one (post-compromise security: an
                      attacker who copied the state is locked out again
                      once the victim has ratcheted in a fresh key pair).

Header (sent in clear, authenticated as AEAD associated data):

    ratchet_pk (1216) || kem_ct (1120) || pn (u32) || n (u32)
"""

from __future__ import annotations

import copy
import struct
from dataclasses import dataclass, field

from . import hybrid
from .primitives import CryptoError, aead_decrypt, aead_encrypt, hkdf, hmac_sha256, sha256

HEADER_LEN = hybrid.PUBLIC_KEY_LEN + hybrid.CIPHERTEXT_LEN + 8
PAD_BLOCK = 256
MAX_PLAINTEXT = 16 * 1024
# Bounds on out-of-order handling. Without them a peer could send n = 2^32-1
# and make us derive (and store) billions of keys.
MAX_SKIP = 256
MAX_STORED_KEYS = 1024


def _kdf_root(root_key: bytes, kem_secret: bytes) -> tuple[bytes, bytes]:
    out = hkdf(kem_secret, salt=root_key, info=b"pqchat/v1/ratchet/root", length=64)
    return out[:32], out[32:]


def _kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """Returns (next_chain_key, message_key). One-way: no path back to chain_key."""
    return hmac_sha256(chain_key, b"\x02"), hmac_sha256(chain_key, b"\x01")


def _message_cipher(message_key: bytes) -> tuple[bytes, bytes]:
    # Key and nonce both come from the single-use message key, so nonce
    # reuse under one key is impossible by construction.
    material = hkdf(message_key, salt=bytes(32), info=b"pqchat/v1/ratchet/message", length=44)
    return material[:32], material[32:]


def pad(data: bytes) -> bytes:
    """ISO/IEC 7816-4 padding to a multiple of PAD_BLOCK.

    Hides the exact message length: an observer learns only which 256-byte
    bucket a message falls in, not whether you typed "yes" or "no".
    """
    padded_len = (len(data) // PAD_BLOCK + 1) * PAD_BLOCK
    return data + b"\x80" + bytes(padded_len - len(data) - 1)


def unpad(data: bytes) -> bytes:
    stripped = data.rstrip(b"\x00")
    if not stripped or stripped[-1] != 0x80 or len(data) % PAD_BLOCK:
        raise CryptoError("invalid padding")
    return stripped[:-1]


def key_tag(key: bytes | None) -> str | None:
    """Short public identifier for a secret key, safe to show in a UI."""
    return sha256(b"pqchat/v1/display-tag", key)[:8].hex() if key else None


@dataclass
class _State:
    root_key: bytes
    own_key: hybrid.HybridPrivateKey | None
    own_pk: bytes | None
    peer_pk: bytes | None
    send_ct: bytes | None = None
    send_chain: bytes | None = None
    recv_chain: bytes | None = None
    send_n: int = 0
    recv_n: int = 0
    prev_send_n: int = 0
    epoch: int = 0
    # (sha256(ratchet_pk)[:8], n) -> message key, for late / reordered messages
    skipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict)

    def clone(self) -> "_State":
        dup = copy.copy(self)
        dup.skipped = dict(self.skipped)
        return dup


@dataclass(frozen=True)
class MessageInfo:
    """Metadata about one encrypted or decrypted message, for the UI."""

    epoch: int
    n: int
    key_tag: str


class Ratchet:
    def __init__(self, state: _State, session_id: bytes) -> None:
        self._s = state
        self._sid = session_id

    @classmethod
    def as_responder(cls, root_key: bytes, session_id: bytes, peer_ratchet_pk: bytes) -> "Ratchet":
        """The responder knows the initiator's ratchet key and takes the first step."""
        state = _State(root_key=root_key, own_key=None, own_pk=None, peer_pk=peer_ratchet_pk)
        cls._send_step(state)
        return cls(state, session_id)

    @classmethod
    def as_initiator(cls, root_key: bytes, session_id: bytes, own_ratchet_key: hybrid.HybridPrivateKey) -> "Ratchet":
        """The initiator can receive straight away and send after the first message arrives."""
        state = _State(root_key=root_key, own_key=own_ratchet_key, own_pk=own_ratchet_key.public_bytes(), peer_pk=None)
        return cls(state, session_id)

    # ----------------------------------------------------------- ratchet
    @staticmethod
    def _send_step(s: _State) -> None:
        s.own_key = hybrid.HybridPrivateKey.generate()
        s.own_pk = s.own_key.public_bytes()
        s.send_ct, secret = hybrid.encapsulate(s.peer_pk)
        s.root_key, s.send_chain = _kdf_root(s.root_key, secret)
        s.prev_send_n, s.send_n = s.send_n, 0
        s.epoch += 1

    @staticmethod
    def _skip(s: _State, until: int) -> None:
        if s.recv_chain is None:
            return
        if until - s.recv_n > MAX_SKIP:
            raise CryptoError("too many skipped messages")
        pk_id = sha256(s.peer_pk)[:8]
        while s.recv_n < until:
            s.recv_chain, message_key = _kdf_chain(s.recv_chain)
            s.skipped[(pk_id, s.recv_n)] = message_key
            s.recv_n += 1
        while len(s.skipped) > MAX_STORED_KEYS:
            s.skipped.pop(next(iter(s.skipped)))  # drop the oldest

    @property
    def can_send(self) -> bool:
        return self._s.send_chain is not None

    def encrypt(self, plaintext: bytes) -> tuple[bytes, MessageInfo]:
        s = self._s
        if s.send_chain is None:
            raise CryptoError("cannot send before the first message is received")
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError("message too long")

        s.send_chain, message_key = _kdf_chain(s.send_chain)
        header = s.own_pk + s.send_ct + struct.pack(">II", s.prev_send_n, s.send_n)
        key, nonce = _message_cipher(message_key)
        # The header is bound to the ciphertext and to this session: it cannot
        # be swapped, edited or replayed into another conversation.
        ciphertext = aead_encrypt(key, nonce, pad(plaintext), self._sid + header)
        info = MessageInfo(s.epoch, s.send_n, key_tag(message_key))
        s.send_n += 1
        return header + ciphertext, info

    def decrypt(self, message: bytes) -> tuple[bytes, MessageInfo]:
        if len(message) < HEADER_LEN + 16:
            raise CryptoError("malformed message")
        header, ciphertext = message[:HEADER_LEN], message[HEADER_LEN:]
        peer_pk = header[: hybrid.PUBLIC_KEY_LEN]
        kem_ct = header[hybrid.PUBLIC_KEY_LEN : hybrid.PUBLIC_KEY_LEN + hybrid.CIPHERTEXT_LEN]
        prev_n, n = struct.unpack(">II", header[-8:])

        # All work happens on a copy. A forged message must not be able to
        # advance or corrupt the real state; it is committed only if the AEAD
        # tag verifies.
        s = self._s.clone()
        pk_id = sha256(peer_pk)[:8]

        message_key = s.skipped.pop((pk_id, n), None)
        if message_key is None:
            if peer_pk != s.peer_pk:
                self._skip(s, prev_n)  # keep keys for stragglers of the old chain
                s.root_key, s.recv_chain = _kdf_root(s.root_key, s.own_key.decapsulate(kem_ct))
                s.peer_pk, s.recv_n = peer_pk, 0
                self._send_step(s)
            if n < s.recv_n:
                raise CryptoError("replayed message")
            self._skip(s, n)
            s.recv_chain, message_key = _kdf_chain(s.recv_chain)
            s.recv_n += 1

        key, nonce = _message_cipher(message_key)
        plaintext = unpad(aead_decrypt(key, nonce, ciphertext, self._sid + header))
        self._s = s
        return plaintext, MessageInfo(s.epoch, n, key_tag(message_key))

    def snapshot(self) -> dict:
        """Public, non-secret view of the ratchet for the state panel."""
        s = self._s
        return {
            "epoch": s.epoch,
            "send_n": s.send_n,
            "recv_n": s.recv_n,
            "root_tag": key_tag(s.root_key),
            "send_chain_tag": key_tag(s.send_chain),
            "recv_chain_tag": key_tag(s.recv_chain),
            "ratchet_pk_tag": sha256(s.own_pk)[:8].hex() if s.own_pk else None,
            "skipped_keys": len(s.skipped),
            "can_send": s.send_chain is not None,
        }
