import json
from pathlib import Path

import pytest

from pqchat import hybrid
from pqchat.primitives import CryptoError

VECTORS = json.loads((Path(__file__).parent / "vectors" / "xwing.json").read_text())


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["seed"][:8])
def test_matches_official_xwing_vectors(vector):
    """Known-answer test from draft-connolly-cfrg-xwing-kem.

    Passing this means the key derivation, the ML-KEM-768 / X25519 halves and
    the SHA3 combiner are byte-compatible with other X-Wing implementations.
    """
    key = hybrid.HybridPrivateKey(bytes.fromhex(vector["sk"]))
    assert key.public_bytes().hex() == vector["pk"]
    assert key.decapsulate(bytes.fromhex(vector["ct"])).hex() == vector["ss"]


def test_roundtrip_and_sizes():
    key = hybrid.HybridPrivateKey.generate()
    public = key.public_bytes()
    ciphertext, secret = hybrid.encapsulate(public)
    assert len(public) == 1216 and len(ciphertext) == 1120 and len(secret) == 32
    assert key.decapsulate(ciphertext) == secret


def test_each_encapsulation_is_fresh():
    public = hybrid.HybridPrivateKey.generate().public_bytes()
    (ct1, ss1), (ct2, ss2) = hybrid.encapsulate(public), hybrid.encapsulate(public)
    assert ct1 != ct2 and ss1 != ss2


def test_wrong_key_does_not_recover_the_secret():
    ciphertext, secret = hybrid.encapsulate(hybrid.HybridPrivateKey.generate().public_bytes())
    assert hybrid.HybridPrivateKey.generate().decapsulate(ciphertext) != secret


@pytest.mark.parametrize("offset", [0, 500, 1087, 1088, 1119], ids=["mlkem-first", "mlkem-mid", "mlkem-last", "x25519-first", "x25519-last"])
def test_tampering_with_either_half_changes_the_secret(offset):
    """Both components contribute: flipping a bit in either one breaks agreement."""
    key = hybrid.HybridPrivateKey.generate()
    ciphertext, secret = hybrid.encapsulate(key.public_bytes())
    tampered = bytearray(ciphertext)
    tampered[offset] ^= 0x01
    assert key.decapsulate(bytes(tampered)) != secret


def test_rejects_small_order_x25519_point():
    """An all-zero X25519 share would force a known shared secret."""
    key = hybrid.HybridPrivateKey.generate()
    ciphertext, _ = hybrid.encapsulate(key.public_bytes())
    with pytest.raises(CryptoError):
        key.decapsulate(ciphertext[:1088] + bytes(32))
    with pytest.raises(CryptoError):
        hybrid.encapsulate(key.public_bytes()[:1184] + bytes(32))


def test_rejects_malformed_inputs():
    key = hybrid.HybridPrivateKey.generate()
    with pytest.raises(CryptoError):
        key.decapsulate(b"short")
    with pytest.raises(CryptoError):
        hybrid.encapsulate(b"short")
    with pytest.raises(CryptoError):
        # Coefficients out of range fail the FIPS 203 encapsulation key check.
        hybrid.encapsulate(b"\xff" * 1184 + key.public_bytes()[1184:])
