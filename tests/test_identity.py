import pytest

from pqchat.identity import ContactCard, Identity, safety_number, verify
from pqchat.primitives import CryptoError, pack, unpack


def test_hybrid_signature_roundtrip(alice):
    signature = alice.sign(b"transcript")
    assert len(signature) == 64 + 3309
    verify(alice.public_bytes, signature, b"transcript")


def test_signature_rejects_other_message_and_other_identity(alice, bob):
    signature = alice.sign(b"transcript")
    with pytest.raises(CryptoError):
        verify(alice.public_bytes, signature, b"different")
    with pytest.raises(CryptoError):
        verify(bob.public_bytes, signature, b"transcript")


def test_both_signature_halves_are_required(alice, bob):
    """A forger who can break only one scheme still fails."""
    good = alice.sign(b"m")
    other = bob.sign(b"m")
    with pytest.raises(CryptoError):
        verify(alice.public_bytes, other[:64] + good[64:], b"m")  # bad Ed25519 half
    with pytest.raises(CryptoError):
        verify(alice.public_bytes, good[:64] + other[64:], b"m")  # bad ML-DSA half


def test_signature_is_bound_to_the_full_identity(alice, bob):
    """Mixing one of Alice's keys into another identity must not verify."""
    signature = alice.sign(b"m")
    frankenstein = alice.public_bytes[:32] + bob.public_bytes[32:]
    with pytest.raises(CryptoError):
        verify(frankenstein, signature, b"m")


def test_contact_card_roundtrip(bob):
    card = ContactCard("192.168.1.20", 9443, bob.fingerprint, b"s" * 16)
    assert ContactCard.decode(card.encode()) == card
    assert ContactCard.decode(f"  {card.encode()}\n") == card


@pytest.mark.parametrize("mutate", [lambda t: t[:-4] + ("A" if t[-4] != "A" else "B") + t[-3:], lambda t: t[:20] + "x" + t[21:], lambda t: t.replace("pqchat1:", "pqchat2:"), lambda t: t[:30], lambda t: "pqchat1:" + "A" * 600, lambda t: "pqchat1:!!!"])
def test_contact_card_rejects_typos_and_garbage(bob, mutate):
    text = ContactCard("127.0.0.1", 9000, bob.fingerprint, b"s" * 16).encode()
    with pytest.raises(ValueError):
        ContactCard.decode(mutate(text))


def test_safety_number_is_symmetric_and_key_dependent(alice, bob):
    number = safety_number(alice.fingerprint, bob.fingerprint)
    assert number == safety_number(bob.fingerprint, alice.fingerprint)
    assert len(number.replace(" ", "")) == 60 and number.replace(" ", "").isdigit()
    assert number != safety_number(alice.fingerprint, Identity.generate().fingerprint)


def test_keystore_roundtrip_and_wrong_passphrase(alice):
    blob = alice.export_encrypted("correct horse battery")
    assert Identity.load_encrypted(blob, "correct horse battery").public_bytes == alice.public_bytes
    with pytest.raises(CryptoError):
        Identity.load_encrypted(blob, "wrong passphrase")
    with pytest.raises(CryptoError):
        Identity.load_encrypted(blob[:-1] + bytes([blob[-1] ^ 1]), "correct horse battery")
    with pytest.raises(ValueError):
        alice.export_encrypted("short")


def test_keystore_is_salted(alice):
    assert alice.export_encrypted("correct horse battery") != alice.export_encrypted("correct horse battery")


def test_pack_is_unambiguous():
    assert pack(b"ab", b"c") != pack(b"a", b"bc")
    assert unpack(pack(b"ab", b""), 2) == [b"ab", b""]
    for bad in (pack(b"a") + b"x", pack(b"a")[:-1], b"\x00\x00\x00"):
        with pytest.raises(CryptoError):
            unpack(bad, 1)
    with pytest.raises(CryptoError):
        unpack(pack(b"a"), 2)
