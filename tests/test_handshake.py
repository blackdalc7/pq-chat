import pytest

from pqchat.handshake import M1_LEN, Initiator, Responder
from pqchat.identity import ContactCard, Identity
from pqchat.primitives import CryptoError

from .conftest import INVITE, run_handshake


def flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def test_both_sides_agree_and_authenticate(alice, bob, card):
    _, result_i, result_r, _ = run_handshake(alice, bob, card)
    assert result_i.root_key == result_r.root_key
    assert result_i.session_id == result_r.session_id
    assert result_i.transcript_hash == result_r.transcript_hash
    assert result_i.peer_identity == bob.public_bytes
    assert result_r.peer_identity == alice.public_bytes


def test_every_session_gets_fresh_keys(alice, bob, card):
    _, first, _, _ = run_handshake(alice, bob, card)
    _, second, _, _ = run_handshake(alice, bob, card)
    assert first.root_key != second.root_key
    assert first.session_id != second.session_id


def test_message1_size_is_fixed(alice, card):
    assert len(Initiator(alice, card).message1()) == M1_LEN


def test_stranger_without_invite_is_dropped_before_any_reply(alice, bob):
    """No invite secret, no response: the responder reveals nothing."""
    wrong_card = ContactCard("127.0.0.1", 9000, bob.fingerprint, b"\xff" * 16)
    with pytest.raises(CryptoError, match="unknown invite"):
        Responder(bob, INVITE).process_message1(Initiator(alice, wrong_card).message1())


def test_identities_never_appear_in_cleartext(alice, bob, card):
    initiator, responder = Initiator(alice, card), Responder(bob, INVITE)
    m1 = initiator.message1()
    m2 = responder.process_message1(m1)
    m3, _ = initiator.process_message2(m2)
    wire = m1 + m2 + m3
    for identity in (alice, bob):
        assert identity.public_bytes[:32] not in wire  # Ed25519 key
        assert identity.public_bytes[32:96] not in wire  # start of ML-DSA key
        assert identity.fingerprint not in wire


def test_impersonating_the_responder_fails(alice, bob, card):
    """Mallory has the invite secret but not Bob's signing keys."""
    mallory = Identity.generate()
    initiator, fake = Initiator(alice, card), Responder(mallory, INVITE)
    with pytest.raises(CryptoError, match="does not match the contact card"):
        initiator.process_message2(fake.process_message1(initiator.message1()))


@pytest.mark.parametrize("index", [0, 40, 1200, 1264], ids=["version", "nonce", "kem-key", "tag"])
def test_tampered_message1_is_rejected(alice, bob, card, index):
    with pytest.raises(CryptoError):
        Responder(bob, INVITE).process_message1(flip(Initiator(alice, card).message1(), index))


@pytest.mark.parametrize("index", [0, 100, 1150, 1200, -1], ids=["nonce", "mlkem-ct", "x25519-ct", "sealed", "aead-tag"])
def test_tampered_message2_is_rejected(alice, bob, card, index):
    initiator, responder = Initiator(alice, card), Responder(bob, INVITE)
    m2 = responder.process_message1(initiator.message1())
    with pytest.raises(CryptoError):
        initiator.process_message2(flip(m2, index))


@pytest.mark.parametrize("index", [0, 3000, -1])
def test_tampered_message3_is_rejected(alice, bob, card, index):
    initiator, responder = Initiator(alice, card), Responder(bob, INVITE)
    m3, _ = initiator.process_message2(responder.process_message1(initiator.message1()))
    with pytest.raises(CryptoError):
        responder.process_message3(flip(m3, index))


def test_message3_cannot_be_replayed_into_another_handshake(alice, bob, card):
    """Signatures cover the transcript hash, so they are useless elsewhere."""
    initiator, responder = Initiator(alice, card), Responder(bob, INVITE)
    m1 = initiator.message1()
    m3, _ = initiator.process_message2(responder.process_message1(m1))

    second = Responder(bob, INVITE)
    second.process_message1(m1)  # same m1, but fresh nonce and KEM ciphertext
    with pytest.raises(CryptoError):
        second.process_message3(m3)


def test_messages_out_of_order_are_rejected(alice, bob, card):
    with pytest.raises(CryptoError):
        Initiator(alice, card).process_message2(b"\x00" * 7000)
    with pytest.raises(CryptoError):
        Responder(bob, INVITE).process_message3(b"\x00" * 7000)


def test_truncated_messages_are_rejected(alice, bob, card):
    initiator, responder = Initiator(alice, card), Responder(bob, INVITE)
    m1 = initiator.message1()
    with pytest.raises(CryptoError):
        Responder(bob, INVITE).process_message1(m1[:-1])
    m2 = responder.process_message1(m1)
    with pytest.raises(CryptoError):
        initiator.process_message2(m2[:1152])
