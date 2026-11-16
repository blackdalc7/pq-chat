import pytest

from pqchat import hybrid
from pqchat.primitives import CryptoError
from pqchat.ratchet import HEADER_LEN, MAX_SKIP, PAD_BLOCK, Ratchet, pad, unpad


def test_roundtrip_both_directions(pair):
    init, resp = pair
    assert resp.decrypt(init.encrypt(b"hello")[0])[0] == b"hello"
    assert init.decrypt(resp.encrypt(b"hi back")[0])[0] == b"hi back"


def test_initiator_cannot_send_before_key_confirmation():
    root, sid = bytes(32), bytes(16)
    fresh = Ratchet.as_initiator(root, sid, hybrid.HybridPrivateKey.generate())
    assert not fresh.can_send
    with pytest.raises(CryptoError):
        fresh.encrypt(b"too early")


def test_every_message_uses_a_different_key(pair):
    """Symmetric ratchet: the chain key rolls forward on every send."""
    init, resp = pair
    tags, chain_tags = set(), set()
    for i in range(20):
        frame, info = init.encrypt(b"same plaintext")
        tags.add(info.key_tag)
        chain_tags.add(init.snapshot()["send_chain_tag"])
        assert resp.decrypt(frame)[1].key_tag == info.key_tag
        assert info.n == i
    assert len(tags) == 20 and len(chain_tags) == 20


def test_identical_plaintexts_produce_unrelated_ciphertexts(pair):
    init, _ = pair
    first, second = init.encrypt(b"yes")[0], init.encrypt(b"yes")[0]
    assert first[HEADER_LEN:] != second[HEADER_LEN:]


def test_kem_ratchet_advances_when_direction_changes(pair):
    """Each turn of the conversation rotates both parties' hybrid key pairs."""
    init, resp = pair
    roots, public_keys, epochs = set(), set(), set()
    for _ in range(5):
        resp.decrypt(init.encrypt(b"ping")[0])
        init.decrypt(resp.encrypt(b"pong")[0])
        snapshot = init.snapshot()
        roots.add(snapshot["root_tag"])
        public_keys.add(snapshot["ratchet_pk_tag"])
        epochs.add(snapshot["epoch"])
    assert len(roots) == len(public_keys) == len(epochs) == 5


def test_no_kem_step_within_one_direction(pair):
    init, resp = pair
    resp.decrypt(init.encrypt(b"1")[0])
    epoch = init.snapshot()["epoch"]
    for _ in range(5):
        resp.decrypt(init.encrypt(b"more")[0])
    assert init.snapshot()["epoch"] == epoch


def test_forward_secrecy_old_keys_are_gone(pair):
    """A state captured *after* a message cannot decrypt that message."""
    init, resp = pair
    old_frame = init.encrypt(b"secret from the past")[0]
    resp.decrypt(old_frame)
    for _ in range(3):
        resp.decrypt(init.encrypt(b"later")[0])
    with pytest.raises(CryptoError):
        resp.decrypt(old_frame)


def test_post_compromise_security_heals_itself(pair):
    """An attacker who copies a party's entire state is locked out again once
    that party has mixed in fresh randomness the attacker never saw."""
    import copy

    init, resp = pair
    resp.decrypt(init.encrypt(b"before compromise")[0])
    stolen = Ratchet(copy.deepcopy(resp._s), resp._sid)  # full state compromise

    def exchange(text: bytes) -> bytes:
        """One round trip between the honest parties; returns init's frame."""
        init.decrypt(resp.encrypt(b"reply")[0])
        frame = init.encrypt(text)[0]
        resp.decrypt(frame)
        return frame

    # The stolen decapsulation key is still current, so the next epoch leaks.
    assert stolen.decrypt(exchange(b"still exposed"))[0] == b"still exposed"

    # Receiving that message made resp generate a new key pair. The attacker
    # holds a copy of the old state, not resp's random number generator, so
    # everything after resp's next reply is out of reach.
    healed = exchange(b"private again")
    with pytest.raises(CryptoError):
        stolen.decrypt(healed)


def test_out_of_order_delivery_within_a_chain(pair):
    init, resp = pair
    frames = [init.encrypt(f"m{i}".encode())[0] for i in range(5)]
    for i in (4, 0, 3, 1, 2):
        assert resp.decrypt(frames[i])[0] == f"m{i}".encode()
    assert resp.snapshot()["skipped_keys"] == 0


def test_late_message_from_a_previous_epoch(pair):
    init, resp = pair
    late = init.encrypt(b"late")[0]
    resp.decrypt(init.encrypt(b"on time")[0])
    init.decrypt(resp.encrypt(b"reply")[0])
    resp.decrypt(init.encrypt(b"new epoch")[0])
    assert resp.decrypt(late)[0] == b"late"


def test_replay_is_rejected(pair):
    init, resp = pair
    frame = init.encrypt(b"once")[0]
    resp.decrypt(frame)
    with pytest.raises(CryptoError):
        resp.decrypt(frame)


@pytest.mark.parametrize("index", [0, 1300, HEADER_LEN - 6, HEADER_LEN - 1, HEADER_LEN, -1], ids=["ratchet-pk", "kem-ct", "pn", "n", "ciphertext", "tag"])
def test_tampering_is_rejected_and_does_not_corrupt_state(pair, index):
    init, resp = pair
    frame = init.encrypt(b"intact")[0]
    forged = bytearray(frame)
    forged[index] ^= 0x01
    before = resp.snapshot()
    with pytest.raises(CryptoError):
        resp.decrypt(bytes(forged))
    assert resp.snapshot() == before
    assert resp.decrypt(frame)[0] == b"intact"  # the genuine frame still works


def test_message_from_another_session_is_rejected(alice, bob, card, pair):
    from .conftest import run_handshake

    initiator, result_i, result_r, ratchet_pk = run_handshake(alice, bob, card)
    other_init = Ratchet.as_initiator(result_i.root_key, result_i.session_id, initiator.ratchet_key)
    other_resp = Ratchet.as_responder(result_r.root_key, result_r.session_id, ratchet_pk)
    other_init.decrypt(other_resp.encrypt(b"\x00")[0])

    _, resp = pair
    with pytest.raises(CryptoError):
        resp.decrypt(other_init.encrypt(b"cross-session")[0])


def test_skip_limit_bounds_work_for_a_hostile_counter(pair):
    init, resp = pair
    for _ in range(MAX_SKIP + 2):
        frame = init.encrypt(b"x")[0]
    with pytest.raises(CryptoError, match="too many skipped"):
        resp.decrypt(frame)
    assert resp.snapshot()["skipped_keys"] == 0


def test_padding_hides_length_within_a_bucket(pair):
    init, _ = pair
    sizes = {len(init.encrypt(b"a" * n)[0]) for n in (0, 1, 50, 255)}
    assert len(sizes) == 1
    assert len(init.encrypt(b"a" * 256)[0]) == sizes.pop() + PAD_BLOCK


def test_padding_roundtrip_and_validation():
    for n in (0, 1, 255, 256, 257, 1000):
        data = bytes([0x80]) * n  # worst case: payload made of the pad marker
        assert len(pad(data)) % PAD_BLOCK == 0 and unpad(pad(data)) == data
    assert unpad(pad(b"ends with zeros\x00\x00")) == b"ends with zeros\x00\x00"
    for bad in (bytes(PAD_BLOCK), b"\x80" + bytes(10), b""):
        with pytest.raises(CryptoError):
            unpad(bad)


def test_truncated_frame_is_rejected(pair):
    _, resp = pair
    with pytest.raises(CryptoError):
        resp.decrypt(bytes(HEADER_LEN))
