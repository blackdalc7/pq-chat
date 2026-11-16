import pytest

from pqchat.handshake import Initiator, Responder
from pqchat.identity import ContactCard, Identity
from pqchat.ratchet import Ratchet

INVITE = bytes(range(16))


@pytest.fixture(scope="session")
def alice() -> Identity:
    return Identity.generate()


@pytest.fixture(scope="session")
def bob() -> Identity:
    return Identity.generate()


@pytest.fixture
def card(bob) -> ContactCard:
    return ContactCard("127.0.0.1", 9000, bob.fingerprint, INVITE)


def run_handshake(alice, bob, card, invite=INVITE):
    initiator, responder = Initiator(alice, card), Responder(bob, invite)
    m2 = responder.process_message1(initiator.message1())
    m3, result_i = initiator.process_message2(m2)
    result_r, ratchet_pk = responder.process_message3(m3)
    return initiator, result_i, result_r, ratchet_pk


@pytest.fixture
def pair(alice, bob, card):
    """An established session: (initiator ratchet, responder ratchet)."""
    initiator, result_i, result_r, ratchet_pk = run_handshake(alice, bob, card)
    init = Ratchet.as_initiator(result_i.root_key, result_i.session_id, initiator.ratchet_key)
    resp = Ratchet.as_responder(result_r.root_key, result_r.session_id, ratchet_pk)
    # Responder speaks first; this is the key-confirmation message.
    init.decrypt(resp.encrypt(b"\x00")[0])
    return init, resp
