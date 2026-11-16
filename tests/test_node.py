import asyncio
import struct

import pytest

from pqchat import wire
from pqchat.identity import ContactCard
from pqchat.node import Node
from pqchat.primitives import CryptoError


async def settle(condition, timeout=3.0):
    """Waits until condition() is truthy; network delivery is asynchronous."""
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "condition not reached"
        await asyncio.sleep(0.01)


@pytest.fixture
async def nodes():
    alice, bob = Node(name="alice"), Node(name="bob")
    await alice.start()
    await bob.start()
    yield alice, bob
    await alice.stop()
    await bob.stop()


async def connected(alice: Node, bob: Node):
    bob_id = await alice.connect(bob.card)
    alice_id = alice.identity.fingerprint.hex()
    await settle(lambda: alice_id in bob.peers)
    return bob_id, alice_id


async def test_two_nodes_exchange_messages(nodes):
    alice, bob = nodes
    bob_id, alice_id = await connected(alice, bob)

    await alice.send(bob_id, "hello bob")
    await settle(lambda: bob.peers[alice_id].messages)
    await bob.send(alice_id, "hello alice ✓")
    await settle(lambda: len(alice.peers[bob_id].messages) == 2)

    assert [m["text"] for m in bob.peers[alice_id].messages] == ["hello bob", "hello alice ✓"]
    assert [m["direction"] for m in alice.peers[bob_id].messages] == ["out", "in"]
    # Both ends report the same per-message key tag without sharing the key.
    assert alice.peers[bob_id].messages[0]["key_tag"] == bob.peers[alice_id].messages[0]["key_tag"]
    assert alice.peers[bob_id].safety_number == bob.peers[alice_id].safety_number


async def test_plaintext_never_reaches_the_wire(nodes):
    """Relays the TCP stream through a recording proxy and inspects every byte."""
    alice, bob = nodes
    captured = bytearray()

    async def pipe(reader, writer):
        try:
            while data := await reader.read(65536):
                captured.extend(data)
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def relay(client_reader, client_writer):
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", bob.port)
        await asyncio.gather(pipe(client_reader, upstream_writer), pipe(upstream_reader, client_writer))

    proxy = await asyncio.start_server(relay, "127.0.0.1", 0)
    proxy_port = proxy.sockets[0].getsockname()[1]
    card = ContactCard.decode(bob.card)
    via_proxy = ContactCard("127.0.0.1", proxy_port, card.fingerprint, card.invite_secret).encode()

    bob_id = await alice.connect(via_proxy)
    alice_id = alice.identity.fingerprint.hex()
    secret = "the launch code is 7-4-1-9"
    await alice.send(bob_id, secret)
    await settle(lambda: alice_id in bob.peers and bob.peers[alice_id].messages)

    assert bob.peers[alice_id].messages[0]["text"] == secret
    assert len(captured) > 10_000
    assert secret.encode() not in captured
    for node in (alice, bob):
        assert node.identity.fingerprint not in captured
        assert node.identity.public_bytes[:32] not in captured
    proxy.close()


async def test_tampering_in_transit_terminates_the_session(nodes):
    """An active attacker flipping one bit gets a closed session, not a message."""
    alice, bob = nodes
    state = {"frames": 0}

    async def pipe(reader, writer, tamper):
        try:
            while True:
                header = await reader.readexactly(5)
                length, kind = struct.unpack(">IB", header)
                body = bytearray(await reader.readexactly(length))
                if tamper and kind == wire.MESSAGE:
                    state["frames"] += 1
                    body[-20] ^= 0x01
                writer.write(header + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            writer.close()

    async def relay(client_reader, client_writer):
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", bob.port)
        await asyncio.gather(pipe(client_reader, upstream_writer, True), pipe(upstream_reader, client_writer, False))

    proxy = await asyncio.start_server(relay, "127.0.0.1", 0)
    card = ContactCard.decode(bob.card)
    via_proxy = ContactCard("127.0.0.1", proxy.sockets[0].getsockname()[1], card.fingerprint, card.invite_secret).encode()

    bob_id = await alice.connect(via_proxy)
    alice_id = alice.identity.fingerprint.hex()
    await settle(lambda: alice_id in bob.peers)
    await alice.send(bob_id, "will be modified")
    await settle(lambda: not bob.peers[alice_id].connected)

    assert state["frames"] == 1
    assert bob.peers[alice_id].messages == []
    assert any(e["kind"] == "error" for e in bob.peers[alice_id].events)
    proxy.close()


async def test_peer_without_the_invite_gets_no_response(nodes):
    alice, bob = nodes
    card = ContactCard.decode(bob.card)
    stale = ContactCard(card.host, card.port, card.fingerprint, bytes(16)).encode()
    with pytest.raises((ConnectionError, CryptoError)):
        await alice.connect(stale)
    assert bob.peers == {}


async def test_rotating_the_invite_revokes_old_cards(nodes):
    alice, bob = nodes
    old_card = bob.card
    assert bob.rotate_invite() != old_card
    with pytest.raises((ConnectionError, CryptoError)):
        await alice.connect(old_card)
    assert await alice.connect(bob.card)


async def test_connecting_to_the_wrong_identity_fails(nodes):
    """Right address and invite, but the listener is not who the card says."""
    alice, bob = nodes
    card = ContactCard.decode(bob.card)
    forged = ContactCard(card.host, card.port, bytes(32), card.invite_secret).encode()
    with pytest.raises(CryptoError, match="does not match"):
        await alice.connect(forged)
    assert alice.peers == {}


async def test_garbage_and_oversized_frames_are_dropped_silently(nodes):
    _, bob = nodes
    for payload in (b"GET / HTTP/1.1\r\n\r\n", struct.pack(">IB", 2**31, 1), struct.pack(">IB", 4, 1) + b"abcd"):
        reader, writer = await asyncio.open_connection("127.0.0.1", bob.port)
        writer.write(payload)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 3) == b""  # closed, nothing sent back
        writer.close()
    assert bob.peers == {}


async def test_send_validation(nodes):
    alice, bob = nodes
    bob_id, _ = await connected(alice, bob)
    for bad in ("", "x" * 5000):
        with pytest.raises(ValueError):
            await alice.send(bob_id, bad)
    with pytest.raises(ValueError):
        await alice.send("00" * 32, "nobody")
    with pytest.raises(ValueError, match="own contact card"):
        await alice.connect(alice.card)


async def test_reconnect_keeps_history_and_verification(nodes):
    alice, bob = nodes
    bob_id, alice_id = await connected(alice, bob)
    await alice.send(bob_id, "first session")
    await settle(lambda: bob.peers[alice_id].messages)
    alice.mark_verified(bob_id)
    first_session = alice.peers[bob_id].session_id

    await alice.connect(bob.card)
    peer = alice.peers[bob_id]
    assert peer.session_id != first_session
    assert peer.verified and peer.messages[0]["text"] == "first session"
    await alice.send(bob_id, "second session")
    await settle(lambda: len(bob.peers[alice_id].messages) == 2)


async def test_state_snapshot_exposes_no_secrets(nodes):
    alice, bob = nodes
    bob_id, _ = await connected(alice, bob)
    await alice.send(bob_id, "x")
    blob = repr(alice.state()).encode()
    internal = alice.peers[bob_id].ratchet._s
    for secret in (internal.root_key, internal.send_chain, alice.identity._ed_seed):
        assert secret.hex().encode() not in blob
    subscriber = alice.subscribe()
    await alice.send(bob_id, "y")
    assert (await subscriber.get())["peers"][0]["messages"][-1]["text"] == "y"
