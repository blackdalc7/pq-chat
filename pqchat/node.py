"""Peer-to-peer node: direct TCP sessions, no server in the middle."""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from dataclasses import dataclass, field

from . import hybrid, wire
from .handshake import Initiator, Responder
from .identity import INVITE_SECRET_LEN, SIGNATURE_ALGORITHM, ContactCard, Identity, safety_number
from .primitives import CryptoError
from .ratchet import MAX_PLAINTEXT, Ratchet

HANDSHAKE_TIMEOUT = 10.0
MAX_SESSIONS = 16
MAX_TEXT_BYTES = 4096
HISTORY_LIMIT = 500
# Inner payload types (first plaintext byte, inside the encryption).
_READY, _TEXT = 0x00, 0x01

assert MAX_TEXT_BYTES < MAX_PLAINTEXT


@dataclass
class Peer:
    peer_id: str  # hex fingerprint of the peer's identity key
    fingerprint: bytes
    role: str  # "initiator" or "responder" (our role in the handshake)
    ratchet: Ratchet
    writer: asyncio.StreamWriter
    safety_number: str
    session_id: bytes
    connected: bool = True
    verified: bool = False
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    messages: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    last_epoch: int = 0

    def public(self) -> dict:
        return {
            "id": self.peer_id,
            "role": self.role,
            "connected": self.connected,
            "verified": self.verified,
            # How this peer was authenticated at connection time.
            "authenticated_by": "pinned fingerprint" if self.role == "initiator" else "invite secret",
            "safety_number": self.safety_number,
            "session_id": self.session_id.hex(),
            "ratchet": self.ratchet.snapshot(),
            "messages": self.messages,
            "events": self.events[-12:],
        }


class Node:
    def __init__(
        self,
        identity: Identity | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        advertise_host: str | None = None,
        name: str = "node",
    ) -> None:
        self.identity = identity or Identity.generate()
        self.name = name
        self.host, self.port = host, port
        self.advertise_host = advertise_host or host
        self.invite_secret = os.urandom(INVITE_SECRET_LEN)
        self.peers: dict[str, Peer] = {}
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task] = set()
        self._subscribers: set[asyncio.Queue] = set()
        self._pending = 0

    # ------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_connection, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
        for peer in self.peers.values():
            self._close(peer)
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._server:
            await self._server.wait_closed()

    # ------------------------------------------------------- out-of-band
    @property
    def card(self) -> str:
        return ContactCard(self.advertise_host, self.port, self.identity.fingerprint, self.invite_secret).encode()

    def rotate_invite(self) -> str:
        """Invalidates every card handed out so far. Existing sessions are unaffected."""
        self.invite_secret = os.urandom(INVITE_SECRET_LEN)
        self._publish()
        return self.card

    # ------------------------------------------------------------ dialling
    async def connect(self, card_text: str) -> str:
        card = ContactCard.decode(card_text)
        if card.fingerprint == self.identity.fingerprint:
            raise ValueError("that is your own contact card")

        reader, writer = await asyncio.wait_for(asyncio.open_connection(card.host, card.port), HANDSHAKE_TIMEOUT)
        try:
            async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                handshake = Initiator(self.identity, card)
                await wire.write_frame(writer, wire.HANDSHAKE_1, handshake.message1())
                _, m2 = await wire.read_frame(reader, wire.HANDSHAKE_2)
                m3, result = handshake.process_message2(m2)
                await wire.write_frame(writer, wire.HANDSHAKE_3, m3)
        except BaseException:
            writer.close()
            raise

        ratchet = Ratchet.as_initiator(result.root_key, result.session_id, handshake.ratchet_key)
        peer = self._register(result, ratchet, writer, role="initiator")
        self._spawn(self._receive_loop(peer, reader))
        # The responder's first ratchet message doubles as key confirmation:
        # it only decrypts if both sides derived the same root key.
        try:
            await asyncio.wait_for(peer.ready.wait(), HANDSHAKE_TIMEOUT)
        except TimeoutError:
            self._close(peer)
            raise CryptoError("peer did not confirm the session") from None
        return peer.peer_id

    # ----------------------------------------------------------- listening
    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Bound unauthenticated work: handshakes in flight plus live sessions.
        live = sum(p.connected for p in self.peers.values())
        if self._pending + live >= MAX_SESSIONS:
            writer.close()
            return
        self._pending += 1
        try:
            async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                handshake = Responder(self.identity, self.invite_secret)
                _, m1 = await wire.read_frame(reader, wire.HANDSHAKE_1)
                await wire.write_frame(writer, wire.HANDSHAKE_2, handshake.process_message1(m1))
                _, m3 = await wire.read_frame(reader, wire.HANDSHAKE_3)
                result, ratchet_pk = handshake.process_message3(m3)
        except (CryptoError, ConnectionError, TimeoutError, OSError):
            # Fail silently. A scanner or a peer without the invite learns
            # nothing: no error text, no identity, not even the protocol name.
            writer.close()
            return
        finally:
            self._pending -= 1

        ratchet = Ratchet.as_responder(result.root_key, result.session_id, ratchet_pk)
        peer = self._register(result, ratchet, writer, role="responder")
        try:
            await self._send_payload(peer, bytes([_READY]))
        except (ConnectionError, OSError):
            self._close(peer)
            return
        peer.ready.set()
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._receive_loop(peer, reader)
        finally:
            self._tasks.discard(task)

    # ------------------------------------------------------------ sessions
    def _register(self, result, ratchet: Ratchet, writer: asyncio.StreamWriter, *, role: str) -> Peer:
        peer_id = result.peer_fingerprint.hex()
        previous = self.peers.get(peer_id)
        peer = Peer(
            peer_id=peer_id,
            fingerprint=result.peer_fingerprint,
            role=role,
            ratchet=ratchet,
            writer=writer,
            # Derived from both long-term identities, so it stays the same
            # across reconnects and only changes if a key changes.
            safety_number=safety_number(self.identity.fingerprint, result.peer_fingerprint),
            session_id=result.session_id,
        )
        if previous:
            # Same identity reconnecting: keep the history and the user's
            # verification decision, replace the cryptographic session.
            self._close(previous, publish=False)
            peer.messages, peer.verified = previous.messages, previous.verified
        self.peers[peer_id] = peer
        self._log(peer, "handshake", f"session established ({hybrid.ALGORITHM}, {SIGNATURE_ALGORITHM})")
        self._track_epoch(peer)
        self._publish()
        return peer

    def _close(self, peer: Peer, *, publish: bool = True) -> None:
        if peer.connected:
            peer.connected = False
            with contextlib.suppress(Exception):
                peer.writer.close()
            if publish:
                self._log(peer, "closed", "session closed")
                self._publish()

    async def _receive_loop(self, peer: Peer, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                _, frame = await wire.read_frame(reader, wire.MESSAGE)
                plaintext, info = peer.ratchet.decrypt(frame)
                self._track_epoch(peer)
                if not plaintext:
                    raise CryptoError("empty payload")
                if plaintext[0] == _READY:
                    peer.ready.set()
                elif plaintext[0] == _TEXT:
                    self._record(peer, "in", plaintext[1:].decode("utf-8"), info)
                self._publish()
        except (CryptoError, UnicodeDecodeError):
            # TCP delivers in order, so a frame that fails authentication
            # means tampering. Tear the session down instead of guessing.
            self._log(peer, "error", "authentication failure, session terminated")
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            if self.peers.get(peer.peer_id) is peer:
                self._close(peer)

    async def _send_payload(self, peer: Peer, payload: bytes):
        # The lock keeps "advance the chain" and "write the frame" atomic, so
        # frames reach the wire in the same order their keys were derived.
        async with peer.send_lock:
            frame, info = peer.ratchet.encrypt(payload)
            await wire.write_frame(peer.writer, wire.MESSAGE, frame)
        self._track_epoch(peer)
        return info

    async def send(self, peer_id: str, text: str) -> dict:
        peer = self.peers.get(peer_id)
        if peer is None or not peer.connected:
            raise ValueError("no active session with that peer")
        data = text.encode("utf-8")
        if not data or len(data) > MAX_TEXT_BYTES:
            raise ValueError(f"message must be 1 to {MAX_TEXT_BYTES} bytes")
        if not peer.ratchet.can_send:
            raise ValueError("session is not ready yet")
        info = await self._send_payload(peer, bytes([_TEXT]) + data)
        message = self._record(peer, "out", text, info)
        self._publish()
        return message

    def mark_verified(self, peer_id: str, verified: bool = True) -> None:
        peer = self.peers.get(peer_id)
        if peer is None:
            raise ValueError("unknown peer")
        peer.verified = verified
        self._log(peer, "verify", "safety number confirmed by user" if verified else "verification cleared")
        self._publish()

    # ---------------------------------------------------------- observers
    def _record(self, peer: Peer, direction: str, text: str, info) -> dict:
        message = {
            "id": f"{info.epoch}.{direction}.{info.n}",
            "direction": direction,
            "text": text,
            "ts": time.time(),
            "epoch": info.epoch,
            "n": info.n,
            "key_tag": info.key_tag,
        }
        peer.messages.append(message)
        del peer.messages[:-HISTORY_LIMIT]
        return message

    def _track_epoch(self, peer: Peer) -> None:
        epoch = peer.ratchet.snapshot()["epoch"]
        if epoch != peer.last_epoch:
            peer.last_epoch = epoch
            self._log(peer, "ratchet", f"KEM ratchet step: fresh X25519 + ML-KEM-768 keys, epoch {epoch}")

    def _log(self, peer: Peer, kind: str, detail: str) -> None:
        peer.events.append({"ts": time.time(), "kind": kind, "detail": detail})
        del peer.events[:-50]

    def state(self) -> dict:
        return {
            "name": self.name,
            "fingerprint": self.identity.fingerprint.hex(),
            "listen": f"{self.advertise_host}:{self.port}",
            "card": self.card,
            "algorithms": {
                "key_exchange": hybrid.ALGORITHM,
                "signatures": SIGNATURE_ALGORITHM,
                "aead": "ChaCha20-Poly1305",
                "kdf": "HKDF-SHA256",
            },
            "peers": [p.public() for p in self.peers.values()],
        }

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=64)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def _publish(self) -> None:
        snapshot = self.state()
        for queue in self._subscribers:
            # A slow UI must never block the protocol: drop its oldest update.
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(snapshot)

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
