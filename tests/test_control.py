import aiohttp
import pytest

from pqchat.control import ControlServer
from pqchat.node import Node

TOKEN = "t" * 43


@pytest.fixture
async def stack():
    alice, bob = Node(name="alice"), Node(name="bob")
    await alice.start()
    await bob.start()
    control = ControlServer(alice, token=TOKEN)
    await control.start()
    async with aiohttp.ClientSession() as http:
        yield control, alice, bob, http, f"http://127.0.0.1:{control.port}"
    await control.stop()
    await alice.stop()
    await bob.stop()


AUTH = {"Authorization": f"Bearer {TOKEN}"}


async def test_api_requires_the_bearer_token(stack):
    _, _, _, http, base = stack
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}):
        async with http.get(f"{base}/api/state", headers=headers) as res:
            assert res.status == 401
    async with http.get(f"{base}/api/state", headers=AUTH) as res:
        assert res.status == 200 and (await res.json())["name"] == "alice"


async def test_dns_rebinding_and_cross_origin_requests_are_refused(stack):
    _, _, _, http, base = stack
    async with http.get(f"{base}/api/state", headers={**AUTH, "Host": "attacker.example"}) as res:
        assert res.status == 403
    async with http.post(f"{base}/api/send", headers={**AUTH, "Origin": "https://attacker.example"}, json={}) as res:
        assert res.status == 403


async def test_security_headers_on_every_response(stack):
    _, _, _, http, base = stack
    for path in ("/", "/api/state", "/missing"):
        async with http.get(f"{base}{path}") as res:
            csp = res.headers["Content-Security-Policy"]
            assert "default-src 'none'" in csp and "unsafe" not in csp
            assert res.headers["X-Frame-Options"] == "DENY"
            assert res.headers["X-Content-Type-Options"] == "nosniff"
            assert res.headers["Cache-Control"] == "no-store"


async def test_connect_and_send_through_the_api(stack):
    _, alice, bob, http, base = stack
    async with http.post(f"{base}/api/connect", headers=AUTH, json={"card": bob.card}) as res:
        assert res.status == 200
        peer = (await res.json())["peer"]
    async with http.post(f"{base}/api/send", headers=AUTH, json={"peer": peer, "text": "via api"}) as res:
        assert res.status == 200 and (await res.json())["direction"] == "out"
    async with http.post(f"{base}/api/verify", headers=AUTH, json={"peer": peer}) as res:
        assert res.status == 200
    assert alice.peers[peer].verified


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/connect", {"card": "not-a-card"}),
        ("/api/connect", {"card": 5}),
        ("/api/connect", {"card": "pqchat1:AAAA", "extra": "field"}),
        ("/api/send", {"peer": "00" * 32}),
        ("/api/send", {"peer": "00" * 32, "text": ""}),
        ("/api/send", {"peer": "00" * 32, "text": "nobody home"}),
        ("/api/verify", {"peer": "unknown"}),
    ],
)
async def test_invalid_requests_are_rejected(stack, path, body):
    _, _, _, http, base = stack
    async with http.post(f"{base}{path}", headers=AUTH, json=body) as res:
        assert res.status == 400


async def test_malformed_and_oversized_bodies(stack):
    _, _, _, http, base = stack
    async with http.post(f"{base}/api/send", headers=AUTH, data=b"{not json") as res:
        assert res.status == 400
    async with http.post(f"{base}/api/send", headers=AUTH, data=b"x" * 64_000) as res:
        assert res.status == 413


async def test_websocket_needs_the_token_first(stack):
    _, _, _, http, base = stack
    async with http.ws_connect(f"{base}/ws") as ws:
        await ws.send_json({"token": "wrong"})
        closing = await ws.receive()
        assert closing.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED) and ws.close_code == 4401


async def test_websocket_streams_state_updates(stack):
    _, alice, bob, http, base = stack
    async with http.ws_connect(f"{base}/ws") as ws:
        await ws.send_json({"token": TOKEN})
        assert (await ws.receive_json())["peers"] == []
        await alice.connect(bob.card)
        update = await ws.receive_json()
        assert update["peers"][0]["connected"] is True


def test_short_ui_tokens_are_refused():
    with pytest.raises(ValueError):
        ControlServer(Node(), token="short")
