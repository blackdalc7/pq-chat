"""Local control plane: serves the UI and bridges it to the node.

This listener is for the person sitting at the machine and nobody else:
  * binds to loopback only
  * every API call needs a per-launch bearer token
  * Host and Origin are checked, which stops DNS-rebinding and cross-site
    requests from a web page open in the same browser
Plaintext messages exist only here and in the node's memory.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

from aiohttp import WSMsgType, web

from .node import MAX_TEXT_BYTES, Node
from .primitives import CryptoError, ct_equal

WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"
MAX_BODY = 16 * 1024

SECURITY_HEADERS = {
    # No inline script or style and no remote origins, so injected markup in a
    # chat message has nothing to execute and nowhere to send data.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


def _json_error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


class ControlServer:
    def __init__(self, node: Node, *, port: int = 0, token: str | None = None) -> None:
        if token is not None and len(token) < 32:
            raise ValueError("UI token must be at least 32 characters")
        self.node = node
        self.port = port
        self.token = token or secrets.token_urlsafe(32)
        self._runner: web.AppRunner | None = None
        self._sockets: set[web.WebSocketResponse] = set()

    @property
    def url(self) -> str:
        # The token rides in the URL fragment, which browsers never send to
        # the server or include in a Referer header.
        return f"http://127.0.0.1:{self.port}/#token={self.token}"

    async def start(self) -> None:
        app = web.Application(middlewares=[self._guard], client_max_size=MAX_BODY)
        app.add_routes(
            [
                web.get("/api/state", self._state),
                web.post("/api/connect", self._connect),
                web.post("/api/send", self._send),
                web.post("/api/verify", self._verify),
                web.post("/api/invite/rotate", self._rotate),
                web.get("/ws", self._websocket),
                web.get("/", self._index),
            ]
        )
        if (WEB_DIST / "assets").is_dir():
            app.router.add_static("/assets", WEB_DIST / "assets")
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await site.start()
        self.port = self._runner.addresses[0][1]  # resolves port 0 to the one actually bound

    async def stop(self) -> None:
        for ws in list(self._sockets):
            await ws.close()
        if self._runner:
            await self._runner.cleanup()

    # ---------------------------------------------------------- middleware
    @web.middleware
    async def _guard(self, request: web.Request, handler):
        allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        origin = request.headers.get("Origin")
        if request.host not in allowed_hosts:
            response = _json_error(403, "forbidden")
        elif origin is not None and origin not in {f"http://{h}" for h in allowed_hosts}:
            response = _json_error(403, "forbidden")
        elif request.path.startswith("/api/") and not self._authorised(request):
            response = _json_error(401, "unauthorised")
        else:
            try:
                response = await handler(request)
            except web.HTTPException as exc:
                response = _json_error(exc.status, exc.reason or "error")
        if not isinstance(response, web.WebSocketResponse):
            response.headers.update(SECURITY_HEADERS)
        return response

    def _authorised(self, request: web.Request) -> bool:
        supplied = request.headers.get("Authorization", "")
        return ct_equal(supplied.encode(), f"Bearer {self.token}".encode())

    @staticmethod
    async def _body(request: web.Request, **fields: int) -> dict:
        """Parses a JSON object with exactly the given string fields (name -> max length)."""
        try:
            data = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise web.HTTPBadRequest(reason="invalid JSON") from None
        if not isinstance(data, dict) or set(data) != set(fields):
            raise web.HTTPBadRequest(reason="unexpected fields")
        for name, limit in fields.items():
            if not isinstance(data[name], str) or not 0 < len(data[name]) <= limit:
                raise web.HTTPBadRequest(reason=f"invalid {name}")
        return data

    # ------------------------------------------------------------ handlers
    async def _index(self, request: web.Request) -> web.StreamResponse:
        index = WEB_DIST / "index.html"
        if not index.is_file():
            return web.Response(text="UI not built yet. Run: npm install && npm run build", status=503)
        return web.FileResponse(index)

    async def _state(self, request: web.Request) -> web.Response:
        return web.json_response(self.node.state())

    async def _connect(self, request: web.Request) -> web.Response:
        data = await self._body(request, card=512)
        try:
            peer_id = await self.node.connect(data["card"])
        except ValueError as exc:
            return _json_error(400, str(exc))
        except CryptoError as exc:
            return _json_error(502, f"handshake failed: {exc}")
        except (OSError, TimeoutError, ConnectionError):
            return _json_error(502, "could not reach that peer")
        return web.json_response({"peer": peer_id})

    async def _send(self, request: web.Request) -> web.Response:
        data = await self._body(request, peer=64, text=MAX_TEXT_BYTES)
        try:
            message = await self.node.send(data["peer"], data["text"])
        except ValueError as exc:
            return _json_error(400, str(exc))
        except (OSError, ConnectionError):
            return _json_error(502, "connection lost")
        return web.json_response(message)

    async def _verify(self, request: web.Request) -> web.Response:
        data = await self._body(request, peer=64)
        try:
            self.node.mark_verified(data["peer"])
        except ValueError as exc:
            return _json_error(400, str(exc))
        return web.json_response({"ok": True})

    async def _rotate(self, request: web.Request) -> web.Response:
        return web.json_response({"card": self.node.rotate_invite()})

    async def _websocket(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=1024)
        await ws.prepare(request)
        # Browsers cannot set headers on a WebSocket, so the first frame must
        # be the token. Nothing is sent before it has been checked.
        try:
            first = await asyncio.wait_for(ws.receive(), 5)
            token = json.loads(first.data).get("token", "") if first.type == WSMsgType.TEXT else ""
        except (TimeoutError, json.JSONDecodeError, AttributeError):
            token = ""
        if not isinstance(token, str) or not ct_equal(token.encode(), self.token.encode()):
            await ws.close(code=4401, message=b"unauthorised")
            return ws

        queue = self.node.subscribe()
        self._sockets.add(ws)
        try:
            await ws.send_json(self.node.state())
            while not ws.closed:
                getter = asyncio.ensure_future(queue.get())
                closer = asyncio.ensure_future(ws.receive())
                done, pending = await asyncio.wait({getter, closer}, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                if closer in done:
                    break
                await ws.send_json(getter.result())
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self.node.unsubscribe(queue)
            self._sockets.discard(ws)
        return ws
