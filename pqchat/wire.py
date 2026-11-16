"""Length-prefixed framing over a TCP stream."""

from __future__ import annotations

import asyncio
import struct

from .primitives import CryptoError

# Largest legitimate frame is a handshake message (~6.6 KiB) or a padded
# chat message. Anything bigger is refused before a single byte is buffered.
MAX_FRAME = 32 * 1024

HANDSHAKE_1 = 0x01
HANDSHAKE_2 = 0x02
HANDSHAKE_3 = 0x03
MESSAGE = 0x10


async def read_frame(reader: asyncio.StreamReader, expect: int | None = None) -> tuple[int, bytes]:
    try:
        header = await reader.readexactly(5)
        length, kind = struct.unpack(">IB", header)
        if length > MAX_FRAME:
            raise CryptoError("frame too large")
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise ConnectionError("peer closed the connection") from None
    if expect is not None and kind != expect:
        raise CryptoError("unexpected frame type")
    return kind, body


async def write_frame(writer: asyncio.StreamWriter, kind: int, body: bytes) -> None:
    if len(body) > MAX_FRAME:
        raise ValueError("frame too large")
    writer.write(struct.pack(">IB", len(body), kind) + body)
    await writer.drain()
