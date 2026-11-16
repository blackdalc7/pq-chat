"""Command line entry point:  python -m pqchat --port 9001 --ui-port 8081"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import os
import signal
from pathlib import Path

from .control import ControlServer
from .identity import Identity
from .node import Node
from .primitives import CryptoError


def _load_identity(path: Path | None) -> Identity:
    if path is None:
        return Identity.generate()  # ephemeral: gone when the process exits
    # The passphrase comes from the environment or a prompt, never from argv,
    # where it would be visible in the process list and shell history.
    passphrase = os.environ.get("PQCHAT_PASSPHRASE") or getpass.getpass("Identity passphrase: ")
    if path.exists():
        return Identity.load_encrypted(path.read_bytes(), passphrase)
    identity = Identity.generate()
    path.write_bytes(identity.export_encrypted(passphrase))
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    return identity


async def _run(args: argparse.Namespace) -> None:
    node = Node(
        _load_identity(args.identity),
        host=args.host,
        port=args.port,
        advertise_host=args.advertise,
        name=args.name,
    )
    await node.start()
    control = ControlServer(node, port=args.ui_port, token=os.environ.get("PQCHAT_UI_TOKEN"))
    await control.start()

    print(f"node         {node.name} listening on {node.host}:{node.port}")
    print(f"fingerprint  {node.identity.fingerprint.hex()}")
    print(f"contact card {node.card}")
    print(f"open         {control.url}", flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows event loop
            loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await control.stop()
        await node.stop()


def main() -> None:
    parser = argparse.ArgumentParser(prog="pqchat", description="Serverless post-quantum E2EE chat node")
    parser.add_argument("--name", default="node", help="label shown in the UI")
    parser.add_argument("--host", default="127.0.0.1", help="address the P2P listener binds to")
    parser.add_argument("--port", type=int, default=0, help="P2P port (0 = pick a free one)")
    parser.add_argument("--advertise", help="address written into the contact card (default: --host)")
    parser.add_argument("--ui-port", type=int, default=0, help="loopback port for the web UI")
    parser.add_argument("--identity", type=Path, help="encrypted identity file (created if missing)")
    args = parser.parse_args()
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        pass
    except CryptoError:
        raise SystemExit("could not unlock the identity file (wrong passphrase?)") from None


if __name__ == "__main__":
    main()
