"""Run the saddler IRC hub: asyncio IRC server + the web dashboard thread."""
from __future__ import annotations

import asyncio
import threading

from .. import config
from ..ledger import Ledger
from .server import Hub
from .web import run_web


async def _serve(hub, host, port):
    server = await asyncio.start_server(hub.on_connect, host, port)
    async with server:
        await server.serve_forever()


def run(host=None, port=None, web_port=None):
    host = host or config.HUB_BIND
    port = port or config.IRC_PORT
    web_port = web_port or config.HUB_WEB_PORT
    # Fail closed: a writable IRC server (control channels) must not be exposed
    # beyond loopback without auth — set SADDLER_IRC_PASSWORD to expose it.
    if host not in ("127.0.0.1", "localhost", "::1") and not config.IRC_PASSWORD:
        raise SystemExit(
            f"saddler hub: refusing to bind a writable IRC server to {host} without "
            "auth. Set SADDLER_IRC_PASSWORD to expose it, or bind 127.0.0.1 (default)."
        )
    from ..netwatch import NetWatch
    hub = Hub(ledger=Ledger())
    threading.Thread(target=run_web, args=(hub, web_port, host, NetWatch()), daemon=True).start()
    print(f"saddler IRC hub · irc://{host}:{port} · dashboard http://{host}:{web_port}",
          flush=True)
    try:
        asyncio.run(_serve(hub, host, port))
    except KeyboardInterrupt:
        pass
