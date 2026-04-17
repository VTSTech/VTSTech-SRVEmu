#!/usr/bin/env python3
"""
=============================================================================
 NASCAR Thunder 2004 (PS2) — Dir Server (TCP :10600)
=============================================================================

The first server the PS2 client contacts.  It receives a @dir request
containing the game's product identifier and version, then returns the
address of the Login Server along with a session key and ticket.

PROTOCOL (observed from PCAP):
    Client → @dir:  PROD=NASCAR-PS2-2004, VERS="PS2/XXX-Jul  2 2003",
                   LANG=en, SLUS=BASLUS-20824
    Server → @dir:  ADDR=<login_ip>, PORT=<login_port>, LKEY=<hex>,
                   SESS=<decimal>, MASK=4294967295

USAGE:
    python3 dir_server.py --host 0.0.0.0 --port 10600 --debug
    python3 dir_server.py --config dir_config.json
=============================================================================
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import socket
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

# ── Shared protocol ──────────────────────────────────────────────────────────
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from ea_protocol import (
    TCPStreamReader,
    send_kv,
    build_kv_body,
    DEFAULT_DIR_PORT,
    setup_logging,
)

LOG = logging.getLogger("dir_server")

# ── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_HOST = "0.0.0.0"
DEFAULT_LOGIN_HOST = ""  # empty = auto-detect LAN IP
DEFAULT_LOGIN_PORT = 10901


def get_lan_ip() -> str:
    """Auto-detect this machine's LAN IP (first non-loopback IPv4)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.2.123"  # fallback


# ── Session tracker ──────────────────────────────────────────────────────────

class DirSession:
    """Tracks a single client connection to the Dir Server."""

    def __init__(self, addr: tuple):
        self.addr = addr
        self.producer_id = ""
        self.version = ""
        self.lang = ""
        self.slus = ""
        self.login_key = ""
        self.session_id = ""
        self.created_at = time.time()


class DirServer:
    """
    TCP Dir Server on port 10600.

    Handles the initial @dir handshake that redirects the PS2 client
    to the Login Server.  This is a stateless request-response server:
    one connection, one @dir exchange, then the client disconnects and
    reconnects to the Login Server.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_DIR_PORT,
        login_host: str = DEFAULT_LOGIN_HOST,
        login_port: int = DEFAULT_LOGIN_PORT,
        debug: bool = False,
    ):
        self.host = host
        self.port = port
        self.login_host = login_host
        self.login_port = login_port
        self.debug = debug
        self._sessions: Dict[str, DirSession] = {}

    # ── Handlers ────────────────────────────────────────────────────────────

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single TCP client connection."""
        peer = writer.get_extra_info("peername")
        LOG.info("Connection from %s", peer)
        session = DirSession(peer)
        conn_id = uuid.uuid4().hex[:8]

        stream_reader = TCPStreamReader(reader)

        try:
            while True:
                frame = await stream_reader.read_frame()
                if frame is None:
                    break

                msg_type, kv, raw = frame
                LOG.info(
                    "[%s] RX %s: %s", conn_id, msg_type,
                    {k: v for k, v in kv.items()},
                )

                if msg_type == "@dir":
                    await self._handle_dir(conn_id, session, kv, writer)
                else:
                    LOG.warning(
                        "[%s] Unknown message type: %s", conn_id, msg_type
                    )

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            LOG.info("[%s] Client disconnected", conn_id)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            LOG.info("[%s] Connection closed", conn_id)

    async def _handle_dir(
        self,
        conn_id: str,
        session: DirSession,
        kv: Dict[str, str],
        writer: asyncio.StreamWriter,
    ) -> None:
        """Process a @dir request and respond with login server details."""
        session.producer_id = kv.get("PROD", "UNKNOWN")
        session.version = kv.get("VERS", "")
        session.lang = kv.get("LANG", "en")
        session.slus = kv.get("SLUS", "")

        LOG.info(
            "[%s] @dir: PROD=%s VERS=%s LANG=%s SLUS=%s",
            conn_id, session.producer_id, session.version,
            session.lang, session.slus,
        )

        # Generate session credentials
        login_key = uuid.uuid4().hex  # 32-char hex string
        session_id = str(int(time.time() * 1000))  # epoch milliseconds
        mask = 4294967295  # 0xFFFFFFFF — observed in PCAP

        session.login_key = login_key
        session.session_id = session_id

        # Send response
        send_kv(writer, "@dir", {
            "ADDR": self.login_host,
            "PORT": str(self.login_port),
            "LKEY": login_key,
            "SESS": session_id,
            "MASK": str(mask),
        })
        await writer.drain()

        LOG.info(
            "[%s] Redirected to login server %s:%d (LKEY=%s..., SESS=%s)",
            conn_id, self.login_host, self.login_port,
            login_key[:12], session_id,
        )

    # ── Server runner ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the TCP Dir Server."""
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        LOG.info(
            "Dir Server listening on %s:%d (login redirect → %s:%d)",
            addr[0], addr[1], self.login_host, self.login_port,
        )

        async with server:
            await server.serve_forever()


def load_config(path: str) -> dict:
    """Load JSON config file."""
    p = Path(path)
    if not p.exists():
        LOG.warning("Config not found: %s — using defaults", path)
        return {}
    with open(p, "r") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="NASCAR 2004 Dir Server (TCP :10600)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_DIR_PORT)
    parser.add_argument("--login-host", default=DEFAULT_LOGIN_HOST)
    parser.add_argument("--login-port", type=int, default=DEFAULT_LOGIN_PORT)
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    setup_logging(level=logging.DEBUG if args.debug else logging.INFO)

    cfg = load_config(args.config) if args.config else {}

    # Resolve login host: config > CLI arg > auto-detect LAN IP
    login_host = cfg.get("login_host", args.login_host)
    if not login_host:
        login_host = get_lan_ip()
        LOG.info("Auto-detected LAN IP: %s", login_host)

    server = DirServer(
        host=cfg.get("host", args.host),
        port=cfg.get("port", args.port),
        login_host=login_host,
        login_port=cfg.get("login_port", args.login_port),
        debug=args.debug,
    )

    asyncio.run(server.start())


if __name__ == "__main__":
    main()