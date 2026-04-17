#!/usr/bin/env python3
"""
=============================================================================
 NASCAR Thunder 2004 (PS2) — Buddy Server (TCP :10899)
=============================================================================

The Buddy Server handles friend lists (roster), presence tracking, chat,
and status updates.  The client connects here after the Login Server
(port 10901) pushes the BUDDY_URL/BUDDY_PORT in the newsnew0 message.

PROTOCOL FLOW (observed from PCAP):
    1. AUTH  — client authenticates: PROD, VERS, PRES, USER, LKEY
               → server replies NAME, S, STATUS
    2. PSET  — client sets presence/status: SHOW, STAT, PROD
               → server confirms NAME, ID, S, STATUS
    3. RGET  — client requests buddy roster: LRSC, LIST, PRES, ID
               → server responds per buddy: NAME, ID, S, STATUS, COUNT
    4. +pop  — server pushes population counts periodically
    5. +usr  — server pushes user presence updates

USAGE:
    python3 buddy_server.py --host 0.0.0.0 --port 10899 --debug
    python3 buddy_server.py --config buddy_config.json
=============================================================================
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Shared protocol ──────────────────────────────────────────────────────────
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from ea_protocol import (
    TCPStreamReader,
    send_kv,
    build_kv_body,
    DEFAULT_BUDDY_PORT,
    setup_logging,
)

LOG = logging.getLogger("buddy_server")

# ── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_HOST = "0.0.0.0"


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class BuddyClient:
    """Active client connected to the Buddy Server."""
    addr: Tuple[str, int]
    conn_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    username: str = ""
    user_path: str = ""       # e.g. "VTSTech/cso/nascar-ps2-2004"
    presence: str = ""        # e.g. "NASCAR2004"
    status: int = 0           # 0=offline, 1=online
    show_text: str = ""       # presence show message
    stat_text: str = ""       # status stat message
    prod_text: str = ""       # product display text
    roster_id: int = 0        # ID assigned by server
    authenticated: bool = False
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    # Friends list (buddy IDs)
    friends: Set[int] = field(default_factory=set)
    _keepalive_task: Optional[asyncio.Task] = field(default=None, repr=False)


@dataclass
class BuddyEntry:
    """A buddy (friend) in someone's roster."""
    buddy_id: int
    username: str
    status: int = 0
    count: int = 0            # online count / message count


# ── Buddy Server ────────────────────────────────────────────────────────────

class BuddyServer:
    """
    TCP Buddy Server on port 10899.

    Manages friend rosters, presence, and status updates using the EA
    Buddy protocol.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_BUDDY_PORT,
        debug: bool = False,
    ):
        self.host = host
        self.port = port
        self.debug = debug
        self._clients: Dict[str, BuddyClient] = {}
        self._client_writers: Dict[str, asyncio.StreamWriter] = {}
        self._next_roster_id: int = 1
        self._population_push_interval: int = 30  # seconds

    # ── Client handler ──────────────────────────────────────────────────────

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        LOG.info("Connection from %s", peer)
        client = BuddyClient(addr=peer)
        self._clients[client.conn_id] = client
        self._client_writers[client.conn_id] = writer
        stream = TCPStreamReader(reader)

        # Start periodic keepalive to prevent client disconnect
        client._keepalive_task = asyncio.create_task(
            self._keepalive_loop(client, writer)
        )

        try:
            while True:
                frame = await stream.read_frame()
                if frame is None:
                    break

                msg_type, kv, raw = frame
                clean_type = msg_type.rstrip('\x00')
                LOG.info(
                    "[%s] RX %s: %s", client.conn_id, clean_type, dict(kv)
                )

                await self._dispatch(client, clean_type, kv, writer)

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            LOG.info("[%s] Client disconnected", client.conn_id)
        finally:
            # Cancel keepalive task
            if client._keepalive_task:
                client._keepalive_task.cancel()
            client.status = 0
            self._clients.pop(client.conn_id, None)
            self._client_writers.pop(client.conn_id, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            LOG.info("[%s] Connection closed (%s)", client.conn_id, client.username)

    async def _dispatch(
        self,
        client: BuddyClient,
        msg_type: str,
        kv: Dict[str, str],
        writer: asyncio.StreamWriter,
    ) -> None:
        handler = {
            "AUTH": self._handle_auth,
            "PSET": self._handle_pset,
            "RGET": self._handle_rget,
            "STAT": self._handle_stat,
            "SEND": self._handle_send,
            "~png": self._handle_ping,
        }.get(msg_type)

        if handler:
            await handler(client, kv, writer)
        else:
            LOG.warning("[%s] No handler for: %s", client.conn_id, msg_type)

    # ── Message handlers ────────────────────────────────────────────────────

    async def _handle_auth(
        self, client: BuddyClient, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client authenticates with the Buddy Server."""
        prod = kv.get("PROD", "")
        vers = kv.get("VERS", "")
        pres = kv.get("PRES", "")
        user = kv.get("USER", "")
        lkey = kv.get("LKEY", "")

        LOG.info(
            "[%s] AUTH: PROD=%s VERS=%s USER=%s",
            client.conn_id, prod, vers, user,
        )

        client.username = user.split("/")[0] if "/" in user else user
        client.user_path = user
        client.presence = pres
        client.authenticated = True
        client.status = 1  # Mark as online so +pop counts correctly
        client.roster_id = self._next_roster_id
        self._next_roster_id += 1
        client.last_activity = time.time()

        # Respond with auth confirmation
        send_kv(writer, "AUTH", {
            "NAME": client.username,
            "S": "0",
            "STATUS": "1",   # STATUS=1 means auth succeeded
        })
        await writer.drain()

        # After a short delay, push population
        await asyncio.sleep(0.1)
        await self._push_population(client, writer)

    async def _handle_pset(
        self, client: BuddyClient, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client sets presence/status."""
        show = kv.get("SHOW", "")
        stat = kv.get("STAT", "")
        prod = kv.get("PROD", "")

        LOG.info(
            "[%s] PSET: SHOW=%s STAT=%s PROD=%s",
            client.conn_id, show, stat, prod,
        )

        client.show_text = show
        client.stat_text = stat
        client.prod_text = prod
        client.last_activity = time.time()

        # Confirm
        send_kv(writer, "PSET", {
            "NAME": client.username,
            "ID": str(client.roster_id),
            "S": "0",
            "STATUS": "1",
        })
        await writer.drain()

    async def _handle_rget(
        self, client: BuddyClient, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client requests buddy roster."""
        lrsc = kv.get("LRSC", "")
        list_val = kv.get("LIST", "")
        pres = kv.get("PRES", "")
        req_id = kv.get("ID", "")

        LOG.info(
            "[%s] RGET: LRSC=%s LIST=%s PRES=%s ID=%s",
            client.conn_id, lrsc, list_val, pres, req_id,
        )

        client.last_activity = time.time()

        # The RGET can contain multiple back-to-back requests in one frame
        # (observed in PCAP: two RGET blocks in one frame)
        # Respond with the user's own info for each request
        if req_id:
            send_kv(writer, "RGET", {
                "NAME": client.username,
                "ID": req_id,
                "S": "0",
                "STATUS": "1",
                "COUNT": "0",
            })
            await writer.drain()

    async def _handle_stat(
        self, client: BuddyClient, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Status check."""
        send_kv(writer, "STAT", {"STATUS": str(client.status)})
        await writer.drain()

    async def _handle_send(
        self, client: BuddyClient, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Buddy instant message (TYPE=C = chat)."""
        msg_type = kv.get("TYPE", "")
        target_user = kv.get("USER", "")
        body = kv.get("BODY", "")
        secs = kv.get("SECS", "")

        LOG.info(
            "[%s] SEND: TYPE=%s USER=%s BODY=%s SECS=%s",
            client.conn_id, msg_type, target_user, body, secs,
        )

        client.last_activity = time.time()

        # Acknowledge receipt to sender
        send_kv(writer, "SEND", {"S": "0"})
        await writer.drain()

        # Deliver to recipient if online
        if msg_type == "C" and target_user:
            for c in self._clients.values():
                if c.authenticated and c.username == target_user and c.conn_id != client.conn_id:
                    # Look up the sender's writer from the server's active connections
                    # We'll need to store writers per client — use _client_writers
                    recipient = c
                    break
            else:
                recipient = None

            if recipient and recipient.conn_id in self._client_writers:
                recv_writer = self._client_writers[recipient.conn_id]
                send_kv(recv_writer, "SEND", {
                    "FROM": client.username,
                    "TYPE": msg_type,
                    "BODY": body,
                    "TIME": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
                try:
                    await recv_writer.drain()
                except Exception as e:
                    LOG.warning("[%s] Failed to deliver message to %s: %s",
                                client.conn_id, target_user, e)

    async def _handle_ping(
        self, client: BuddyClient, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Handle ~png keepalive from the PS2 client.

        Do NOT respond — the _keepalive_loop sends pings proactively.
        Responding here would cause an infinite ping-pong loop.
        """
        client.last_activity = time.time()

    # ── Keepalive ───────────────────────────────────────────────────────

    async def _keepalive_loop(
        self, client: BuddyClient, writer: asyncio.StreamWriter
    ) -> None:
        """Send periodic ~png keepalive to prevent client timeout/disconnect."""
        try:
            while True:
                await asyncio.sleep(20)  # every 20 seconds
                if client.authenticated:
                    send_kv(writer, "~png", {
                        "TIME": "2",
                        "NAME": client.username,
                        "STATUS": str(client.status),
                    })
                    try:
                        await writer.drain()
                    except Exception:
                        break
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    # ── Server pushes ──────────────────────────────────────────────────────

    async def _push_population(
        self, client: BuddyClient, writer: asyncio.StreamWriter
    ) -> None:
        """Push +pop — population counts."""
        online_count = sum(1 for c in self._clients.values() if c.authenticated and c.status)
        parts = [f"0:{online_count}", "1:0", "2:0", "3:0"]
        send_kv(writer, "+pop", {"Z": " ".join(parts)})
        await writer.drain()

    async def _push_user_presence(
        self, client: BuddyClient, writer: asyncio.StreamWriter
    ) -> None:
        """Push +usr — user presence update for a specific user."""
        send_kv(writer, "+usr", {
            "I": str(client.roster_id),
            "N": client.username,
            "F": "1",
            "A": client.addr[0],
        })
        await writer.drain()

    # ── Server runner ──────────────────────────────────────────────────────

    async def start(self) -> None:
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        LOG.info("Buddy Server listening on %s:%d", addr[0], addr[1])

        async with server:
            await server.serve_forever()


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="NASCAR 2004 Buddy Server (TCP :10899)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_BUDDY_PORT)
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    setup_logging(level=logging.DEBUG if args.debug else logging.INFO)

    cfg = load_config(args.config) if args.config else {}

    server = BuddyServer(
        host=cfg.get("host", args.host),
        port=cfg.get("port", args.port),
        debug=args.debug,
    )

    asyncio.run(server.start())


if __name__ == "__main__":
    main()