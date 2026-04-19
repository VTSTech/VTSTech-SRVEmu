#!/usr/bin/env python3
"""
=============================================================================
 NASCAR Thunder 2004 (PS2) — Login Server (TCP :10901)
=============================================================================

Handles authentication, room management, and matchmaking for the EA Lobby
protocol.  The client connects here after receiving the redirect from the
Dir Server (port 10600).

PROTOCOL FLOW (observed from PCAP):
    1. addr  — client reports its own IP:port  →  server replies STATUS=1
    2. skey  — client sends public key ($hex)  →  server replies SKEY=0
    3. auth  — full login (NAME, PASS, MID, PROD, VERS, HWFLAG, HWMASK, SLUS, MASK)
               →  server replies TOS, NAME, USER, PERSONAS, PRIV, LAST, SESS, S, STATUS
    4. pers  — client selects persona (PERS=name) → server confirms
    5. +who  — server pushes user's own presence info (F, N, RI, RT, R, RF)
    6. sele  — client requests room/user/rank/message counts
               →  server replies with user rank (DRANK, USER, RATING, WINS, LOSS, STATUS)
    7. news  — client requests news by NAME=0
               →  server replies with rank info, then pushes newsnew0
                 containing BUDDY_URL, BUDDY_PORT, BUDDY_SERVER, etc.
    8. +rom  — server pushes room listings (HI/JI/NI=index, N=name, H=heading,
               A=address, T=type, L=limit, F=flags)
    9. +usr  — server pushes user info for users in the room (I=id, N=name,
               M=motto, RI=room_id, ST=status, F=flags)
   10. +pop  — server pushes population counts (Z=room_id:user_count ...)
   11. move  — client joins a room (NAME=room_name, PASS=password)
               →  server confirms (I=room_index, N=room_name, F=flags)

USAGE:
    python3 login_server.py --host 0.0.0.0 --port 10901 --debug
    python3 login_server.py --config login_config.json
=============================================================================
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import socket
import sqlite3
import struct
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
    send_frame,
    build_kv_body,
    DEFAULT_LOGIN_PORT,
    setup_logging,
)

LOG = logging.getLogger("login_server")

# ── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_HOST = "0.0.0.0"
DEFAULT_BUDDY_HOST = ""  # empty = auto-detect LAN IP
DEFAULT_BUDDY_PORT = 10899


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


def ip_to_int(ip_string: str) -> str:
    """Convert dotted-quad IP to integer string for the Aries protocol.

    The PS2 client parses the A tag via TagFieldGetAddress which expects
    an integer, NOT a dotted-quad string.  Sending A=192.168.2.123 will
    fail; it must be A=3232236155.

    Ref: cheatsheet.md "Wrong IP Format" and protocol_spec.md "IP Address".
    """
    try:
        return str(struct.unpack("!I", socket.inet_aton(ip_string))[0])
    except Exception:
        return "0"


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class User:
    """A registered user account."""
    username: str
    password_hash: str = ""
    personas: str = ""       # comma-separated: "VTSTech,{is},Reviving,\"PS2 Games\""
    rating: int = 1500
    wins: int = 0
    losses: int = 0
    tos_accepted: bool = True
    status: int = 0          # 0=offline, 1=online
    last_login: str = ""
    session_key: str = ""
    hwflag: int = 4
    hwmask: str = "65828"

    def to_auth_response(self, session_id: str) -> Dict[str, str]:
        return {
            "TOS": "1" if self.tos_accepted else "0",
            "NAME": self.username,
            "USER": "Unknown",
            "PERSONAS": self.personas,
            "PRIV": "",
            "LAST": "",
            "SESS": session_id,
            "S": "0",
            "STATUS": "0",
        }


@dataclass
class Room:
    """A chat/matchmaking room."""
    index: int = 0
    name: str = ""
    heading: str = ""
    address: str = "127.0.0.1"
    room_type: int = 0       # T: 0=regular, 1=main lobby
    limit: int = 100
    flags: int = 0
    password: str = ""


@dataclass
class ClientConn:
    """Active client connection state."""
    addr: Tuple[str, int]
    conn_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    username: str = ""
    persona: str = ""
    client_ip: str = ""
    client_port: int = 0
    session_id: str = ""
    authenticated: bool = False
    current_room_idx: int = -1
    room_index: int = -1     # RI field (room they're in)
    created_at: float = field(default_factory=time.time)
    _writer: Optional[asyncio.StreamWriter] = field(default=None, repr=False)
    _keepalive_task: Optional[asyncio.Task] = field(default=None, repr=False)


# ── Database ────────────────────────────────────────────────────────────────

class LoginDatabase:
    """SQLite persistence for users and accounts."""

    def __init__(self, db_path: str = "login_server.db"):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._init_tables()

    def _init_tables(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL DEFAULT '',
                personas TEXT NOT NULL DEFAULT '',
                rating INTEGER NOT NULL DEFAULT 1500,
                wins INTEGER NOT NULL DEFAULT 0,
                losses INTEGER NOT NULL DEFAULT 0,
                tos_accepted INTEGER NOT NULL DEFAULT 1,
                hwflag INTEGER NOT NULL DEFAULT 4,
                hwmask TEXT NOT NULL DEFAULT '65828'
            )
        """)
        self.conn.commit()

    def get_user(self, username: str) -> Optional[User]:
        cur = self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return User(
            username=row["username"],
            password_hash=row["password_hash"],
            personas=row["personas"],
            rating=row["rating"],
            wins=row["wins"],
            losses=row["losses"],
            tos_accepted=bool(row["tos_accepted"]),
            hwflag=row["hwflag"],
            hwmask=row["hwmask"],
        )

    def create_user(self, username: str, password: str = "") -> User:
        pw_hash = hashlib.md5(password.encode()).hexdigest() if password else hashlib.md5(username.encode()).hexdigest()
        # Default personas format matching PCAP
        personas = f"{username},{{is}},Reviving,\"PS2 Games\""
        user = User(
            username=username,
            password_hash=pw_hash,
            personas=personas,
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, personas) VALUES (?, ?, ?)",
            (username, pw_hash, personas),
        )
        self.conn.commit()
        return user

    def verify_password(self, username: str, password_hash: str) -> bool:
        """Verify a password hash sent by the client ($hex format)."""
        # The client sends PASS=$md5hash — we just accept any hash for emulation
        # In a real system you'd compare against stored hash
        user = self.get_user(username)
        if not user:
            return True  # Auto-create
        return True  # Accept any login for emulation

    def close(self):
        if self.conn:
            self.conn.close()


# ── Login Server ─────────────────────────────────────────────────────────────

class LoginServer:
    """
    TCP Login Server on port 10901.

    Handles the full login lifecycle: addr, skey, auth, pers, room
    management (sele, news, move), and async pushes (+who, +rom, +usr, +pop).
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_LOGIN_PORT,
        buddy_host: str = DEFAULT_BUDDY_HOST,
        buddy_port: int = DEFAULT_BUDDY_PORT,
        debug: bool = False,
        db_path: str = "login_server.db",
    ):
        self.host = host
        self.port = port
        self.buddy_host = buddy_host
        self.buddy_port = buddy_port
        self.debug = debug
        self.db = LoginDatabase(db_path)

        # Active connections: conn_id -> ClientConn
        self._clients: Dict[str, ClientConn] = {}

        # Default rooms (matching PCAP captures)
        # Index 0 (Lobby) is implicit — the client assumes it exists and
        # uses it as the "room selection" screen.  It is NOT pushed via
        # +rom in the room-join flow.  In the login flow it IS pushed
        # with HI=0 and T=1 (room_type=1 = main lobby).
        self._rooms: List[Room] = [
            Room(index=0, name="Lobby", heading="Main Lobby Hub",
                 address=buddy_host, room_type=1, limit=100),
            Room(index=1, name="East", heading="East Coast Racers",
                 address=buddy_host, room_type=1, limit=50),
            Room(index=2, name="West", heading="West Coast Racers",
                 address=buddy_host, room_type=1, limit=50),
            Room(index=3, name="Beginner", heading="New Drivers Welcome",
                 address=buddy_host, room_type=1, limit=50),
        ]

    # ── Client handler ──────────────────────────────────────────────────────

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        LOG.info("Connection from %s", peer)
        conn = ClientConn(addr=peer)
        conn._writer = writer
        self._clients[conn.conn_id] = conn
        stream = TCPStreamReader(reader)

        # Start periodic keepalive to prevent client disconnect
        conn._keepalive_task = asyncio.create_task(
            self._keepalive_loop(conn, writer)
        )

        try:
            while True:
                frame = await stream.read_frame()
                if frame is None:
                    break

                msg_type, kv, raw = frame

                # Trim null bytes from msg_type for display
                clean_type = msg_type.rstrip('\x00')
                LOG.info("[%s] RX %s: %s", conn.conn_id, clean_type, dict(kv))

                await self._dispatch(conn, clean_type, kv, writer)

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            LOG.info("[%s] Client disconnected", conn.conn_id)
        except Exception as exc:
            LOG.error("[%s] Unhandled exception: %s: %s", conn.conn_id, type(exc).__name__, exc, exc_info=True)
        finally:
            # Cancel keepalive task
            if conn._keepalive_task:
                conn._keepalive_task.cancel()
            # Notify other clients in the same room
            if conn.authenticated and conn.current_room_idx > 0:
                await self._broadcast_room_leave(conn, conn.current_room_idx)
            # Clean up
            self._clients.pop(conn.conn_id, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            LOG.info("[%s] Connection closed", conn.conn_id)

    async def _dispatch(
        self,
        conn: ClientConn,
        msg_type: str,
        kv: Dict[str, str],
        writer: asyncio.StreamWriter,
    ) -> None:
        """Dispatch incoming messages to appropriate handlers."""
        handler = {
            "addr": self._handle_addr,
            "skey": self._handle_skey,
            "auth": self._handle_auth,
            "pers": self._handle_pers,
            "sele": self._handle_sele,
            "news": self._handle_news,
            "move": self._handle_move,
            "room": self._handle_room,
            "STAT": self._handle_stat,
            "snap": self._handle_snap,
            "user": self._handle_user,
            "mesg": self._handle_mesg,
            "peek": self._handle_peek,
            "~png": self._handle_ping,
        }.get(msg_type)

        if handler:
            try:
                await handler(conn, kv, writer)
            except Exception as exc:
                LOG.error("[%s] Handler %s crashed: %s: %s", conn.conn_id, msg_type, type(exc).__name__, exc, exc_info=True)
        else:
            LOG.warning("[%s] No handler for: %s", conn.conn_id, msg_type)

    # ── Message handlers ────────────────────────────────────────────────────

    async def _handle_addr(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client reports its IP and port."""
        conn.client_ip = kv.get("ADDR", conn.addr[0])
        conn.client_port = int(kv.get("PORT", conn.addr[1]))
        LOG.info(
            "[%s] addr: client at %s:%d",
            conn.conn_id, conn.client_ip, conn.client_port,
        )
        send_kv(writer, "addr", {"STATUS": "1"})
        await writer.drain()

    async def _handle_skey(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client sends public key exchange."""
        skey = kv.get("SKEY", "")
        LOG.info("[%s] skey: %s...", conn.conn_id, skey[:20])
        # Accept and clear — respond with SKEY=0 (key exchange complete)
        send_kv(writer, "skey", {"SKEY": "0"})
        await writer.drain()

    async def _handle_auth(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Full authentication handshake."""
        username = kv.get("NAME", "")
        password = kv.get("PASS", "")
        mid = kv.get("MID", "")
        prod = kv.get("PROD", "")
        vers = kv.get("VERS", "")
        lang = kv.get("LANG", "en")
        slus = kv.get("SLUS", "")
        mask = kv.get("MASK", "")

        LOG.info("[%s] auth: NAME=%s PROD=%s", conn.conn_id, username, prod)

        # Get or create user
        user = self.db.get_user(username)
        if not user:
            user = self.db.create_user(username)

        conn.username = username
        conn.authenticated = True
        conn.session_id = str(int(time.time() * 1000))

        # Store session reference in the user's password field for buddy auth
        # (the buddy server will receive LKEY=$0 which maps to this session)

        # Respond with auth confirmation
        send_kv(writer, "auth", user.to_auth_response(conn.session_id))
        await writer.drain()

        # Set room state to Lobby (room 0) — the user is conceptually
        # "in the Lobby" from the moment they authenticate.  The PCAP
        # shows RI=0 in the +who push that follows pers.
        conn.room_index = 0
        conn.current_room_idx = 0

        # NOTE: No pushes here!  The PCAP shows the server does NOT
        # push +who/+rom/+usr/+pop after auth.  They come later:
        #   +who  → after pers
        #   +rom/+usr/+pop → after news NAME=0

    async def _handle_pers(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client selects a persona."""
        persona = kv.get("PERS", conn.username)
        conn.persona = persona
        LOG.info("[%s] pers: selected %s", conn.conn_id, persona)

        # Confirm persona selection
        user = self.db.get_user(conn.username)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        send_kv(writer, "pers", {
            "PERS": persona,
            "LKEY": "$0",
            "S": "0",
            "STATUS": "0",
            "LAST": now,
        })
        await writer.drain()

        # Push +who after pers — the PCAP shows this is where +who
        # arrives (RI=0, meaning the user is in the Lobby).
        await asyncio.sleep(0.05)
        await self._push_who(conn, writer)

    async def _handle_sele(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client requests selection info (room counts, rank).

        PCAP ground truth — two distinct sele requests:

        1) Initial query (ROOMS=1 USERS=1 RANKS=1 MESGS=1):
           → server responds with DRANK only (display rank)

        2) Rank expansion (RANKS=50, no other fields):
           → server responds with ERANK only (expanded rank list)

        These are mutually exclusive — each sele gets exactly one response.
        """
        LOG.info("[%s] sele: %s", conn.conn_id, dict(kv))

        user = self.db.get_user(conn.username)

        if "ROOMS" in kv or "USERS" in kv or "MESGS" in kv:
            # ── Initial query: respond with DRANK only ──
            # Client sends ROOMS=1 USERS=1 RANKS=1 MESGS=1 to request
            # room/user/rank/message counts.  Server responds with the
            # user's display rank (DRANK) and that's it.
            send_kv(writer, "sele", {
                "DRANK": str(user.rating if user else 1500),
                "USER": conn.username,
                "RATING": str(user.rating if user else 1500),
                "WINS": str(user.wins if user else 0),
                "LOSS": str(user.losses if user else 0),
                "STATUS": "0",
            })
            await writer.drain()

        elif "RANKS" in kv:
            # ── Rank expansion: respond with ERANK only ──
            # Client sends RANKS=50 (no ROOMS/USERS/MESGS) to request
            # an expanded rank listing.  Server responds with ERANK.
            send_kv(writer, "sele", {
                "ERANK": str(user.rating if user else 50),
                "USER": conn.username,
                "RATING": str(user.rating if user else 1500),
                "WINS": str(user.wins if user else 0),
                "LOSS": str(user.losses if user else 0),
                "STATUS": "0",
            })
            await writer.drain()

    async def _handle_news(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client requests news. Server pushes rank info, buddy handoff,
        then room list (+rom), user info (+usr), and population (+pop).

        PCAP ground truth — the response to ``news NAME=0`` is:
            1. sele  ERANK=... USER=... RATING=... WINS=... LOSS=... STATUS=0
               (NOTE: type is ``sele``, NOT ``news``!)
            2. news  newsnew0  BUDDY_URL=... BUDDY_PORT=... ...
               (buddy handoff, flags=b"new0")
            3. +rom  HI=0 N=Lobby ... JI=1 N=East ... PI=3 N=Beginner ...
            4. +usr  I=<id> N=<name> F=1 A=<client_ip>
            5. +pop  Z=0:1 1:0 2:0 3:0
        """
        name = kv.get("NAME", "0")
        LOG.info("[%s] news: NAME=%s", conn.conn_id, name)

        user = self.db.get_user(conn.username)

        # 1) First response — type is 'sele', not 'news'!
        #    Verified against both PCAP captures.
        send_kv(writer, "sele", {
            "ERANK": str(user.rating if user else 50),
            "USER": conn.username,
            "RATING": str(user.rating if user else 1500),
            "WINS": str(user.wins if user else 0),
            "LOSS": str(user.losses if user else 0),
            "STATUS": "0",
        })
        await writer.drain()

        # 2) Push newsnew0 with buddy server handoff info
        await asyncio.sleep(0.05)
        send_kv(writer, "news", {
            "BUDDY_URL": self.buddy_host,
            "BUDDY_PORT": str(self.buddy_port),
            "BUDDY_SERVER": self.buddy_host,
            "TOS_TEXT": f"{conn.username}_TOS",
            "NEWS_TEXT": f"{conn.username}_NEWS",
            "USE_ETOKEN": "0",
            "S": "0",
            "STATUS": "0",
        }, flags=b"new0")
        await writer.drain()

        # 3) Push room list — PCAP shows this comes after newsnew0
        await asyncio.sleep(0.05)
        await self._push_room_list(conn, writer)

        # 4) Push user info (login/lobby format: I, N, F=1, A=ip)
        await asyncio.sleep(0.05)
        await self._push_user_login(conn, writer)

        # 5) Push population counts
        await asyncio.sleep(0.05)
        await self._push_population(conn, writer)

    async def _handle_move(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client joins or leaves a room.

        When NAME is non-empty the client wants to join a named room.
        When NAME is empty the client is leaving its current room (going
        back to an unroomed / lobby-browsing state).  Observed on real PS2
        after a game-invite decline flow.
        """
        room_name = kv.get("NAME", "")
        password = kv.get("PASS", "")
        LOG.info("[%s] move: NAME=%s PASS=%s", conn.conn_id, room_name, password)

        # Empty name = leave current room, go back to Lobby (room 0)
        if not room_name:
            old_idx = conn.current_room_idx
            conn.current_room_idx = 0
            conn.room_index = 0
            LOG.info("[%s] move: left room %d (back to Lobby)", conn.conn_id, old_idx)
            # PCAP shows: move I=0 N=Lobby F=0 (NOT S=0)
            send_kv(writer, "move", {"I": "0", "N": "Lobby", "F": "0"})
            await writer.drain()
            # Match PCAP move-leave pushes: +pop, +who, +usr, +pop
            await asyncio.sleep(0.05)
            await self._push_population(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_who(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_user_login(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_population(conn, writer)
            # Notify other clients in the old room
            if old_idx > 0:
                await self._broadcast_room_leave(conn, old_idx)
            return

        # Find room by name
        room_idx = -1
        for room in self._rooms:
            if room.name.lower() == room_name.lower():
                room_idx = room.index
                break

        if room_idx >= 0:
            conn.current_room_idx = room_idx
            conn.room_index = room_idx
            send_kv(writer, "move", {
                "I": str(room_idx),
                "N": room_name,
                "F": "0",
            })
            await writer.drain()

            # PCAP move-join push sequence:
            #   +pop → +usr(room format) → +who → +pop → +usr(login format)
            await asyncio.sleep(0.05)
            await self._push_population(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_user_in_room(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_who(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_population(conn, writer)
            await asyncio.sleep(0.05)
            await self._push_user_login(conn, writer)

            # Push existing room occupants to the joiner
            await self._push_existing_room_users(conn, room_idx, writer)

            # Broadcast to other clients already in this room
            await self._broadcast_room_join(conn, room_idx)
        else:
            LOG.warning("[%s] Room not found: %s", conn.conn_id, room_name)

    async def _handle_room(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Client creates or joins a custom room.

        The PS2 sends a 'room' message with NAME, PASS, DESC, MAX fields.
        This is essentially a room-creation request.  We create the room
        dynamically and immediately move the client into it.
        """
        room_name = kv.get("NAME", "")
        password = kv.get("PASS", "")
        desc = kv.get("DESC", "")
        max_users = int(kv.get("MAX", "50"))

        LOG.info(
            "[%s] room: NAME=%s PASS=%s DESC=%s MAX=%d",
            conn.conn_id, room_name, password, desc, max_users,
        )

        if not room_name:
            return

        # Check if room already exists
        room_idx = -1
        for room in self._rooms:
            if room.name.lower() == room_name.lower():
                room_idx = room.index
                break

        if room_idx < 0:
            # Create a new room dynamically
            room_idx = len(self._rooms)
            self._rooms.append(Room(
                index=room_idx,
                name=room_name,
                heading=desc if desc and desc != "None" else room_name,
                address=self.buddy_host,
                room_type=0,
                limit=max_users,
                password=password,
            ))
            LOG.info("[%s] Created room %d: %s", conn.conn_id, room_idx, room_name)

        # Move the client into the room
        conn.current_room_idx = room_idx
        conn.room_index = room_idx

        # Respond with room confirmation (same format as 'move' response)
        send_kv(writer, "room", {
            "I": str(room_idx),
            "N": room_name,
            "F": "0",
        })
        await writer.drain()

        # Push updated room list (exclude Lobby), user list, and population
        await asyncio.sleep(0.05)
        await self._push_room_list(conn, writer, include_lobby=False)
        await asyncio.sleep(0.05)
        await self._push_user_in_room(conn, writer)
        await asyncio.sleep(0.05)
        await self._push_population(conn, writer)

    async def _handle_stat(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Status request."""
        send_kv(writer, "STAT", {"STATUS": "0"})
        await writer.drain()

    async def _handle_snap(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Stats snapshot request — player lookup OR leaderboard browsing.

        Two distinct modes observed from real PS2 traffic:

        CHAN=4 — Player lookup (search by name)
            INDEX=0, FIND=VTSTech, RANGE=1
            Server responds with +snp for matching player, then snap S=0.

        CHAN=5 — Leaderboard browsing (paginated ranked list)
            INDEX=page_offset, START=0, RANGE=100 (first page)
            INDEX=1, START=0, RANGE=10 (subsequent pages)
            Server should respond with multiple +snp entries (one per player
            on the page) sorted by rank, then snap S=0.  With no real
            player data we send an empty leaderboard (just S=0).

        +snp response fields (from PCAP):
            N=player name, R=rank/rating, W=wins, L=losses, S=streak,
            P=poles, T5=top 5 finishes, T10=top 10, LL=laps led,
            LC=lap count, STRK=best streak, AS=avg speed, AF=avg finish
        """
        index = kv.get("INDEX", "0")
        chan = kv.get("CHAN", "0")
        find = kv.get("FIND", "")
        start = kv.get("START", "0")
        range_val = kv.get("RANGE", "1")

        LOG.info(
            "[%s] snap: INDEX=%s CHAN=%s FIND=%s START=%s RANGE=%s",
            conn.conn_id, index, chan, find, start, range_val,
        )

        if chan == "4" and find:
            # ── Player lookup: return stats for the named player ──
            user = self.db.get_user(find) or self.db.get_user(conn.username)
            if user:
                send_kv(writer, "+snp", {
                    "N": user.username,
                    "R": str(user.rating),
                    "W": str(user.wins),
                    "L": str(user.losses),
                    "S": "0",          # streak
                    "P": "0",          # poles
                    "T5": "0",         # top 5 finishes
                    "T10": "0",        # top 10 finishes
                    "LL": "0",         # laps led
                    "LC": "0",         # lap count
                    "STRK": "0",       # best streak
                    "AS": "0",         # average speed
                    "AF": "0",         # average finish
                })
                await writer.drain()
            LOG.info("[%s] snap: sent player stats for %s", conn.conn_id, find)

        elif chan == "5":
            # ── Leaderboard browsing: paginated ranked list ──
            # In a full implementation we'd query users sorted by rating
            # and return RANGE entries starting at START/INDEX.
            # For now, send empty leaderboard (just the S=0 terminator).
            LOG.info(
                "[%s] snap: leaderboard page (INDEX=%s RANGE=%s) — no entries",
                conn.conn_id, index, range_val,
            )

        # Final frame signals end of stats batch
        await asyncio.sleep(0.05)
        send_kv(writer, "snap", {"S": "0"})
        await writer.drain()
        LOG.info("[%s] snap: sent final S=0", conn.conn_id)

    async def _handle_peek(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Room peek — client requests the user list for a named room.

        The PS2 sends ``peek NAME=<room_name>`` when the user highlights or
        selects a room from the room list.  The server responds by pushing
        ``+usr`` entries for every authenticated user currently in that room,
        followed by a ``peek S=0`` terminator (mirrors the snap protocol).

        The response lets the client display "X in room" and a username list
        without the client having to join the room first.
        """
        room_name = kv.get("NAME", "")
        LOG.info("[%s] peek: NAME=%s", conn.conn_id, room_name)

        # Find the room by name
        target_idx = -1
        for room in self._rooms:
            if room.name.lower() == room_name.lower():
                target_idx = room.index
                break

        if target_idx < 0:
            LOG.warning("[%s] peek: room not found: %s", conn.conn_id, room_name)
            send_kv(writer, "peek", {"S": "0"})
            await writer.drain()
            return

        # Push +usr for every user in the target room
        count = 0
        for cid, c in self._clients.items():
            if c.authenticated and c.current_room_idx == target_idx:
                user_id = abs(hash(c.username)) % 1000000
                send_kv(writer, "+usr", {
                    "I": str(user_id),
                    "N": c.username,
                    "A": ip_to_int(c.client_ip or self.buddy_host),
                    "R": str(target_idx),
                    "S": "Online",
                    "F": "0",
                    "P": "",
                })
                await writer.drain()
                await asyncio.sleep(0.02)
                count += 1

        # Terminator
        await asyncio.sleep(0.03)
        send_kv(writer, "peek", {"S": "0"})
        await writer.drain()
        LOG.info("[%s] peek: sent %d users in room '%s' (idx=%d)",
                 conn.conn_id, count, room_name, target_idx)

    async def _handle_user(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """User profile lookup.

        The client sends 'user' with PERS=<username> to request profile
        information for a specific user.  This is likely used for the player
        profile display when viewing another user in the lobby.

        Client request fields (from real PS2 capture):
            PERS=VTSTech  — the persona name to look up

        """
        pers = kv.get("PERS", "")

        LOG.info("[%s] user: PERS=%s", conn.conn_id, pers)

        # Look up the requested user, fall back to self if not found
        target_user = self.db.get_user(pers) or self.db.get_user(conn.username)
        if target_user:
            # Return user profile info — similar fields to auth response
            send_kv(writer, "user", {
                "N": target_user.username,
                "R": str(target_user.rating),
                "W": str(target_user.wins),
                "L": str(target_user.losses),
                "PERSONAS": target_user.personas,
                "STATUS": "1",
            })
            await writer.drain()

            LOG.info("[%s] user: sent profile for %s", conn.conn_id, target_user.username)
        else:
            # User not found — send minimal response
            send_kv(writer, "user", {"N": pers, "STATUS": "0"})
            await writer.drain()
            LOG.warning("[%s] user: user not found: %s", conn.conn_id, pers)

    async def _handle_mesg(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Private message / room chat / game invitation.

        The client sends 'mesg' with PRIV, TEXT, and ATTR fields:

            ATTR=0, PRIV=     — room chat (broadcast to all in same room)
            ATTR=0, PRIV=name — private whisper to a specific user
            ATTR=3             — game invite / invite-related

        The PRIV field contains the *target* username (empty = room broadcast).
        TEXT contains the payload (chat text, invite token, 'DECL', etc.).

        Binary-verified tags (C→S send path in fcn.00288668):
            PRIV  — 0x3d8390 (.rodata)
            TEXT  — 0x3d8398 (.rodata)
            ATTR  — 0x3d83a0 (.rodata)

        Server relay uses '+msg' type (0x2b6d7367), NOT 'mesg'.
        The binary has NO 'mesg' receive handler — 'mesg' is send-only.
        '+msg' is dispatched in LobbyApiUpdate (fcn.0031bdf0) at 0x31c6f8.

        Relay payload format (protocol doc §8.4 + r2 analysis):
            Room broadcast: FROM=username, TEXT=message, CHAT=public, TIME=ts
            Private message: FROM=username, TEXT=message, PRIV=target, TIME=ts

        The +msg handler at 0x31c6f8 in LobbyApiUpdate dispatches S→C relay.
        Protocol doc §8.4: "Server broadcasts to ALL room members" — sender
        included.  The client uses the +msg for display, not local echo.

        Key fixes:
            Session 12: BODY→TEXT, F=B→CHAT=public, WHEN→TIME, FROM=sid→username
            Session 14: Include SENDER in +msg broadcast (was excluded!)
                       Sender needs +msg to display their own message.
                       Remove mesg S=0 ack (client parsed it as empty chat → ":")
        """
        priv = kv.get("PRIV", "")
        text = kv.get("TEXT", "")
        attr = kv.get("ATTR", "0")

        LOG.info(
            "[%s] mesg: PRIV=%s TEXT=%s ATTR=%s",
            conn.conn_id, priv, text, attr,
        )

        # Do NOT send mesg S=0 ack — the client has no 'mesg' receive
        # handler.  The binary confirms: 'mesg' is send-only; only '+msg'
        # (0x2b6d7367) is dispatched in LobbyApiUpdate at 0x31c6f8.
        # Sending mesg S=0 caused the client to parse it as an empty chat
        # message, displaying a bare ":" separator.
        if not text:
            LOG.info("[%s] mesg: empty TEXT, skip delivery", conn.conn_id)
            return

        # Build delivery payload — server relay type is '+msg', not 'mesg'.
        # r2 confirmed: 'mesg' has no receive handler in LobbyApiUpdate.
        # Only '+msg' (0x2b6d7367) is dispatched there (at 0x31c6f8).
        relay_type = "+msg"

        # EA uses no-leading-zero month/day (e.g. "2003.7.2 14:30:00").
        t = time.localtime()
        now = f"{t.tm_year}.{t.tm_mon}.{t.tm_mday} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"

        if priv:
            # ── Private message: deliver to specific user ────────────
            payload = {
                "FROM": conn.username,
                "TEXT": text,
                "PRIV": priv,
                "TIME": now,
            }
            for cid, c in self._clients.items():
                if (c.authenticated
                        and c.username.lower() == priv.lower()
                        and hasattr(c, '_writer')):
                    try:
                        send_kv(c._writer, relay_type, payload)
                        await c._writer.drain()
                        LOG.info(
                            "[%s] mesg: delivered to %s (%s)",
                            conn.conn_id, priv, cid,
                        )
                    except Exception:
                        LOG.warning(
                            "[%s] mesg: failed to deliver to %s",
                            conn.conn_id, priv,
                        )
                    break
            else:
                LOG.info("[%s] mesg: target %s not online", conn.conn_id, priv)
        else:
            # ── Room chat (ATTR=0, no PRIV): broadcast to room ───────
            payload = {
                "FROM": conn.username,
                "TEXT": text,
                "CHAT": "public",
                "TIME": now,
            }
            room_idx = conn.current_room_idx
            if room_idx < 0:
                LOG.info("[%s] mesg: not in a room, skip broadcast", conn.conn_id)
                return
            delivered = 0
            for cid, c in self._clients.items():
                if (c.authenticated
                        and c.current_room_idx == room_idx
                        and hasattr(c, '_writer')):
                    try:
                        send_kv(c._writer, relay_type, payload)
                        await c._writer.drain()
                        delivered += 1
                    except Exception:
                        pass
            LOG.info(
                "[%s] mesg: broadcast to room %d (%d clients)",
                conn.conn_id, room_idx, delivered,
            )

    async def _handle_ping(
        self, conn: ClientConn, kv: Dict[str, str], writer: asyncio.StreamWriter
    ) -> None:
        """Handle ~png ping from the PS2 client.

        The client echoes ~png back as a keepalive ACK.  We do NOT respond —
        the _keepalive_loop sends pings proactively.  Responding here would
        cause an infinite ping-pong loop.
        """
        LOG.info("[%s] ~png: %s", conn.conn_id, dict(kv))
        conn.last_activity = time.time()

    # ── Keepalive ───────────────────────────────────────────────────────

    async def _keepalive_loop(
        self, conn: ClientConn, writer: asyncio.StreamWriter
    ) -> None:
        """Send periodic ~png keepalive to prevent client timeout/disconnect."""
        try:
            while True:
                await asyncio.sleep(20)  # every 20 seconds
                if conn.authenticated:
                    send_kv(writer, "~png", {
                        "TIME": "2",
                        "SESS": conn.session_id,
                        "NAME": conn.username,
                        "STATUS": "0",
                    })
                    try:
                        await writer.drain()
                    except Exception:
                        break
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    # ── Server push messages ────────────────────────────────────────────────

    async def _push_who(
        self, conn: ClientConn, writer: asyncio.StreamWriter
    ) -> None:
        """Push +who — user's own presence info."""
        send_kv(writer, "+who", {
            "F": "U",           # friend status flag
            "N": conn.username,
            "RI": str(conn.room_index),  # room index
            "RT": "4",          # room type?
            "R": "0",           # rank?
            "RF": "0",          # rank flag?
        })
        await writer.drain()

    async def _push_room_list(
        self, conn: ClientConn, writer: asyncio.StreamWriter,
        include_lobby: bool = True,
    ) -> None:
        """Push +rom — room listings.

        Each room uses I (Room ID) per decompilation.
        T = current player count (from room population), not room type.
        """
        pop_counts = self._room_population()
        rooms = self._rooms
        for i, room in enumerate(rooms):
            # Skip Lobby if not requested
            if room.room_type == 1 and not include_lobby:
                continue

            send_kv(writer, "+rom", {
                "I": str(room.index),
                "N": room.name,
                "H": room.heading,
                "A": ip_to_int(room.address),
                "T": str(pop_counts.get(room.index, 0)),
                "L": str(room.limit),
                "F": str(room.flags),
            })
            await writer.drain()
            await asyncio.sleep(0.02)

    async def _push_user_login(
        self, conn: ClientConn, writer: asyncio.StreamWriter
    ) -> None:
        """Push +usr in login/lobby context.

        Protocol tags (from commands.md + structure_definitions.md):
            I=user_id  N=name  A=int_ip  F=flags  S=status_text

        A must be an integer string (TagFieldGetAddress).  Used during
        initial login and after returning to the Lobby.
        """
        if not conn.username:
            return
        user_id = abs(hash(conn.username)) % 1000000
        send_kv(writer, "+usr", {
            "I": str(user_id),
            "N": conn.username,
            "F": "1",
            "A": ip_to_int(conn.client_ip or self.buddy_host),
            "S": "Online",
            "P": "",  # Bug #13: password field (client reads it)
        })
        await writer.drain()

    async def _push_user_in_room(
        self, conn: ClientConn, writer: asyncio.StreamWriter
    ) -> None:
        """Push +usr in room context.

        Protocol tags (from commands.md + structure_definitions.md):
            I=user_id  N=name  A=int_ip  F=flags  S=status  RI=room_id

        r2 verified: Room ID tag is R (0x3e30c8), NOT RI.
        RI is only used by +who.  A must be integer string.
        """
        if not conn.username:
            return
        user_id = abs(hash(conn.username)) % 1000000
        send_kv(writer, "+usr", {
            "I": str(user_id),
            "N": conn.username,
            "A": ip_to_int(conn.client_ip or self.buddy_host),
            "R": str(conn.room_index),  # Bug #12: client reads "R", not "RI"
            "S": "Online",
            "F": "0",
            "P": "",  # Bug #13: password field (client reads it)
        })
        await writer.drain()

    def _room_population(self) -> Dict[int, int]:
        """Count authenticated clients per room."""
        counts: Dict[int, int] = {r.index: 0 for r in self._rooms}
        for c in self._clients.values():
            if c.authenticated and c.current_room_idx in counts:
                counts[c.current_room_idx] += 1
        return counts

    async def _push_population(
        self, conn: ClientConn, writer: asyncio.StreamWriter
    ) -> None:
        """Push +pop — population counts per room."""
        # Format: Z=0:1 1:0 2:0 3:0  (room_idx:user_count)
        counts = self._room_population()
        parts = [f"{idx}:{counts.get(idx, 0)}" for idx in counts]
        send_kv(writer, "+pop", {"Z": " ".join(parts)})
        await writer.drain()

    async def _push_existing_room_users(
        self, joiner: ClientConn, room_idx: int, writer: asyncio.StreamWriter
    ) -> None:
        """Push +usr for every existing user in the room to the joiner."""
        for cid, c in self._clients.items():
            if (c.conn_id != joiner.conn_id
                    and c.authenticated
                    and c.current_room_idx == room_idx):
                user_id = abs(hash(c.username)) % 1000000
                send_kv(writer, "+usr", {
                    "I": str(user_id),
                    "N": c.username,
                    "A": ip_to_int(c.client_ip or self.buddy_host),
                    "R": str(room_idx),
                    "S": "Online",
                    "F": "0",
                    "P": "",
                })
                await writer.drain()
                await asyncio.sleep(0.02)

    async def _broadcast_room_join(
        self, joiner: ClientConn, room_idx: int
    ) -> None:
        """Notify other clients in the same room that a user joined.

        Sends +usr (room format), updated +rom (player count), and +pop
        to every authenticated client already in room_idx (excluding the
        joiner).
        """
        for cid, c in self._clients.items():
            if (c.conn_id != joiner.conn_id
                    and c.authenticated
                    and c.current_room_idx == room_idx
                    and hasattr(c, '_writer')):
                try:
                    user_id = abs(hash(joiner.username)) % 1000000
                    send_kv(c._writer, "+usr", {
                        "I": str(user_id),
                        "N": joiner.username,
                        "A": ip_to_int(joiner.client_ip or self.buddy_host),
                        "R": str(room_idx),
                        "S": "Online",
                        "F": "0",
                        "P": "",
                    })
                    await c._writer.drain()
                    # Re-push +rom so the room list T field (player count)
                    # updates in the client's Room Object.
                    await self._push_room_list(c, c._writer)
                    await self._push_population(c, c._writer)
                except Exception as e:
                    LOG.warning("[%s] broadcast to %s failed: %s",
                                joiner.conn_id, c.conn_id, e)

    async def _broadcast_room_leave(
        self, leaver: ClientConn, room_idx: int
    ) -> None:
        """Notify other clients in the same room that a user left.

        Sends +usr with I but NO N tag — the +usr handler deletes a user
        from the HashTable when N is absent (confirmed by r2 disassembly).
        Also sends updated +rom (player count) and +pop.
        """
        for cid, c in self._clients.items():
            if (c.conn_id != leaver.conn_id
                    and c.authenticated
                    and c.current_room_idx == room_idx
                    and hasattr(c, '_writer')):
                try:
                    user_id = abs(hash(leaver.username)) % 1000000
                    # Critical: do NOT include N tag — handler deletes user
                    # from HashTable when N is NULL (r2 verified).
                    send_kv(c._writer, "+usr", {
                        "I": str(user_id),
                        "A": ip_to_int(leaver.client_ip or self.buddy_host),
                        "S": "Online",
                        "P": "",
                    })
                    await c._writer.drain()
                    # Re-push +rom so the room list T field (player count)
                    # updates in the client's Room Object.
                    await self._push_room_list(c, c._writer)
                    await self._push_population(c, c._writer)
                except Exception as e:
                    LOG.warning("[%s] broadcast to %s failed: %s",
                                leaver.conn_id, c.conn_id, e)

    # ── Server runner ──────────────────────────────────────────────────────

    async def start(self) -> None:
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        LOG.info(
            "Login Server listening on %s:%d (buddy at %s:%d)",
            addr[0], addr[1], self.buddy_host, self.buddy_port,
        )

        async with server:
            await server.serve_forever()


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="NASCAR 2004 Login Server (TCP :10901)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_LOGIN_PORT)
    parser.add_argument("--buddy-host", default=DEFAULT_BUDDY_HOST)
    parser.add_argument("--buddy-port", type=int, default=DEFAULT_BUDDY_PORT)
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    setup_logging(level=logging.DEBUG if args.debug else logging.INFO)

    cfg = load_config(args.config) if args.config else {}

    # Resolve buddy host: config > CLI arg > auto-detect LAN IP
    buddy_host = cfg.get("buddy_host", args.buddy_host)
    if not buddy_host:
        buddy_host = get_lan_ip()
        LOG.info("Auto-detected LAN IP: %s", buddy_host)

    server = LoginServer(
        host=cfg.get("host", args.host),
        port=cfg.get("port", args.port),
        buddy_host=buddy_host,
        buddy_port=cfg.get("buddy_port", args.buddy_port),
        debug=args.debug,
    )

    asyncio.run(server.start())


if __name__ == "__main__":
    main()