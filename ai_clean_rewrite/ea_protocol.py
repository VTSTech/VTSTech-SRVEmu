#!/usr/bin/env python3
"""
EA Lobby Protocol — shared wire format for NASCAR Thunder 2004 PS2 online.

Wire format (TCP):
    [4 bytes] type    — ASCII message type (e.g. b'@dir', b'auth', b'+rom')
    [4 bytes] flags   — usually zero; some server pushes use a sub-type ID here
    [4 bytes] length  — TOTAL frame size in big-endian (uint32), INCLUDING the 12-byte header
    [N bytes] body    — text key=value pairs separated by 0x0A (LF), null terminated 0x00

    Example: if body is 75 bytes, length field = 12 + 75 = 87 (0x57).

The body is line-oriented: each line is "KEY=value\\n".  The last byte before
the null terminator is always 0x0A (LF).

Message naming convention observed in captures:
    @xxx   — server-initiated command (e.g. @dir)
    +xxx   — async server push / notification (e.g. +who, +rom, +usr, +pop)
    XXXX   — client request (e.g. AUTH, PSET, RGET, STAT)
    xxxx   — server response to client request (e.g. auth, addr, skey, pers, sele, news)
    move   — client action (join room)
"""

from __future__ import annotations

import asyncio
import struct
import logging
from typing import Dict, Optional, Tuple

LOG = logging.getLogger("ea_protocol")

# ── Constants ────────────────────────────────────────────────────────────────

HEADER_SIZE: int = 12
TYPE_FIELD_SIZE: int = 4
ZERO_FIELD_SIZE: int = 4
LEN_FIELD_SIZE: int = 4

# Default ports from PCAP captures
DEFAULT_DIR_PORT: int = 10600
DEFAULT_LOGIN_PORT: int = 10901
DEFAULT_BUDDY_PORT: int = 10899


# ── Frame helpers ────────────────────────────────────────────────────────────

def encode_frame(msg_type: str, body: str = "", flags: bytes = b"\x00\x00\x00\x00") -> bytes:
    """
    Build a complete TCP frame: 12-byte header + body bytes + null terminator.

    Args:
        msg_type: 4-char ASCII message type (e.g. '@dir', 'auth', '+rom')
        body: Text body with key=value lines separated by LF.
        flags: 4-byte flags field (usually zero; e.g. b'new0' for news sub-types).

    Returns:
        Complete frame ready to send over TCP.
    """
    type_bytes = msg_type.encode("ascii")[:TYPE_FIELD_SIZE].ljust(TYPE_FIELD_SIZE, b"\x00")
    flags_bytes = flags[:ZERO_FIELD_SIZE].ljust(ZERO_FIELD_SIZE, b"\x00")

    # Body: add LF if not present, then null terminate
    if body and not body.endswith("\n"):
        body += "\n"
    body_bytes = body.encode("ascii", errors="replace")
    # Null terminate
    body_bytes += b"\x00"

    # CRITICAL: length field = TOTAL frame size (header + body), not body alone.
    # Verified against PCAP captures from the real EA servers.
    total_length = HEADER_SIZE + len(body_bytes)
    len_bytes = struct.pack(">I", total_length)

    return type_bytes + flags_bytes + len_bytes + body_bytes


def decode_header(data: bytes) -> Optional[Tuple[str, int, int]]:
    """
    Parse the 12-byte header from raw TCP stream data.

    Returns:
        Tuple of (msg_type_str, body_length, total_frame_size) or None if incomplete.

    Note:
        The length field in the wire format is the TOTAL frame size (header + body),
        NOT the body length alone.  body_length = total_frame_size - HEADER_SIZE.
    """
    if len(data) < HEADER_SIZE:
        return None

    type_raw = data[:TYPE_FIELD_SIZE]
    msg_type = type_raw.rstrip(b"\x00").decode("ascii", errors="replace")

    # The second 4-byte field is usually zero but some server push messages
    # (e.g. news with buddy config) use it as a sub-type identifier.
    # flags_field = data[TYPE_FIELD_SIZE:TYPE_FIELD_SIZE + ZERO_FIELD_SIZE]

    # CRITICAL: length field = TOTAL frame size, not body length.
    # Verified against every frame in PCAP captures from real EA servers.
    total_frame_size = struct.unpack(">I", data[TYPE_FIELD_SIZE + ZERO_FIELD_SIZE:HEADER_SIZE])[0]

    if total_frame_size < HEADER_SIZE:
        LOG.debug("decode_header: invalid frame size %d (smaller than header)", total_frame_size)
        return None

    body_length = total_frame_size - HEADER_SIZE
    return (msg_type, body_length, total_frame_size)


def parse_kv_body(body_bytes: bytes) -> Dict[str, str]:
    """
    Parse the text key=value body into a dictionary.

    Handles null-terminated bodies by stripping the trailing 0x00.
    Lines are separated by LF (0x0A) OR by spaces (0x20).

    The EA protocol uses LF-separated KVs for most messages, but
    some messages (e.g. sele with \"ROOMS=1 USERS=1 RANKS=1 MESGS=1\")
    use space-separated KVs with no LF at all.
    """
    # Strip null terminator
    text = body_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
    # Strip trailing LF / whitespace
    text = text.rstrip("\n ")

    result: Dict[str, str] = {}

    # Split on LF first (newline-separated KVs)
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Within each line, also split on spaces for space-separated KVs
        # e.g. "ROOMS=1 USERS=1 RANKS=1 MESGS=1"
        # but NOT inside quoted values like VERS="PS2/XXX-Jul  2 2003"
        tokens = _split_kv_tokens(line)
        for token in tokens:
            if "=" in token:
                key, _, value = token.partition("=")
                result[key.strip()] = value.strip()
            elif token:
                result[token.strip()] = ""

    return result


def _split_kv_tokens(line: str) -> list:
    """
    Split a line into KEY=VALUE tokens, respecting quoted values.

    E.g. 'ROOMS=1 USERS=1 RANKS=1 MESGS=1' -> ['ROOMS=1', 'USERS=1', ...]
    E.g. 'VERS="PS2/XXX-Jul  2 2003"'       -> ['VERS="PS2/XXX-Jul  2 2003"']
    """
    tokens = []
    current = []
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == ' ' and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def build_kv_body(pairs: Dict[str, str]) -> str:
    """Build a text body from a dictionary of key=value pairs."""
    lines = []
    for key, value in pairs.items():
        lines.append(f"{key}={value}")
    return "\n".join(lines)


# ── TCP Stream Reader ───────────────────────────────────────────────────────

class TCPStreamReader:
    """
    Reads framed messages from an asyncio TCP stream.

    Uses ``readexactly()`` instead of ``read()`` for Windows IocpProactor
    compatibility — ``read(N)`` can silently buffer and block until EOF on
    some platforms.

    Usage::

        reader = TCPStreamReader(stream)
        while frame := await reader.read_frame():
            msg_type, kv, raw = frame
    """

    def __init__(self, stream: asyncio.StreamReader):
        self.stream = stream
        self._buffer = bytearray()

    async def read_frame(self) -> Optional[Tuple[str, Dict[str, str], bytes]]:
        """
        Read one complete frame from the stream.

        Returns:
            Tuple of (msg_type, kv_dict, raw_body_bytes) or None on EOF.
        """
        # --- fast path: buffer already has a complete frame ---
        while len(self._buffer) >= HEADER_SIZE:
            parsed = decode_header(bytes(self._buffer))
            if not parsed:
                break
            msg_type, body_length, total_size = parsed
            if len(self._buffer) < total_size:
                break  # need more body bytes
            body = bytes(self._buffer[HEADER_SIZE:total_size])
            del self._buffer[:total_size]
            return (msg_type, parse_kv_body(body), body)

        # --- slow path: read from the OS socket ---
        # Use readexactly() — it returns as soon as N bytes arrive,
        # which avoids the Windows IocpProactor buffering issue
        # where read(4096) may block until EOF.
        try:
            header_data = await self.stream.readexactly(HEADER_SIZE)
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            LOG.debug("read_frame: header EOF: %s", exc)
            return None

        parsed = decode_header(header_data)
        if not parsed:
            LOG.debug("read_frame: failed to decode header")
            return None

        msg_type, body_length, total_size = parsed

        if body_length > 0:
            try:
                body_data = await self.stream.readexactly(body_length)
            except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
                LOG.debug("read_frame: body EOF (wanted %d): %s", body_length, exc)
                return None
        else:
            body_data = b""

        # Check if any leftover buffered bytes start a new frame
        # (shouldn't happen with readexactly, but be safe)
        kv = parse_kv_body(body_data)
        return (msg_type, kv, body_data)

    def feed_data(self, data: bytes) -> list:
        """Feed raw data and return any complete frames. (For non-async use.)"""
        self._buffer.extend(data)
        frames = []
        while True:
            if len(self._buffer) < HEADER_SIZE:
                break
            parsed = decode_header(bytes(self._buffer))
            if parsed is None:
                break
            msg_type, body_length, total_size = parsed
            if len(self._buffer) < total_size:
                break
            body = bytes(self._buffer[HEADER_SIZE:total_size])
            del self._buffer[:total_size]
            kv = parse_kv_body(body)
            frames.append((msg_type, kv, body))
        return frames


async def send_frame(writer: asyncio.StreamWriter, msg_type: str, body: str = "", flags: bytes = b"\x00\x00\x00\x00") -> None:
    """Encode and send one framed message over TCP."""
    frame = encode_frame(msg_type, body, flags=flags)
    writer.write(frame)
    await writer.drain()


async def send_kv(writer: asyncio.StreamWriter, msg_type: str, pairs: Dict[str, str], flags: bytes = b"\x00\x00\x00\x00") -> None:
    """Convenience: send a frame built from a KV dict."""
    body = build_kv_body(pairs)
    LOG.info("TX %s (flags=%s): %s", msg_type, flags, pairs)
    await send_frame(writer, msg_type, body, flags=flags)