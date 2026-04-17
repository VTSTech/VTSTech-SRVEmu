# NASCAR Thunder 2004 (PS2) — Online Server Emulator

## Quick Start

Start all three servers in order:

```bash
# 1) Dir Server — TCP :10600 (first thing the PS2 connects to)
python3 dir_server.py --config dir_config.json --debug

# 2) Login Server — TCP :10901 (authentication, rooms, matchmaking)
python3 login_server.py --config login_config.json --debug

# 3) Buddy Server — TCP :10899 (friends, presence, status)
python3 buddy_server.py --config buddy_config.json --debug
```

No `pip install` needed — Python 3.10+ stdlib only (asyncio, sqlite3).

## Architecture

All lobby/login/matchmaking traffic is **TCP** with a 12-byte framed text protocol.

```
PS2 Client
    │
    ▼ TCP :10600
┌─────────────┐     @dir redirect      ┌──────────────┐
│  Dir Server  │ ──────────────────►   │ Login Server  │ TCP :10901
│  dir_server  │                       │ login_server  │
└─────────────┘                       └──────┬───────┘
                                              │
                                     newsnew0 push:
                                     BUDDY_URL/BUDDY_PORT
                                              │
                                              ▼
                                     ┌──────────────┐
                                     │Buddy Server  │ TCP :10899
                                     │buddy_server  │
                                     └──────────────┘
```

## Wire Format (TCP)

Every message has a 12-byte header followed by a text body:

```
[4 bytes] type    — ASCII (e.g. b'@dir', b'auth', b'+rom')
[4 bytes] flags   — usually 0x00000000; e.g. b'new0' for news sub-type
[4 bytes] length  — TOTAL frame size INCLUDING header, big-endian uint32
[N bytes] body    — "KEY=value\\n" lines, null-terminated (\\0)
```

**Critical rules:**
- **Length field = total frame size** (header + body), NOT body length
- **A tag must be integer IP**, NOT dotted-quad (e.g. `A=3232236155`, not `A=192.168.2.123`)
- **Short tags** for lobby updates (`N`, `I`, `A`, `F`, `S`, `R`, `X`, `T`, `L`, `H`, `P`); **Long tags** for auth (`NAME`, `PASS`, `ADDR`, `PORT`, `SESS`, `MASK`)

## Protocol Flow

### Dir Server (TCP :10600)
| Direction | Type | Keys |
|-----------|------|------|
| C→S | `@dir` | PROD, VERS, LANG, SLUS |
| S→C | `@dir` | ADDR, PORT, LKEY, SESS, MASK |

### Login Server (TCP :10901)
| Direction | Type | Keys |
|-----------|------|------|
| C→S | `addr` | ADDR, PORT |
| S→C | `addr` | STATUS=1 |
| C→S | `skey` | SKEY=$hex |
| S→C | `skey` | SKEY=0 |
| C→S | `auth` | NAME, TOS, PASS, MID, HWFLAG, HWMASK, PROD, VERS, LANG, SLUS, MASK |
| S→C | `auth` | TOS, NAME, USER, PERSONAS, PRIV, LAST, SESS, S, STATUS |
| S→C | `+who` | F, N, RI, RT, R, RF |
| C→S | `sele` | ROOMS, USERS, RANKS, MESGS |
| S→C | `sele` | DRANK, USER, RATING, WINS, LOSS, STATUS |
| C→S | `news` | NAME=0 |
| S→C | `newsnew0` | BUDDY_URL, BUDDY_PORT, BUDDY_SERVER, TOS_TEXT, NEWS_TEXT, USE_ETOKEN |
| S→C | `+rom` | I, N, H, A (int IP), T (player count), L, F |
| S→C | `+usr` | I, N, A (int IP), R (room ID), S, F, P |
| S→C | `+pop` | Z=0:count 1:count 2:count 3:count |
| C→S | `move` | NAME, PASS |
| S→C | `move` | I, N, F |
| S→C | `~png` | TIME, SESS, NAME, STATUS (every 20s keepalive) |

### Buddy Server (TCP :10899)
| Direction | Type | Keys |
|-----------|------|------|
| C→S | `AUTH` | PROD, VERS, PRES, USER, LKEY |
| S→C | `AUTH` | NAME, S, STATUS |
| C→S | `PSET` | SHOW, STAT, PROD |
| S→C | `PSET` | NAME, ID, S, STATUS |
| C→S | `RGET` | LRSC, LIST, PRES, ID |
| S→C | `RGET` | NAME, ID, S, STATUS, COUNT |
| C→S | `SEND` | TYPE, USER, BODY, SESS |
| S→C | `SEND` | S=0 (ack) |
| S→C | `~png` | TIME, NAME, STATUS (every 20s keepalive) |

## Files

| File | Purpose |
|------|---------|
| `ea_protocol.py` | Shared TCP wire format (12-byte header + text KV) |
| `dir_server.py` | Dir Server — TCP :10600, redirects to Login Server |
| `login_server.py` | Login Server — TCP :10901, auth + rooms + matchmaking |
| `buddy_server.py` | Buddy Server — TCP :10899, friends + presence + status |
| `dir_config.json` | Dir Server configuration |
| `login_config.json` | Login Server configuration |
| `buddy_config.json` | Buddy Server configuration |

## PS2 Network Setup

Point your PS2's DNS/server settings to the IP running `dir_server.py` on port 10600. The Dir Server will redirect the client to the Login Server, which will hand off to the Buddy Server — all automatically.

## Current Status

- ✅ Full login flow working on real PS2 hardware (two clients tested)
- ✅ Room browsing, joining, leaving — all working
- ✅ Multi-client room visibility (both clients see each other)
- ✅ Room population counts accurate (+pop)
- ✅ Join/leave/disconnect broadcast between clients
- ✅ Buddy auth, presence, roster queries working
- ✅ Buddy instant messaging (SEND TYPE=C) with relay
- ✅ Server-side keepalive (~png, 20s interval, no disconnects)
- ⏳ P2P racing protocol (UDP 1073) — not yet implemented
- ⏳ Game invitations — ack only, relay not yet implemented

## Notes

- The UDP binary 8-byte tag protocol (`nascar_protocol.py`) applies only to P2P racing traffic, not lobby/login.
- All authentication is open (any password accepted) for emulation purposes.
- Sessions auto-create accounts on first login.
- The `~png` keepalive is server-initiated only — the PS2 client does NOT send pings proactively. The server sends every 20s and the client may or may not respond depending on which server connection (login: responds, buddy: silent).
- The `TREF` field is NOT part of the EA protocol — it was removed after r2 analysis confirmed it does not exist in the binary.
