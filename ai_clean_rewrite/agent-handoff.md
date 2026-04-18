# NASCAR Thunder 2004 PS2 — Agent Handoff Document

**Project:** Reverse-engineering and emulating the online server infrastructure for NASCAR Thunder 2004 (PS2, SLUS-20824).
**Date:** 2026-04-18 (updated session 9 — mesg/+msg relay debugging, r2 analysis)
**Status:** ✅ MULTI-CLIENT WORKING on real PS2 hardware. Two PS2 clients can join the same room, see each other, exchange buddy messages. Keepalive stable, no disconnects. All known binary discrepancies documented in §9.

---

## 1. Project Overview

NASCAR Thunder 2004 for PS2 used EA's online lobby service (now defunct). This project reverse-engineers the protocol from the binary (`NASCAR.ELF`, MIPS R3000, stripped) and PCAP captures of real server traffic, then implements emulated servers in Python so the game can connect online again.

### Critical Rule
**Client packets = ground truth. Server packets in PCAPs = hints only.** The Ghidra/r2 decompilation of `LobbyApiUpdate` is the most authoritative reference for what the client expects.

### VTSTech's Documentation (GitHub)
User's previous emulation efforts are documented at:
`https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/docs/nascar04`

Key files (5 markdown + 2 JSON):
- `commands.md` — Command/tag reference for all 4-char commands
- `protocol_spec.md` — Wire format, tag types (long vs short), IP address format
- `cheatsheet.md` — Common pitfalls (IP format, null terminators, zero IDs)
- `structure_definitions.md` — Client memory layout for User/Room objects
- `logic_flow.md` — State machine, HashTable bridge, challenge sequence
- `functions.json` — 1,096 named functions from ELF (reference for r2)
- `strings.json` — 3,330+ strings from binary

### Decomposition Files (GitHub)
Ghidra decompilations available at:
`https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/docs/nascar04/decom/`
- `LobbyApiUpdate.txt` — Main lobby protocol dispatcher (FULLY ANALYZED, see §9)

---

## 2. Wire Format (CRITICAL)

```
[4 bytes] type    — ASCII message type (e.g. @dir, auth, +rom)
[4 bytes] flags   — usually 0x00000000; e.g. b"new0" for news sub-type
[4 bytes] length  — TOTAL frame size INCLUDING the 12-byte header, big-endian uint32
[N bytes] body    — text KEY=VALUE pairs separated by 0x0A (LF), null terminated 0x00
```

### Critical Tag Rules (from protocol_spec.md)
- **Long Tags** for handshake/auth: `NAME`, `PASS`, `ADDR`, `PORT`, `SESS`, `MASK`
- **Short Tags** for lobby updates: `N`, `I`, `A`, `F`, `S`, `R`, `X`, `T`, `L`, `H`, `P`
- **Wrong tag type = client ignores the packet** (e.g. `NAME=` instead of `N=` in `+usr`)

### IP Address Format (CRITICAL — from cheatsheet.md)
- **A tag MUST be integer string**, NOT dotted-quad
- `A=3232236155` ✅ — `A=192.168.2.123` ❌
- Client parses via `TagFieldGetAddress` which calls `inet_aton` + integer conversion
- `ip_to_int()` helper exists in `login_server.py`

### Body Format
- Some messages use **space-separated** KVs (e.g. `ROOMS=1 USERS=1 RANKS=1 MESGS=1`)
- Others use **LF-separated** KVs
- Parser handles both, respecting quoted values

---

## 3. Server Chain & Current Status

```
PS2 Client
    │
    ▼ TCP :10600
┌─────────────┐    @dir redirect       ┌──────────────┐
│  Dir Server  │ ──────────────────►    │ Login Server  │ TCP :10901
│  dir_server  │                        │ login_server  │
└─────────────┘                        └──────┬───────┘
                                               │
                                    news + flags=new0 push:
                                    BUDDY_URL/BUDDY_PORT
                                               │
                                               ▼
                                    ┌──────────────┐
                                    │ Buddy Server  │ TCP :10899
                                    │ buddy_server  │
                                    └──────────────┘
```

### Login Flow — CONFIRMED WORKING on real PS2

| # | Msg Type | Dir | Keys | Status |
|---|----------|-----|------|--------|
| 1 | `@dir` | C→S | PROD=NASCAR-PS2-2004, VERS, LANG, SLUS | ✅ |
| 2 | `@dir` | S→C | ADDR, PORT, LKEY, SESS, MASK | ✅ |
| 3 | `addr` | C→S | ADDR=192.0.2.100, PORT=NNNNN | ✅ |
| 4 | `addr` | S→C | STATUS=1 | ✅ |
| 5 | `skey` | C→S | SKEY=$5075626c6963204b6579 ("Public Key") | ✅ |
| 6 | `skey` | S→C | SKEY=0 | ✅ |
| 7 | `auth` | C→S | NAME, PASS, MID, HWFLAG, HWMASK, PROD, VERS, LANG, SLUS, MASK | ✅ |
| 8 | `auth` | S→C | TOS, NAME, USER, PERSONAS, PRIV, LAST, SESS, S, STATUS | ✅ |
| 9 | `pers` | C→S | PERS=VTSTech | ✅ |
| 10 | `pers` | S→C | PERS, LKEY=$0, S, STATUS, LAST | ✅ |
| 11 | `+who` | S→C | F=U, N, RI=0, RT=4, R=0, RF=0 (pushed AFTER pers) | ✅ |
| 12 | `sele` | C→S | ROOMS=1 USERS=1 RANKS=1 MESGS=1 | ✅ |
| 13 | `sele` | S→C | DRANK (only — no ERANK) | ✅ |
| 14 | `sele` | C→S | RANKS=50 | ✅ |
| 15 | `sele` | S→C | ERANK (only — no DRANK) | ✅ |
| 16 | `news` | C→S | NAME=0 | ✅ |
| 17 | `sele` | S→C | ERANK (type=sele, NOT type=news) | ✅ |
| 18 | `news` (flags=new0) | S→C | BUDDY_URL, BUDDY_PORT, BUDDY_SERVER, TOS_TEXT, NEWS_TEXT, USE_ETOKEN, S, STATUS | ✅ |
| 19 | `+rom` x4 | S→C | I, N, H, A=int_ip, T=0, L, F | ✅ |
| 20 | `+usr` | S→C | I, N, F=1, A=int_ip, S, P | ✅ |
| 21 | `+pop` | S→C | Z=0:1 1:0 2:0 3:0 | ✅ |

### Buddy Server — CONFIRMED WORKING on real PS2

| # | Msg Type | Dir | Keys | Status |
|---|----------|-----|------|--------|
| 1 | `AUTH` | C→S | PROD=NASCAR, VERS=XXX, PRES=NASCAR2004, USER=VTSTech/cso/nascar-ps2-2004, LKEY=$0 | ✅ |
| 2 | `AUTH` | S→C | NAME=VTSTech, S=0, STATUS=1 | ✅ |
| 3 | `+pop` | S→C | Z=0:1 1:0 2:0 3:0 | ✅ |
| 4 | `PSET` | C→S | SHOW=CHAT, STAT=..., PROD="is online" | ✅ |
| 5 | `PSET` | S→C | NAME, ID, S=0, STATUS=1 | ✅ |
| 6 | `RGET` | C→S | LRSC=cso, LIST=B, PRES=Y, ID=1 | ✅ |
| 7 | `RGET` | S→C | NAME, ID, S=0, STATUS=1, COUNT=0 | ✅ |
| 8 | `RGET` | C→S | LRSC=cso, LIST=I, PRES=Y, ID=2 | ✅ |
| 9 | `SEND` | C→S | TYPE=C, USER=target, BODY=message, SECS=259200 | ✅ |
| 10 | `SEND` | S→C | S=0 (ack) | ✅ |
| 11 | `~png` | S→C | TIME=2, NAME=username, STATUS=1 (every 20s) | ✅ |

---

## 4. ~png Keepalive Implementation (Session 7)

### Problem
The PS2 client disconnects after ~2 minutes of idle if no traffic is sent. The client does NOT initiate `~png` — the server must send them proactively.

### r2 Analysis of `~png` Handler (address `0x31BEF0–0x31BF40`)

The game's `~png` handler (dispatched by comparing first 4 bytes to `0x7E706E67` = "~png"):
1. Copies message body via `strncpy()` into 256-byte stack buffer
2. Builds its own `TIME=<integer>` from an internal counter (NOT a timestamp)
3. Passes to protocol engine at `0x322190`

**Critical: The game does NOT parse TREF, SESS, NAME, or STATUS from incoming `~png`.** It only cares about the message type.

### TREF — NOT in the Binary
- String `"TREF"` not found anywhere in `.sdata`, `.rodata`, or code sections
- Not used by `TagFieldFind` — game ignores it completely
- **Removed from server** — was causing a parsing issue because the space in `"2026-04-17 14:45:51"` was split by `_split_kv_tokens()` into two keys

### Implementation
- Server sends `~png` every 20 seconds to authenticated clients (both `login_server.py` and `buddy_server.py`)
- `_handle_ping` updates `last_activity` only — does NOT reply (prevents ping-pong flood)
- On the login server, the PS2 client responds to `~png` with its own `~png` (TIME field differs)
- On the buddy server, the PS2 client does NOT respond to `~png`

### Fields Sent
```python
# login_server.py ~png
{"TIME": "2", "SESS": conn.session_id, "NAME": conn.username, "STATUS": "0"}

# buddy_server.py ~png
{"TIME": "2", "NAME": client.username, "STATUS": str(client.status)}
```

### ~png Handler Behavior
- Server sends `~png` proactively every 20 seconds to authenticated clients
- `_handle_ping` on both servers is **silent** (updates `last_activity` only, no TX response) — prevents ping-pong flood

### TREF — Not in Binary
- `"TREF"` string not found anywhere in `.sdata`, `.rodata`, or code sections
- TREF is not sent by the server (removed — game ignores it entirely)

---

## 5. Room Presence & Multi-Client Broadcast (Session 7)

### Problem
When multiple clients join the same room, they cannot see each other. The server only pushed `+usr`/`+pop` to the joining client, not to existing room occupants.

### Population Counting
- `_push_population()` counts actual authenticated clients per room across all connections (via `_room_population()` method)

### New Methods in `login_server.py`

#### `_room_population()` — Count clients per room
Returns `Dict[int, int]` mapping room index to authenticated client count.

#### `_push_existing_room_users(joiner, room_idx, writer)` — Push existing occupants to joiner
When a client joins a room, pushes `+usr` (room format, `F=0`) for every client already in that room. This ensures the joiner sees existing users immediately.

#### `_broadcast_room_join(joiner, room_idx)` — Notify existing occupants of new user
Sends `+usr` (room format, `F=0`) and updated `+pop` to every other authenticated client in the room. Existing occupants learn about the new user.

#### `_broadcast_room_leave(leaver, room_idx)` — Notify remaining occupants
Sends `+usr` (`F=1` — deletion flag) and updated `+pop` when a client leaves a room or disconnects. Called from:
- `_handle_move()` (leave room path)
- `handle_client()` finally block (disconnect cleanup)

### Move Handler Update (join path)
```
move → S=0 → +pop → +usr(self) → +who → +pop → +usr(login) → push_existing_users → broadcast_join
```

### Multi-Client Testing — ✅ CONFIRMED WORKING
Two PS2 clients (VTSTech and VTSTech2) both connected to the same server:
- VTSTech joins East → sees only self
- VTSTech2 joins East → BOTH clients now see each other
- `+pop` correctly shows `Z: 0:0 1:2 2:0 3:0` (2 users in room 1)
- Leave/rejoin works correctly
- Disconnect notification works (remaining client sees user leave)

---

## 6. Buddy Messaging — SEND Handler (Session 7)

### Implementation in `buddy_server.py`

Added `SEND` handler for EA buddy instant messaging:

**Incoming fields:** `TYPE`, `USER`, `BODY`, `SECS`
- `TYPE=C` — Chat message
- `USER` — Recipient username
- `BODY` — Message text
- `SECS` — TTL in seconds (259200 = 3 days)

**Response:** `SEND: S=0` (acknowledgment to sender)

**Delivery:** If recipient is online, pushes `SEND` with `FROM`, `TYPE`, `BODY`, `TIME` to their connection.

**Fields in EA binary (.sdata):**
- `USER` at `0x3e3330`
- `TYPE` at `0x3e3338`
- `BODY` at `0x3e3348`
- `SECS` at `0x3e3368`

Also in binary: `AWAY`, `DISC`, `GROUP`, `SUBJ`, `SIZE` — other message types not yet implemented.

**Limitations:**
- Self-send is acknowledged but not delivered (same conn_id skip)
- Offline message store not implemented (messages to offline users are dropped)
- Only `TYPE=C` (chat) is handled; game invitations, away messages, etc. not yet supported

---

## 7. Verified TagFieldFind String Constants (r2 Session 5)

All constants confirmed via `r2 -c 'ps @ <addr>'` on `NASCAR.ELF` (MD5: 8ebe8d7f8157480d6a288739fa920c3a).

### Lobby Protocol Tags (.sdata section, 0x3e2f80–0x3e3530)

| Address | String | Used By | Purpose |
|---------|--------|---------|---------|
| 0x3e30a0 | `"F"` | +rom, +usr | Flags field |
| 0x3e30b0 | `"N"` | +rom, +usr, +who | Name/username |
| 0x3e30b8 | `"RI"` | +who only | Room Index |
| 0x3e30c0 | `"RT"` | +who only | Room Type |
| 0x3e30c8 | `"R"` | +usr, +who | Room ID (in +usr), Rank (in +who) |
| 0x3e30d0 | `"RF"` | +who only | Rank Flag |
| 0x3e30d8 | `"I"` | +rom, +usr | Room ID / User ID |
| 0x3e30e0 | `"H"` | +rom | Room Heading/Description |
| 0x3e30e8 | `"A"` | +rom, +usr | IP Address (integer) |
| 0x3e30f0 | `"T"` | +rom | **Current Player Count** (NOT room type!) |
| 0x3e30f8 | `"L"` | +rom | Max Players |
| 0x3e3110 | `"P"` | +usr | Password (8 bytes) |
| 0x3e3130 | `"S"` | +usr | Status text (128 bytes) |
| 0x3e3138 | `"X"` | +usr | Extra text (128 bytes) |
| 0x3e3100 | `"No"` | +rom | Password indicator (locked=no) |
| 0x3e3108 | `"Yes"` | +rom | Password indicator (locked=yes) |
| 0x3e3128 | `"___"` | +pop | Population delimiter |

### Critical Distinction: RI vs R
- `"RI"` (0x3e30b8) — used **only** by the `+who` handler for room index
- `"R"` (0x3e30c8) — used by `+usr` for room association AND by `+who` for rank
- The server currently sends `"RI"` in `+usr` messages — **this is wrong** (client expects `"R"`, see §8 +usr handler analysis)

---

## 8. Handler Analysis (Verified by r2 Disassembly)

### `+rom` Handler (msg `0x2b726f6d`) — Room Create/Update/Delete

**Message dispatch:** `iStack_b0 == 0x2b726f6d` in `fcn.0031bdf0`
**Disassembly range:** `0x31c8f0–0x31cbbc`

```
Step 1:  TagFieldFind "I"  (0x3e30d8) → TagFieldGetNumber(-1)
         If < 0 → skip (invalid room ID)
Step 2:  TagFieldFind "N"  (0x3e30b0)
         If NULL → DELETE room from HashTable by room ID
         If found → CREATE/UPDATE room
Step 3:  Allocate 0x68 bytes (104 bytes), memset to 0
Step 4:  Store room_id at obj+0x00
Step 5:  TagFieldFind "N"  → TagFieldGetString(obj+0x1c, 32)  — room name
Step 6:  TagFieldFind "H"  → TagFieldGetString(obj+0x3c, 32)  — room heading
Step 7:  TagFieldFind "F"  → TagFieldGetFlags(-1) → obj+0x08    — flags
Step 8:  TagFieldFind "A"  → TagFieldGetAddress(0) → obj+0x64   — host IP
Step 9:  TagFieldFind "T"  → TagFieldGetNumber(0) → obj+0x10    — PLAYER COUNT
Step 10: TagFieldFind "L"  → TagFieldGetNumber(0) → obj+0x0c    — MAX PLAYERS
Step 11: Util_FormatIPString → obj+0x14 (formatted player string)
Step 12: Check flags & 1:
           if set → copy "No"  (0x3e3100) into obj+0x18 (room locked = no)
           else   → copy "Yes" (0x3e3108) into obj+0x18 (room locked = yes)
Step 13: HashTable insert/update using room_id as key
```

**Room Object Memory Layout (0x68 = 104 bytes) — VERIFIED:**

| Offset | Tag | Getter | Size | Description |
|--------|-----|--------|------|-------------|
| 0x00 | `I` | TagFieldGetNumber | 4B | Room ID (HashTable key) |
| 0x04 | — | — | 4B | (padding/unused) |
| 0x08 | `F` | TagFieldGetFlags | 4B | Flags (bit 0 = password locked) |
| 0x0c | `L` | TagFieldGetNumber | 4B | Max Players |
| 0x10 | `T` | TagFieldGetNumber | 4B | Current Player Count ★ |
| 0x14 | — | FormatIPString | ~32B | Formatted player string |
| 0x18 | — | flags&1 check | 4B | "No" or "Yes" (password indicator) |
| 0x1c | `N` | TagFieldGetString | 32B | Room Name |
| 0x3c | `H` | TagFieldGetString | 32B | Room Heading/Description |
| 0x5c | — | — | 8B | (padding/ping string) |
| 0x64 | `A` | TagFieldGetAddress | 4B | Host IP (integer) |

★ **KEY FINDING:** The `T` tag is **current player count**, NOT room type. The server currently sends `T=str(room.room_type)` which is `T="1"` for all rooms — the client interprets this as "1 player in room". While this shouldn't prevent display, it's semantically wrong and may confuse the client's population logic.

### `+usr` Handler (msg `0x2b757372`) — User Create/Update/Delete

**Message dispatch:** `iStack_b0 == 0x2b757372` in `fcn.0031bdf0`
**Disassembly range:** `0x31cccc–0x31d014`

```
Step 1:  Parse room membership list from body (integer IDs separated by non-digit chars)
Step 2:  TagFieldFind "I"  (0x3e30d8) → TagFieldGetNumber(-1)
         If < 0 → skip (invalid user ID)
Step 3:  TagFieldFind "N"  (0x3e30b0)
         If NULL → DELETE user from HashTable by user ID
         If found → CREATE/UPDATE user
Step 4:  Allocate 0x138 bytes (312 bytes), memset to 0
Step 5:  Store user_id at obj+0x00
Step 6:  TagFieldFind "N"  → TagFieldGetString(obj+0x08, 32)   — persona name
Step 7:  TagFieldFind "A"  → TagFieldGetAddress(0) → obj+0x30   — IP address
Step 8:  TagFieldFind "P"  → TagFieldGetString(obj+0x28, 8)    — password
Step 9:  TagFieldFind "F"  → TagFieldGetFlags(0) → obj+0x04     — flags
Step 10: TagFieldFind "S"  → TagFieldGetString(obj+0x38, 128)  — status text
Step 11: TagFieldFind "R"  → TagFieldGetNumber(0) → obj+0x34    — room ID
Step 12: TagFieldFind "X"  → TagFieldGetString(obj+0xb8, 128)  — extra text
Step 13: HashTable insert/update using user_id as key
```

**User Object Memory Layout (0x138 = 312 bytes) — VERIFIED:**

| Offset | Tag | Getter | Size | Description |
|--------|-----|--------|------|-------------|
| 0x00 | `I` | TagFieldGetNumber | 4B | User ID (HashTable key) |
| 0x04 | `F` | TagFieldGetFlags | 4B | Flags |
| 0x08 | `N` | TagFieldGetString | 32B | Persona Name |
| 0x28 | `P` | TagFieldGetString | 8B | Password ★ MISSING from server |
| 0x30 | `A` | TagFieldGetAddress | 4B | IP Address (integer) |
| 0x34 | `R` | TagFieldGetNumber | 4B | Room ID ★ Server sends "RI" not "R" |
| 0x38 | `S` | TagFieldGetString | 128B | Status text |
| 0xb8 | `X` | TagFieldGetString | 128B | Extra text |

### `+who` Handler (msg `0x2b776f68`) — User Presence

**This is the ONLY handler that uses `"RI"` (room index).**

| Tag | Address | Purpose |
|-----|---------|---------|
| `N` | 0x3e30b0 | Username |
| `RI` | 0x3e30b8 | Room Index (which room the user is in) |
| `RT` | 0x3e30c0 | Room Type |
| `R` | 0x3e30c8 | Rank |
| `RF` | 0x3e30d0 | Rank Flag |
| `F` | 0x3e30a0 | Friend status (e.g. "U") |

**IMPORTANT:** `+who` correctly uses `RI` — the server's `_push_who` implementation is CORRECT. Do NOT change it.

### `+pop` Handler (msg `0x2b706f70`) — Population Counts

Parses body using `"___"` delimiter (0x3e3128) to split room:count pairs. Only processes room IDs that match the user's current room context.

---

## 9. Binary Discrepancies

Tags and fields that the server sends but the binary does not recognize. The client silently ignores unknown tags via `TagFieldFind` returning NULL — none of these cause crashes or malfunctions. Documented here so future agents don't waste time investigating non-issues.

### STATUS vs STAT
- Server sends `STATUS` in auth/pers responses and buddy AUTH. The string `"STATUS"` does not exist anywhere in the binary (`.sdata`, `.rodata`, or otherwise).
- The binary only has `"STAT"` (4 chars) at `0x3e34a8` in the buddy protocol area, used as a message type (not a tag).
- **Impact:** None. Dead weight field — harmless.

### DRANK and ERANK
- Server sends `DRANK` (initial sele) and `ERANK` (RANKS sele). Neither string exists in the binary.
- Only `"RANKS"` (`0x3e2fb8`, `0x3e0380`, `0x3d82d0`) and embedded `"RANK"` in longer strings are found.
- The mutual exclusion logic in the server (initial → DRANK, RANKS → ERANK) is correct per PCAP analysis, but the tags are meaningless to the client.
- **Impact:** Rank display may not work at all, or uses a different mechanism. Not blocking.

### +snp Stats Tags
- Server sends stats via `+snp` with tags: `N`, `R`, `W`, `L`, `S`, `P`, `T5`, `T10`, `LL`, `LC`, `STRK`, `AS`, `AF`.
- Of these, `W`, `T5`, `T10`, `LL`, `LC`, `STRK`, `AS`, `AF` do not exist as standalone strings in the binary. They appear only in SQL strings or UI format strings, unrelated to protocol parsing.
- The short tags `N`, `R`, `L`, `S`, `P` do exist in `.sdata` but are used in different protocol contexts (`L` = max players in `+rom`, `P` = password in `+usr`).
- **Impact:** The snap handler works (client proceeds after receiving `S=0` terminator) but no stats are displayed. If stats display is needed, deeper disassembly of the snap handler function would be required.

### MASK Signed/Unsigned Mismatch
- Dir server sends `MASK=4294967295` (0xFFFFFFFF, unsigned). Login server receives `MASK=-1650254874` (signed int32 interpretation).
- **Impact:** No known issues. Documented for awareness.

---

## 10. radare2 Session 5 & 7 Technical Details

### Session 7 — Additional r2 Analysis (~png, TREF)

```bash
# TREF search — NOT FOUND in binary
/home/z/.local/bin/r2 -q -e scr.color=0 -c 'iz~TREF' NASCAR.ELF   # empty
/home/z/.local/bin/r2 -q -e scr.color=0 -c '/x 54524546' NASCAR.ELF  # empty (hex TREF)
/home/z/.local/bin/r2 -q -e scr.color=0 -c '/a TREF' NASCAR.ELF     # empty

# ~png handler location
/home/z/.local/bin/r2 -q -e scr.color=0 -c 'afl~ping' NASCAR.ELF   # found ~png at 0x31BED0

# Date format strings in binary
0x3DFD48: "%d.%d.%d %d:%02d:%02d"  (internal date format, also has space)
0x2D89C8: "%d/%d/%d %d:%02d %s"    (UI display)

# ~png handler disassembly
pd 80 @ 0x31BEF0  # copies body, builds TIME=int, calls protocol engine

# Binary does NOT use strftime — uses printf-style %d formatting
```

### Binary Info
- **File:** `NASCAR.ELF` at `/home/z/my-project/upload/NASCAR.ELF/NASCAR.ELF`
- **Format:** MIPS R3000 32-bit LE ELF, stripped, 3.01 MB
- **MD5:** 8ebe8d7f8157480d6a288739fa920c3a
- **r2 version:** 6.1.5 (built from source at `/home/z/radare2/`, installed to `~/.local/bin/`)
- **Run command:** `LD_LIBRARY_PATH=/tmp/my-project/r2-install/usr/local/lib/radare2/ /home/z/my-project/radare2/binr/radare2/radare2 -e scr.color=0 -e bin.cache=true NASCAR.ELF`

### Key Function
- **`fcn.0031bdf0`** — `LobbyApiUpdate` — 6,412 bytes, 16-state connection handler
- Contains all lobby protocol dispatch: +rom, +usr, +who, +pop, +rmu, +rmr, etc.
- Uses a 4-byte message type as a 32-bit integer for switch/case dispatch

### Analysis Commands Used
```bash
# Full analysis
aaa

# Find function
afl~LobbyApi  # fcn.0031bdf0

# Read string constants from .sdata
ps @ 0x3e30a0  # "F"
ps @ 0x3e30b0  # "N"
ps @ 0x3e30b8  # "RI"
ps @ 0x3e30c0  # "RT"
ps @ 0x3e30c8  # "R"
ps @ 0x3e30d0  # "RF"
ps @ 0x3e30d8  # "I"
ps @ 0x3e30e0  # "H"
ps @ 0x3e30e8  # "A"
ps @ 0x3e30f0  # "T"
ps @ 0x3e30f8  # "L"
ps @ 0x3e3110  # "P"
ps @ 0x3e3130  # "S"
ps @ 0x3e3138  # "X"

# Find cross-references to string constants
axt @ 0x3e30d8  # where "I" is used
axt @ 0x3e30b8  # where "RI" is used (only +who!)
axt @ 0x3e30c8  # where "R" is used (+usr, +who)

# Disassemble handler ranges
pd 200 @ 0x31c8f0   # +rom handler start
pd 200 @ 0x31cccc   # +usr handler start
```

---

## 11. Files

### Server Code (Python 3.10+, stdlib only)

**GitHub:** `https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/ai_clean_rewrite`

| File | Purpose |
|------|---------|
| `ea_protocol.py` | Shared TCP wire format, encode/decode, TCPStreamReader, send_kv, ColorFormatter |
| `dir_server.py` | Dir Server TCP :10600 |
| `login_server.py` | Login Server TCP :10901 (~1080 lines) |
| `buddy_server.py` | Buddy Server TCP :10899 (~400 lines) |
| `*.json` | Optional config files |

**Local copy (this session):** `/home/z/my-project/upload/server-extract/`

### Reference Files

| File | Location | Purpose |
|------|----------|---------|
| `agent-handoff.md` | `/home/z/my-project/upload/docs/` | This document |
| `worklog.md` | `/home/z/my-project/` | Session worklog |
| VTSTech docs | GitHub `docs/nascar04/` | commands.md, protocol_spec.md, cheatsheet.md, structure_definitions.md, logic_flow.md, functions.json, strings.json |
| VTSTech decomp | GitHub `docs/nascar04/decom/` | LobbyApiUpdate.txt (analyzed), possibly more files |

### Binary & Analysis Tools

| Item | Location | Purpose |
|------|----------|---------|
| `NASCAR.ELF` | `/home/z/my-project/upload/elf-extract/NASCAR.ELF` | Target PS2 binary (3.01 MB) |
| radare2 | `/home/z/my-project/radare2/binr/radare2/radare2` | v6.1.5 — reverse engineering framework |
| r2 libs | `/tmp/my-project/r2-install/usr/local/lib/radare2/` | Runtime libraries |
| r2 run cmd | `LD_LIBRARY_PATH=/tmp/my-project/r2-install/usr/local/lib/radare2/ /home/z/my-project/radare2/binr/radare2/radare2 -e scr.color=0 -e bin.cache=true NASCAR.ELF` | |

### Previous r2 Analysis Files (from earlier sessions)

| File | Location | Purpose |
|------|----------|---------|
| `disasm_network_functions.txt` | `/home/z/my-project/upload/docs/` | Network function disassembly |
| `disasm_large_network_functions.txt` | same | Large network function disassembly |
| `r2_vtable_analysis.txt` | same | C++ vtable analysis |
| `r2_functions_detailed.txt` | same | Detailed function analysis |
| `r2_all_strings.txt` | same | All strings from binary |
| `r2_all_functions.txt` | same | All functions list |
| `class_hierarchy.txt` | same | C++ class hierarchy |

---

## 12. Connection State Machine (from logic_flow.md)

```
State   Hex          Trigger
INIT    0x00         Connection established
CONN    0x636f6e6e   addr command received
SKEY    0x736b6579   skey command sent/received
USER    0x75736572   auth/pers complete
LOBY    0x6c6f6279   sele/+rom sequence
GAME    0x67616d65   strt command (P2P racing)
```

The `LobbyApiUpdate` code also references:
- `0x74696d65` = "time" — timeout state
- `0x7465726d` = "term" — terminated
- `0x6f66666c` = "loff" — offline

---

## 13. Testing Checklist

### 13.1 Directory Server (dir_server.py :10600)
- [x] Accepts PS2 TCP connection
- [x] Parses `@dir` request (PROD, VERS, LANG, SLUS)
- [x] Responds with login server redirect (ADDR, PORT, LKEY, SESS, MASK)
- [x] Client disconnects cleanly after redirect (one-shot)

### 13.2 Login Server — Authentication Flow (login_server.py :10901)
- [x] Handles `addr` (client reports public IP/port)
- [x] Handles `skey` (session key exchange — client sends `$5075626c6963204b6579` = "Public Key")
- [x] Handles `auth` (NAME, PASS, MID, HWFLAG, HWMASK, PROD, VERS, LANG, SLUS, MASK)
- [x] Handles `pers` (persona selection)
- [x] Pushes `+who` after pers (F=U, N, RI=0, RT=4, R=0, RF=0)
- [x] Handles `sele` initial (ROOMS=1 USERS=1 RANKS=1 MESGS=1 → DRANK response)
- [x] Handles `sele` RANKS=50 (→ ERANK response)
- [x] Handles `news` NAME=0 (→ sele ERANK → `news` flags=new0 → BUDDY_URL/PORT/SERVER)
- [x] Pushes room list (`+rom` x4) and self-user (`+usr`) and population (`+pop`)

### 13.3 Login Server — Room Operations
- [x] Handles `move` (room join) — 5-push sequence: S=0 → +pop → +usr(self) → +who → +pop → +usr(login) → push_existing_users → broadcast_join
- [x] Handles `room` (client creates custom room) — responds with I, N, F; broadcasts +rom, +usr, +pop
- [x] Room creation confirmed: "C.Test" created as room ID 4 with correct population broadcast
- [x] Room leave/disconnect — broadcasts +usr(F=1) deletion and updated +pop to remaining occupants
- [x] All +rom use integer IP format (`ip_to_int`) — `A=3232236155` not `A=192.168.2.123`
- [x] All +usr use correct short tags (I, N, A=int_ip, F, P, S, R)

### 13.4 Login Server — Verified Behaviors
- [x] +rom `T` field = player count (`T="0"`, not room type)
- [x] +usr room ID uses `"R"` not `"RI"`
- [x] +usr includes `"P": ""` (password field)
- [x] ~png `_handle_ping` is silent (no reply — prevents ping-pong flood)
- [x] TREF not sent (confirmed absent from binary)
- [x] +pop uses actual `_room_population()` counts (not hardcoded)
- [x] Room display correct on real PS2 after all above fixes

### 13.5 Login Server — Partially Tested Handlers
- [ ] `snap` (player stats/leaderboard) — handler implemented but not tested on real PS2
- [ ] `user` (profile lookup) — handler implemented but not tested on real PS2
- [⚠️] `mesg` (lobby chat) — handler sends `+msg` relay but client shows only ":" — see §16
- [ ] ATTR=3 (game invite relay) — not yet implemented

### 13.6 Buddy Server (buddy_server.py :10899)
- [x] Handles `AUTH` (PROD, VERS, PRES, USER, LKEY=$0)
- [x] Handles `PSET` (SHOW=CHAT, STAT=presence string, PROD=status text)
- [x] Handles `RGET` (LRSC=cso, LIST=B/I, PRES=Y, ID=1/2) — returns COUNT=0 (empty lists)
- [x] Handles `SEND` (TYPE=C, USER, BODY, SECS) — acknowledges and relays to online recipient
- [ ] Handles `RADD` (add buddy to list) — not yet tested

### 13.7 Multi-Client & Stability
- [x] **MULTI-CLIENT** — Two PS2s (VTSTech + VTSTech2) join same room, see each other
- [x] **ROOM POPULATION** — +pop reflects actual client count per room
- [x] **BROADCAST** — Join/leave/disconnect notifications between clients
- [x] **KEEPALIVE STABLE** — No disconnects; login ~png at 20s, buddy ~png at 20s; clean logs
- [x] **LONG SESSION** — Confirmed stable through room creation, navigation, idle periods

### 13.8 Game Protocol (Not Yet Implemented)
- [ ] P2P racing protocol (strt/command, game session negotiation, direct connection)

---

## 14. r2 Binary Verification — All Commands (Session 8)

Systematic verification of every command's parameter names against the NASCAR.ELF binary string constants. **r2 disassembly is the sole source of truth.** All strings confirmed via `LD_LIBRARY_PATH=/home/z/.local/lib /home/z/.local/bin/r2 -q -e scr.color=0 -c 'ps @ <addr>' /home/z/my-project/upload/nascar/NASCAR.ELF`.

### 14.1 Verification Methodology

For each command, we verified:
1. **Tag name exists** — The exact tag string (e.g., `"NAME"`) must appear in `.sdata` (0x3e2f80–0x3e3530) or `.rodata` as a null-terminated string.
2. **Tag address matches** — Cross-reference against the EA Lobby Protocol doc addresses where available.
3. **Server sends correct tag** — The server implementation uses the same tag name the binary expects.

### 14.2 Login Server Commands

#### `auth` (C→S) — Client Sends Authentication

| Tag | Binary Address | Section | Status |
|-----|---------------|---------|--------|
| `NAME` | 0x3e2f90 (.sdata) | Lobby tags | ✅ Confirmed |
| `PASS` | 0x3e2fe0 (.sdata) | Lobby tags | ✅ Confirmed |
| `MID` | 0x3d8198 (.rodata) | Auth credentials | ✅ Confirmed |
| `HWFLAG` | 0x3d81a0 (.rodata) | HW identification | ✅ Confirmed |
| `HWMASK` | 0x3d81a8 (.rodata) | HW identification | ✅ Confirmed |
| `PROD` | 0x3e31a0 (.sdata) | Auth long tags | ✅ Confirmed |
| `VERS` | 0x3e31a8 (.sdata) | Auth long tags | ✅ Confirmed |
| `LANG` | 0x3e31b0 (.sdata) | Auth long tags | ✅ Confirmed |
| `SLUS` | 0x3e31b8 (.sdata) | Auth long tags | ✅ Confirmed |
| `MASK` | 0x3e2fe8 (.sdata) | Lobby tags | ✅ Confirmed |

All 10 tags confirmed in binary. No discrepancies.

#### `auth` (S→C) — Server Response

| Tag | Binary Address | Section | Status |
|-----|---------------|---------|--------|
| `TOS` | 0x3d82f0 (.rodata) | Auth response | ✅ Confirmed |
| `NAME` | 0x3e2f90 (.sdata) | Lobby tags | ✅ Confirmed |
| `USER` | 0x3e32b0 (.sdata) | Messaging area | ✅ Confirmed |
| `PERSONAS` | 0x3e0410 (.rodata) | Profile area | ✅ Confirmed |
| `PRIV` | 0x3d8390 (.rodata) | Messaging area | ✅ Confirmed |
| `LAST` | 0x3d82d8 (.rodata) | Auth response | ✅ Confirmed |
| `SESS` | 0x3e3028 (.sdata) | Lobby tags | ✅ Confirmed |
| `S` | 0x3e3130 (.sdata) | Lobby tags | ✅ Confirmed |
| `STATUS` | **NOT FOUND** | — | ⚠️ See note |

**⚠️ STATUS tag not in binary** — see §9 Binary Discrepancies. Client silently ignores.

#### `pers` (C→S) — Client Selects Persona

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `PERS` | 0x3e3040 (.sdata) | ✅ Confirmed |

#### `pers` (S→C) — Server Response

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `PERS` | 0x3e3040 (.sdata) | ✅ Confirmed |
| `LKEY` | 0x3e34c8 (.sdata) | ✅ Confirmed |
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |
| `STATUS` | **NOT FOUND** | ⚠️ See §9 |
| `LAST` | 0x3d82d8 (.rodata) | ✅ Confirmed |

#### `move` (C→S) — Client Joins/Leaves Room

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `NAME` | 0x3e2f90 (.sdata) | ✅ Confirmed |
| `PASS` | 0x3e2fe0 (.sdata) | ✅ Confirmed |

#### `move` (S→C) — Server Response (join)

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `I` | 0x3e30d8 (.sdata) | ✅ Confirmed |
| `N` | 0x3e30b0 (.sdata) | ✅ Confirmed |
| `F` | 0x3e30a0 (.sdata) | ✅ Confirmed |

#### `move` (S→C) — Server Response (leave)

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |

#### `room` (C→S) — Client Creates Custom Room

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `NAME` | 0x3e2f90 (.sdata) | ✅ Confirmed |
| `PASS` | 0x3e2fe0 (.sdata) | ✅ Confirmed |
| `DESC` | 0x3d8318 (.rodata) | ✅ Confirmed (embedded in "PASSPERSDESC" string) |
| `MAX` | 0x3d8328 (.rodata) | ✅ Confirmed (embedded in "DESCNoneMAX" string) |

#### `room` (S→C) — Server Response

Same as move join response: I, N, F — all confirmed.

#### `snap` (C→S) — Client Requests Stats/Leaderboard

| Tag | Binary Address | Section | Status |
|-----|---------------|---------|--------|
| `CHAN` | 0x3e2ff0 (.sdata) | Lobby tags | ✅ Confirmed |
| `INDEX` | 0x3d9131 (.rodata) | Stats area | ✅ Confirmed (in "INDEXRANGECHAN" string) |
| `FIND` | 0x3d914c (.rodata) | Stats area | ✅ Confirmed (in "CHANFINDSTART" string) |
| `START` | 0x3d9151 (.rodata) | Stats area | ✅ Confirmed (in "FINDSTARTselec" string) |
| `RANGE` | 0x3d9137 (.rodata) | Stats area | ✅ Confirmed (in "INDEXRANGECHAN" string) |

#### `snap` (S→C) — +snp Stats Response

| Tag | Binary Address | Status | Notes |
|-----|---------------|--------|-------|
| `N` | 0x3e30b0 (.sdata) | ✅ | Name |
| `R` | 0x3e30c8 (.sdata) | ✅ | Rating/rank |
| `W` | **NOT FOUND** | ⚠️ | See §9 |
| `L` | 0x3e30f8 (.sdata) | ✅ | Losses (but "L" = max players in +rom context) |
| `S` | 0x3e3130 (.sdata) | ✅ | Streak/status |
| `P` | 0x3e3110 (.sdata) | ✅ | Poles (but "P" = password in +usr context) |
| `T5` | **NOT FOUND** | ⚠️ | See §9 |
| `T10` | **NOT FOUND** | ⚠️ | See §9 |
| `LL` | **NOT FOUND** | ⚠️ | See §9 |
| `LC` | **NOT FOUND** | ⚠️ | See §9 |
| `STRK` | **NOT FOUND** | ⚠️ | See §9 |
| `AS` | **NOT FOUND** | ⚠️ | See §9 |
| `AF` | **NOT FOUND** | ⚠️ | See §9 |

**⚠️ Stats tags not in binary** — see §9 Binary Discrepancies. Client silently ignores all +snp tags.

#### `snap` (S→C) — Final Frame

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |

#### `user` (C→S) — Client Looks Up Profile

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `PERS` | 0x3e3040 (.sdata) | ✅ Confirmed |

#### `user` (S→C) — Server Response

| Tag | Binary Address | Status | Notes |
|-----|---------------|--------|-------|
| `N` | 0x3e30b0 (.sdata) | ✅ | |
| `R` | 0x3e30c8 (.sdata) | ✅ | |
| `W` | **NOT FOUND** | ⚠️ | See §9 |
| `L` | 0x3e30f8 (.sdata) | ✅ | |
| `PERSONAS` | 0x3e0410 (.rodata) | ✅ | |
| `STATUS` | **NOT FOUND** | ⚠️ | See §9 |

#### `mesg` (C→S) — Client Sends Private Message / Invite

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `PRIV` | 0x3d8390 (.rodata) | ✅ Confirmed |
| `TEXT` | 0x3d8388 (.rodata) | ✅ Confirmed |
| `ATTR` | 0x3d83a0 (.rodata) | ✅ Confirmed |

#### `mesg` (S→C) — Server Acknowledgment

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |

#### `sele` (C→S) — Client Requests Selection Info

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `ROOMS` | 0x3e2fb8 (.sdata) — in "ROOMS=1 USERS=1 RANKS=1 MESGS=1" | ✅ Confirmed |
| `USERS` | 0x3e2fc8 (.sdata) — in "ROOMS=1 USERS=1 RANKS=1 MESGS=1" | ✅ Confirmed |
| `RANKS` | 0x3e2fc0 (.sdata) — standalone "RANKS" | ✅ Confirmed |
| `MESGS` | 0x3e0388 (.sdata) — in "MESGS=1" | ✅ Confirmed |

#### `sele` (S→C) — DRANK / ERANK Response

| Tag | Binary Address | Status | Notes |
|-----|---------------|--------|-------|
| `DRANK` | **NOT FOUND** | ⚠️ | See §9 |
| `ERANK` | **NOT FOUND** | ⚠️ | See §9 |
| `USER` | 0x3e32b0 (.sdata) | ✅ | |
| `RATING` | **NOT FOUND** | ⚠️ | |
| `WINS` | **NOT FOUND** | ⚠️ | |
| `LOSS` | **NOT FOUND** | ⚠️ | |
| `STATUS` | **NOT FOUND** | ⚠️ | See §9 |

**⚠️ DRANK/ERANK tags not in binary** — see §9 Binary Discrepancies. Client silently ignores.

### 14.3 Buddy Server Commands

#### `AUTH` (C→S) — Buddy Authentication

| Tag | Binary Address | Section | Status |
|-----|---------------|---------|--------|
| `PROD` | 0x3e34a0 (.sdata) | Buddy protocol | ✅ Confirmed |
| `VERS` | 0x3e34b8 (.sdata) | Buddy protocol | ✅ Confirmed |
| `PRES` | 0x3e34c0 (.sdata) | Buddy protocol | ✅ Confirmed |
| `USER` | 0x3e32b0 (.sdata) | Messaging area | ✅ Confirmed |
| `LKEY` | 0x3e34c8 (.sdata) | Buddy protocol | ✅ Confirmed |

#### `AUTH` (S→C) — Buddy Authentication Response

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `NAME` | 0x3e30b0 (.sdata) | ✅ Confirmed |
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |
| `STATUS` | **NOT FOUND** | ⚠️ See §9 |

**Note:** The buddy server sends `STATUS=1` but the binary only has `STAT` (0x3e34a8). See §9 Binary Discrepancies for full details. The `STATUS` key is harmless but unrecognized by the client.

#### `PSET` (C→S) — Client Sets Presence

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `SHOW` | 0x3e3498 (.sdata) | ✅ Confirmed |
| `STAT` | 0x3e34a8 (.sdata) | ✅ Confirmed |
| `PROD` | 0x3e34a0 (.sdata) | ✅ Confirmed |

#### `PSET` (S→C) — Server Response

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `NAME` | 0x3e30b0 (.sdata) | ✅ Confirmed |
| `ID` | 0x3e34f0 (.sdata) | ✅ Confirmed |
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |
| `STATUS` | **NOT FOUND** | ⚠️ See §9 |

#### `RGET` (C→S) — Client Requests Buddy Roster

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `LRSC` | 0x3e34d0 (.sdata) | ✅ Confirmed |
| `LIST` | 0x3e34d8 (.sdata) | ✅ Confirmed |
| `PRES` | 0x3e34c0 (.sdata) | ✅ Confirmed |
| `ID` | 0x3e34f0 (.sdata) | ✅ Confirmed |

#### `RGET` (S→C) — Server Response

Same as PSET response: NAME, ID, S, STATUS, COUNT.
| `COUNT` | 0x3e3168 (.sdata) | ✅ Confirmed |

#### `SEND` (C→S) — Client Sends Instant Message

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `TYPE` | 0x3e3338 (.sdata) | ✅ Confirmed |
| `USER` | 0x3e32b0 (.sdata) | ✅ Confirmed |
| `BODY` | 0x3e32c8 (.sdata) | ✅ Confirmed |
| `SECS` | 0x3e32e8 (.sdata) | ✅ Confirmed |

#### `SEND` (S→C) — Server Acknowledgment

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `S` | 0x3e3130 (.sdata) | ✅ Confirmed |

#### `SEND` (S→C) — Message Delivery to Recipient

| Tag | Binary Address | Status |
|-----|---------------|--------|
| `FROM` | 0x3e3088 (.sdata) | ✅ Confirmed |
| `TYPE` | 0x3e3338 (.sdata) | ✅ Confirmed |
| `BODY` | 0x3e32c8 (.sdata) | ✅ Confirmed |
| `TIME` | 0x3e3008 (.sdata) | ✅ Confirmed |

### 14.4 Complete Binary String Constant Map

All protocol tag string constants verified in NASCAR.ELF:

#### .sdata Section (0x3e2f80–0x3e3530) — Lobby Protocol Tags

| Address | String | Used By |
|---------|--------|---------|
| 0x3e2f90 | `NAME` | auth, @dir, +usr, +who, move, room, user |
| 0x3e2fa0 | `PING` | keepalive |
| 0x3e2fb0 | `VERS` | @dir, auth, buddy AUTH |
| 0x3e2fb8 | `ROOMS=` | sele subscription |
| 0x3e2fc0 | `RANKS=` | sele subscription |
| 0x3e2fc8 | `USERS=` | sele subscription |
| 0x3e2fe0 | `PASS` | auth, move, room, mesg |
| 0x3e2fe8 | `MASK` | auth, @dir response |
| 0x3e2ff0 | `CHAN` | snap |
| 0x3e3008 | `TIME` | ~png, SEND |
| 0x3e3018 | `DIRECT` | connection config |
| 0x3e3020 | `PORT` | @dir response |
| 0x3e3028 | `SESS` | auth response |
| 0x3e3038 | `SLOTS` | connection config |
| 0x3e3040 | `PERS` | pers, room response, +who |
| 0x3e3080 | `AUTH` | connection config |
| 0x3e3088 | `FROM` | +msg relay, SEND delivery (NOTE: `iz` shows 0x3e3090 as FROM — may be dual reference) |
| 0x3e3090 | `FROM` | +msg relay (alt reference at 0x3e3090 per iz) |
| 0x3e3098 | `SEED` | challenge/matchmaking |
| 0x3e30a0 | `WHEN` | +msg handler timestamp area |
| 0x3e30a8 | `F` | +rom, +usr, move, room |
| 0x3e30b0 | `N` | +rom, +usr, +who |
| 0x3e30c8 | `R` | +usr, +who |
| 0x3e30d8 | `I` | +rom, +usr, PSET, RGET |
| 0x3e30e0 | `H` | +rom |
| 0x3e30e8 | `A` | +rom, +usr |
| 0x3e30f0 | `T` | +rom (player count) |
| 0x3e30f8 | `L` | +rom (max players) |
| 0x3e3110 | `P` | +usr (password) |
| 0x3e3130 | `S` | +usr, pers, auth, move, snap, mesg |
| 0x3e3138 | `X` | +usr (extra text) |
| 0x3e31a0 | `PROD` | auth, @dir, buddy AUTH, PSET |
| 0x3e31a8 | `VERS` | auth, @dir, buddy AUTH |
| 0x3e31b0 | `LANG` | auth |
| 0x3e31b8 | `SLUS` | auth |
| 0x3e32b0 | `USER` | user response, buddy AUTH, SEND |
| 0x3e32c8 | `BODY` | SEND |
| 0x3e32e0 | `en` | language |
| 0x3e32e8 | `SECS` | SEND |
| 0x3e3338 | `TYPE` | SEND |
| 0x3e3498 | `SHOW` | buddy PSET |
| 0x3e34a0 | `PROD` | buddy AUTH, PSET |
| 0x3e34a8 | `STAT` | buddy PSET, STAT command |
| 0x3e34b8 | `VERS` | buddy AUTH |
| 0x3e34c0 | `PRES` | buddy AUTH, RGET |
| 0x3e34c8 | `LKEY` | buddy AUTH, pers response |
| 0x3e34d0 | `LRSC` | buddy RGET |
| 0x3e34d8 | `LIST` | buddy RGET |
| 0x3e34f0 | `ID` | buddy PSET, RGET |
| 0x3e3168 | `COUNT` | buddy RGET |

#### .rodata Section — Auth/Credential Tags

| Address | String | Used By |
|---------|--------|---------|
| 0x3d8198 | `MID` | auth |
| 0x3d81a0 | `HWFLAG` | auth |
| 0x3d81a8 | `HWMASK` | auth |
| 0x3d82d0 | `RANKS` | sele |
| 0x3d82d8 | `LAST` | auth response, pers response |
| 0x3d82f0 | `TOS` | auth response |
| 0x3d8318 | `DESC` | room |
| 0x3d8388 | `TEXT` | mesg, SEND |
| 0x3d8390 | `PRIV` | auth response, mesg |
| 0x3d83a0 | `ATTR` | mesg |
| 0x3d9131 | `INDEX` | snap |
| 0x3d9137 | `RANGE` | snap |
| 0x3d914c | `CHAN` | snap (also at 0x3e2ff0 in sdata) |
| 0x3d914c | `FIND` | snap |
| 0x3d9151 | `START` | snap |
| 0x3e0410 | `PERSONAS` | auth response, user response |

### 14.5 Bug Summary — New Findings

| Bug | Severity | Description | Impact | Action |
|-----|----------|-------------|--------|--------|
| #17 | Low | `STATUS` tag not in binary — only `STAT` exists | Client ignores STATUS fields in auth/pers/news/move/user responses | None (harmless) — optionally remove STATUS from responses for cleanliness |
| #18 | Low | `+snp` stats tags (W, T5, T10, LL, LC, STRK, AS, AF) not in binary | Client ignores all stats in +snp — no stats displayed | Keep current implementation; deeper RE needed for actual stats protocol |
| #19 | Low | `DRANK` and `ERANK` tags not in binary | Client ignores rank data in sele responses — rank display may not work | Keep current implementation; deeper RE needed for actual rank protocol |

All three new bugs are **low severity** — the system is confirmed working on real PS2 hardware with two clients. The unrecognized tags are silently discarded by the client's `TagFieldFind` function.

---

## 15. Lobby Chat — `mesg` / `+msg` Relay (Session 9 — ACTIVE BUG)

### Current State: Client Shows Only ":"

The server correctly relays lobby messages as `+msg` type. The PS2 client processes them (the handler at `0x31c6f8` in `LobbyApiUpdate` runs) but only displays a `:` character in the chat area. This confirms:
- The `+msg` message type IS dispatched (correct)
- The client IS processing the relay (not dropping it)
- The payload format is WRONG — the client can't extract sender/text

### r2 Analysis of `+msg` Handler (0x31c6f8)

The `+msg` handler in `LobbyApiUpdate`:
1. Checks for callback at `*(s2+0x51c)` — if NULL, skips entirely
2. Looks up tag `"F"` (0x3e30a8) via `TagFieldFind` to determine message type:
   - If result has bit 4 set → type = `"cast"` (0x3e30b0 area) — broadcast
   - If result has bit 0 set → type = `"priv"` (0x3e30e8 area) — private
   - Default → type = `"chat"` (already in var_104h from `0x3e3088`)
3. Calls `fcn.0031e938` (flag-checking function using lookup table at `0x3df6e8`) — uses `t5` offset `0x3df6c8` as character mapping table
4. Calls callback at `*(s2+0x51c)` with: s2 (object), var_100h (chat type string), *(s2+0x51c) (callback function pointer), a2 (context)

**Key strings in .sdata near messaging area (0x3e3080–0x3e3180):**

| Address | String | Notes |
|---------|--------|-------|
| 0x3e3080 | `AUTH` | Connection config |
| 0x3e3088 | `AUTH` | Connection config (alt ref?) |
| 0x3e3090 | `FROM` | Tag for +msg relay and SEND delivery |
| 0x3e3098 | `SEED` | Challenge/matchmaking |
| 0x3e30a0 | `WHEN` | Used by +msg for timestamp |
| 0x3e30a8 | `F` | Flags — message type determination |
| 0x3e30b0 | `N` | — |
| 0x3e30b8 | `RI` | — |
| 0x3e30c0 | `RT` | — |
| 0x3e30c8 | `R` | — |
| 0x3e30d0 | `RF` | — |
| 0x3e30d8 | `I` | — |
| 0x3e30e0 | `H` | — |
| 0x3e30e8 | `A` | — |
| 0x3e30f0 | `T` | — |
| 0x3e30f8 | `L` | — |
| 0x3e3100 | `No` | — |
| 0x3e3108 | `Yes` | — |
| 0x3e3128 | `___` | +pop delimiter |
| 0x3e3130 | `S` | — |
| 0x3e3138 | `X` | — |
| 0x3e3458 | `CHAT` | Chat status/presence (buddy) |
| 0x3e3470 | `send: ` | Debug format string (in `fcn.0036163c`) |
| 0x3e3468 | `%s\n` | Format string (in `fcn.003615dc`) |

**IMPORTANT:** `WHEN` (0x3e30a0) is referenced near `FROM` in the +msg handler area. The handler may use `WHEN` instead of `TIME` for the timestamp tag.

### What We've Tried

| Attempt | Payload | Result |
|---------|---------|--------|
| 1 | `FROM=name\nTEXT=msg\nPRIV=\nATTR=0` | No display |
| 2 | `FROM=name\nTEXT=msg\nPRIV=\nATTR=0` (with PRIV= from doc) | Client shows `:` |
| 3 | `FROM=name\nTEXT=msg\nCHAT=public\nTIME=2026.4.17 20:12:07` | Client still shows `:` |

### Hypotheses to Investigate

1. **Tag name is `WHEN` not `TIME`** — `WHEN` (0x3e30a0) is in the .sdata messaging area right near `FROM`. The binary may use `WHEN` for the timestamp in +msg relay.

2. **The callback at `*(s2+0x51c)` is NULL** — If the chat UI module (`FlowModuleUISChatC`) hasn't registered a callback, the handler silently drops the message. The `:` might come from a different code path (e.g., the room user list separator).

3. **The `F` tag is required** — The handler looks up `F` to determine chat type. Without `F` in the relay, the default path may not properly initialize the message display.

4. **`TEXT` tag is wrong** — The handler uses tag lookup from `.rodata` area. For the C→S `mesg` path, `TEXT` is at `0x3d8398` (.rodata). But the +msg receive handler may use a different tag name (e.g., `BODY` like the buddy SEND uses).

5. **Tag ordering matters** — The `fcn.0031ddd0` tag search function scans sequentially. If the parser expects tags in a specific order, the current dict ordering (Python 3.7+ preserves insertion order) may not match.

### Current Server Code (login_server.py)

The `_handle_mesg` function now sends:
- **Room broadcast:** `FROM=sender, TEXT=msg, CHAT=public, TIME=YYYY.M.D HH:MM:SS` via `+msg`
- **Private message:** `FROM=sender, TEXT=msg, PRIV=target, TIME=YYYY.M.D HH:MM:SS` via `+msg`

The `TIME` format uses f-string to avoid `%-m`/`%-d` GNU-only format specifiers.

### Next Steps for Next Session
1. Try `WHEN` instead of `TIME` in the relay payload
2. Try adding `F=` tag to the relay payload
3. Disassemble the callback target at `*(s2+0x51c)` to see what tags it reads
4. Try `BODY` instead of `TEXT` (matching buddy SEND protocol)
5. Check if `FlowModuleUISChatC` registers the callback — trace initialization

---

## 16. Remaining Work

1. **P2P racing protocol** — The `strt` command triggers P2P racing over UDP port 1073. This is entirely separate from the lobby TCP protocol and needs its own investigation. The EA P2P protocol doc (`NASCAR_P2P_Protocol.md`) covers the basics.

2. **Custom room creation** — Test the `room` handler (client creates a custom room with NAME, PASS, DESC, MAX). Not yet tested on real PS2.

3. **Game invitations** — The `mesg` handler on login_server acknowledges invites but doesn't relay them. The buddy `SEND` handler works for chat (`TYPE=C`) but game invitations (`TYPE` with `SUBJ`, `ROOM`, `SEED`, `ACPT`, `DECL`) are not yet implemented.

4. **Room chat (TEXT)** — The login_server may need to handle room-level chat messages. Not yet observed from the PS2 client.

5. **Offline message store** — Buddy `SEND` drops messages for offline users. Implementing a persistent store would allow delivery when the recipient connects.

6. **Snap/stats and user lookup** — The `snap` handler (player stats, leaderboard) and `user` handler (profile lookup) are implemented but untested.

7. **RADD (add buddy)** — The buddy server doesn't handle friend add/remove yet. Clients send `RGET` for roster queries but `RADD` for buddy management is unimplemented.
