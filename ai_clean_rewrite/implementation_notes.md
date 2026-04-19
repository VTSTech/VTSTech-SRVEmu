# Implementation Notes

Extracted from agent-handoff.md. Historical implementation details for completed features.

---

## 1. ~png Keepalive Implementation (Session 7)

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

---

## 2. Room Presence & Multi-Client Broadcast (Session 7)

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

### Multi-Client Testing — CONFIRMED WORKING
Two PS2 clients (VTSTech and VTSTech2) both connected to the same server:
- VTSTech joins East → sees only self
- VTSTech2 joins East → BOTH clients now see each other
- `+pop` correctly shows `Z: 0:0 1:2 2:0 3:0` (2 users in room 1)
- Leave/rejoin works correctly
- Disconnect notification works (remaining client sees user leave)

---

## 3. Buddy Messaging — SEND Handler (Session 7)

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

## 4. Testing Checklist

### 4.1 Directory Server (dir_server.py :10600)
- [x] Accepts PS2 TCP connection
- [x] Parses `@dir` request (PROD, VERS, LANG, SLUS)
- [x] Responds with login server redirect (ADDR, PORT, LKEY, SESS, MASK)
- [x] Client disconnects cleanly after redirect (one-shot)

### 4.2 Login Server — Authentication Flow (login_server.py :10901)
- [x] Handles `addr` (client reports public IP/port)
- [x] Handles `skey` (session key exchange — client sends `$5075626c6963204b6579` = "Public Key")
- [x] Handles `auth` (NAME, PASS, MID, HWFLAG, HWMASK, PROD, VERS, LANG, SLUS, MASK)
- [x] Handles `pers` (persona selection)
- [x] Pushes `+who` after pers (F=U, N, RI=0, RT=4, R=0, RF=0)
- [x] Handles `sele` initial (ROOMS=1 USERS=1 RANKS=1 MESGS=1 → DRANK response)
- [x] Handles `sele` RANKS=50 (→ ERANK response)
- [x] Handles `news` NAME=0 (→ sele ERANK → `news` flags=new0 → BUDDY_URL/PORT/SERVER)
- [x] Pushes room list (`+rom` x4) and self-user (`+usr`) and population (`+pop`)

### 4.3 Login Server — Room Operations
- [x] Handles `move` (room join) — 5-push sequence: S=0 → +pop → +usr(self) → +who → +pop → +usr(login) → push_existing_users → broadcast_join
- [x] Handles `room` (client creates custom room) — responds with I, N, F; broadcasts +rom, +usr, +pop
- [x] Room creation confirmed: "C.Test" created as room ID 4 with correct population broadcast
- [x] Room leave/disconnect — broadcasts +usr(F=1) deletion and updated +pop to remaining occupants
- [x] All +rom use integer IP format (`ip_to_int`) — `A=3232236155` not `A=192.168.2.123`
- [x] All +usr use correct short tags (I, N, A=int_ip, F, P, S, R)

### 4.4 Login Server — Verified Behaviors
- [x] +rom `T` field = player count (`T="0"`, not room type)
- [x] +usr room ID uses `"R"` not `"RI"`
- [x] +usr includes `"P": ""` (password field)
- [x] ~png `_handle_ping` is silent (no reply — prevents ping-pong flood)
- [x] TREF not sent (confirmed absent from binary)
- [x] +pop uses actual `_room_population()` counts (not hardcoded)
- [x] Room display correct on real PS2 after all above fixes

### 4.5 Login Server — Partially Tested Handlers
- [ ] `snap` (player stats/leaderboard) — handler implemented but not tested on real PS2
- [ ] `user` (profile lookup) — handler implemented but not tested on real PS2
- [⚠️] `mesg` (lobby chat) — handler sends `+msg` relay, now shows red ":" (F=B works, content still empty) — see agent-handoff.md §8
- [ ] ATTR=3 (game invite relay) — not yet implemented

### 4.6 Buddy Server (buddy_server.py :10899)
- [x] Handles `AUTH` (PROD, VERS, PRES, USER, LKEY=$0)
- [x] Handles `PSET` (SHOW=CHAT, STAT=presence string, PROD=status text)
- [x] Handles `RGET` (LRSC=cso, LIST=B/I, PRES=Y, ID=1/2) — returns COUNT=0 (empty lists)
- [x] Handles `SEND` (TYPE=C, USER, BODY, SECS) — acknowledges and relays to online recipient
- [ ] Handles `RADD` (add buddy to list) — not yet tested

### 4.7 Multi-Client & Stability
- [x] **MULTI-CLIENT** — Two PS2s (VTSTech + VTSTech2) join same room, see each other
- [x] **ROOM POPULATION** — +pop reflects actual client count per room
- [x] **BROADCAST** — Join/leave/disconnect notifications between clients
- [x] **KEEPALIVE STABLE** — No disconnects; login ~png at 20s, buddy ~png at 20s; clean logs
- [x] **LONG SESSION** — Confirmed stable through room creation, navigation, idle periods

### 4.8 Game Protocol (Not Yet Implemented)
- [ ] P2P racing protocol (strt/command, game session negotiation, direct connection)
