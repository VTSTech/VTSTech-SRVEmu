
## 1. Testing Checklist

### 1.1 Directory Server (dir_server.py :10600)
- [x] Accepts PS2 TCP connection
- [x] Parses `@dir` request (PROD, VERS, LANG, SLUS)
- [x] Responds with login server redirect (ADDR, PORT, LKEY, SESS, MASK)
- [x] Client disconnects cleanly after redirect (one-shot)

### 1.2 Login Server — Authentication Flow (login_server.py :10901)
- [x] Handles `addr` (client reports public IP/port)
- [x] Handles `skey` (session key exchange — client sends `$5075626c6963204b6579` = "Public Key")
- [x] Handles `auth` (NAME, PASS, MID, HWFLAG, HWMASK, PROD, VERS, LANG, SLUS, MASK)
- [x] Handles `pers` (persona selection)
- [x] Pushes `+who` after pers (F=U, N, RI=0, RT=4, R=0, RF=0)
- [x] Handles `sele` initial (ROOMS=1 USERS=1 RANKS=1 MESGS=1 → DRANK response)
- [x] Handles `sele` RANKS=50 (→ ERANK response)
- [x] Handles `news` NAME=0 (→ sele ERANK → `news` flags=new0 → BUDDY_URL/PORT/SERVER)
- [x] Pushes room list (`+rom` x4) and self-user (`+usr`) and population (`+pop`)

### 1.3 Login Server — Room Operations
- [x] Handles `move` (room join) — 5-push sequence: S=0 → +pop → +usr(self) → +who → +pop → +usr(login) → push_existing_users → broadcast_join
- [x] Handles `room` (client creates custom room) — responds with I, N, F; broadcasts +rom, +usr, +pop
- [x] Room creation confirmed: "C.Test" created as room ID 4 with correct population broadcast
- [x] Room leave/disconnect — broadcasts +usr(F=1) deletion and updated +pop to remaining occupants
- [x] All +rom use integer IP format (`ip_to_int`) — `A=3232236155` not `A=192.168.2.123`
- [x] All +usr use correct short tags (I, N, A=int_ip, F, P, S, R)

### 1.4 Login Server — Verified Behaviors
- [x] +rom `T` field = player count (`T="0"`, not room type)
- [x] +usr room ID uses `"R"` not `"RI"`
- [x] +usr includes `"P": ""` (password field)
- [x] ~png `_handle_ping` is silent (no reply — prevents ping-pong flood)
- [x] TREF not sent (confirmed absent from binary)
- [x] +pop uses actual `_room_population()` counts (not hardcoded)
- [x] Room display correct on real PS2 after all above fixes

### 1.5 Login Server — Partially Tested Handlers
- [ ] `snap` (player stats/leaderboard) — handler implemented but not tested on real PS2
- [ ] `user` (profile lookup) — handler implemented but not tested on real PS2
- [⚠️] `mesg` (lobby chat) — handler sends `+msg` relay, now shows red ":" (F=B works, content still empty) — see §15
- [ ] ATTR=3 (game invite relay) — not yet implemented

### 1.6 Buddy Server (buddy_server.py :10899)
- [x] Handles `AUTH` (PROD, VERS, PRES, USER, LKEY=$0)
- [x] Handles `PSET` (SHOW=CHAT, STAT=presence string, PROD=status text)
- [x] Handles `RGET` (LRSC=cso, LIST=B/I, PRES=Y, ID=1/2) — returns COUNT=0 (empty lists)
- [x] Handles `SEND` (TYPE=C, USER, BODY, SECS) — acknowledges and relays to online recipient
- [ ] Handles `RADD` (add buddy to list) — not yet tested

### 1.7 Multi-Client & Stability
- [x] **MULTI-CLIENT** — Two PS2s (VTSTech + VTSTech2) join same room, see each other
- [x] **ROOM POPULATION** — +pop reflects actual client count per room
- [x] **BROADCAST** — Join/leave/disconnect notifications between clients
- [x] **KEEPALIVE STABLE** — No disconnects; login ~png at 20s, buddy ~png at 20s; clean logs
- [x] **LONG SESSION** — Confirmed stable through room creation, navigation, idle periods

### 1.8 Game Protocol (Not Yet Implemented)
- [ ] P2P racing protocol (strt/command, game session negotiation, direct connection)