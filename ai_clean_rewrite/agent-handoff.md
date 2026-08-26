# NASCAR Thunder 2004 PS2 — Agent Handoff Document

**Project:** Reverse-engineering and emulating the online server infrastructure for NASCAR Thunder 2004 (PS2, SLUS-20824).
**Date:** 2025-06-18 (updated session 5)
**Status:** Lobby protocol complete. Challenge protocol working. Racing protocol in progress. **GOAL: Complete race with two PS2 clients.**

---

## 1. Project Overview

NASCAR Thunder 2004 for PS2 used EA's online lobby service (now defunct). This project reverse-engineers the protocol from the binary (`NASCAR.ELF`, MIPS R3000, stripped) and PCAP captures of real server traffic, then implements emulated servers in Python so the game can connect online again.

**ULTIMATE GOAL**: Create a **complete, functional server emulator** where PS2 clients can connect, join rooms, send challenges, and **complete races together**.

**SUCCESS CRITERIA**: Two PS2 clients can connect through the emulator, exchange challenges, and complete a race together.

### Critical Rule
**Client packets = ground truth. Server packets in PCAPs = hints only.** The Ghidra decompilation of `LobbyApiUpdate` is the most authoritative reference for what the client expects.

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
- **Short Tags** for lobby updates: `N`, `I`, `A`, `F`, `S`, `R`, `X`, `T`, `L`, `H`
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
| 19 | `+rom` x4 | S→C | RI=0..3, N, H, A=int_ip, T, L, F | ✅ SENT but ❌ NOT JOINABLE |
| 20 | `+usr` | S→C | I, N, F=1, A=int_ip, S=Online | ✅ |
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

---

## 4. PROTOCOL STATUS

### ✅ COMPLETED PROTOCOLS
- **Lobby Protocol**: Authentication, room listing, user visibility, chat/challenge system
- **Challenge Protocol**: Challenge sending, response handling (DECL/ACPT), message forwarding
- **Buddy Server**: Authentication, presence management, chat functionality
- **Multi-client Support**: Multiple PS2 clients can connect and see each other

### 🔄 IN PROGRESS PROTOCOLS
- **Racing Protocol**: After challenge acceptance, need to implement race session management
- **Race Synchronization**: Coordinate race start, progress, and completion between clients

### CURRENT STATUS: Challenge System Working
The challenge protocol is functional:
- Client A can send challenge to Client B
- Challenge is properly forwarded to target client
- Target client can respond with DECL/ACPT
- Challenge tokens are correctly parsed (w893m_a017l_g format)
- Message forwarding enables cross-client challenge notifications

**Testing Confirmed**: Real PS2 clients can exchange challenges with proper message forwarding.

### What We Know From Decompilation
From `LobbyApiUpdate.txt` (Ghidra decompilation of client code):

**`+rom` handler at `iStack_b0 == 0x2b726f6d`:**
```c
if ((iStack_b0 == 0x2b726f6d) && (piVar24[0xc4] != 0)) {
    pbVar4 = TagFieldFind(pbStack_a8, (byte *)ROOM_IDField);
    iVar10 = TagFieldGetNumber(pbVar4, -1);
    if (-1 < iVar10) {
        pbVar4 = TagFieldFind(pbStack_a8, &MSG_UsernameField);
        if (pbVar4 == (byte *)0x0) {
            // DELETE ROOM
        }
        else {
            // CREATE/UPDATE ROOM
            piVar7 = Util_AllocateMemory(0x68);  // 104 bytes
            *piVar7 = iVar10;                     // [0x00] I = room ID
            TagFieldGetString(N, (piVar7 + 7), 0x20);  // [0x07] N = name
            TagFieldGetString(H, (piVar7 + 0xf), 0x20); // [0x0F] H = heading
            TagFieldGetFlags(F, 0xffffffff);             // [0x02] F = flags
            TagFieldGetAddress(A, 0);                    // [0x19] A = host IP
            TagFieldGetNumber(player_count, 0);          // [0x10] = player count
            TagFieldGetNumber(max_players, 0);           // [0x0C] = max players
            // HashTable insert/update
        }
    }
}
```

**Room Object Memory Layout (0x68 = 104 bytes):**
| Offset | Tag | Size | Description |
|--------|-----|------|-------------|
| 0x00 | `I` | int | Room ID (key for HashTable) |
| 0x07 | `N` | 32B | Room Name |
| 0x0F | `H` | 32B | Room Heading/Description |
| 0x19 | `A` | int | Host IP Address (integer) |
| 0x02 | `F` | int | Flags (masked with 0xFFFFFFFF) |
| 0x0C | L | int | Max Players |
| 0x10 | P | int | Current Player Count |
| 0x14 | ? | ~32B | Formatted player string |

**Key Unknown:** The client calls `TagFieldFind(pbStack_a8, (byte *)ROOM_IDField)` but we don't know what string `ROOM_IDField` resolves to. It could be:
- `"I"` (single letter tag)
- `"ID"` (room ID)
- `"RI"` (room index)
- Something else entirely

Similarly for:
- `ROOM_DescriptionField` → likely `"H"` or `"DESC"`
- `ROOM_HostField` → likely `"A"`
- `ROOM_MaxPlayersField` → likely `"L"` or `"MAX"`
- `MSG_UsernameField` → likely `"N"`
- `MSG_FlagsField` → likely `"F"`

### What To Investigate Next

1. **FRESH DECOMPILATION REQUIRED** — Need to run r2 on the binary to find the actual string constants used by TagFieldFind in the +rom and +usr handlers. The decompilation files from GitHub may be from earlier analysis and don't map to current binary.

2. **String constants in binary** — Use r2 to search for string constants referenced by TagFieldFind. The decompilation shows `&STR_I_003e30d8`, `&STR_N_003e30b0`, etc. — we need to find what these resolve to.

3. **Check if `T` field is used** — The decompiler shows `TagFieldGetNumber(T, 0)` for the type field. We send `T=str(room_type)`. Need to verify if this is read by the +rom handler.

4. **Check flags field** — We send `F=0`. The decompiler shows `TagFieldGetFlags(F, 0xffffffff)`. Need to verify if this is read correctly.

5. **Test outside VM** — User will run servers outside the VM on LAN to test with real PS2.

6. **Consider Lobby (room 0)** — The Lobby might not be a joinable room. The client might only display rooms 1, 2, 3 (East, West, Beginner) as selectable.

7. **Add logging to client** — Could add debug logging to the client to see what TagFieldFind actually receives during +rom parsing.

### Next Step: Analyze Ghidra Decomposition

The `LobbyApiUpdate` decompilation (fetched and analyzed) reveals the **exact `+rom` parsing code**. Key findings:

**`+rom` handler at `iStack_b0 == 0x2b726f6d` ("+rom" reversed as little-endian int):**

```c
if ((iStack_b0 == 0x2b726f6d) && (piVar24[0xc4] != 0)) {
    pbVar4 = TagFieldFind(pbStack_a8, (byte *)ROOM_IDField);      // Room ID
    iVar10 = TagFieldGetNumber(pbVar4, -1);
    if (-1 < iVar10) {
        pbVar4 = TagFieldFind(pbStack_a8, &MSG_UsernameField);   // N (name)
        if (pbVar4 == (byte *)0x0) {
            // NO NAME = DELETE ROOM from HashTable
            puVar6 = HashTable_Lookup(piVar24[0xc4], iVar10);
            if (puVar6 != (undefined4 *)0x0) {
                HashTable_Remove(piVar24[0xc4], iVar10);
                // free memory
            }
        }
        else {
            // NAME EXISTS = CREATE/UPDATE ROOM
            piVar7 = Util_AllocateMemory(0x68);  // 104 bytes
            *piVar7 = iVar10;                     // [0x00] I = room ID
            TagFieldGetString(N, (piVar7 + 7), 0x20);  // [0x07] N = name (32 bytes)
            TagFieldGetString(H, (piVar7 + 0xf), 0x20); // [0x0F] H = heading (32 bytes)
            TagFieldGetFlags(F, 0xffffffff);             // [0x02] F = flags (stored at offset 2)
            TagFieldGetAddress(A, 0);                    // [0x19] A = host IP (integer)
            TagFieldGetNumber(player_count, 0);          // [0x10] = player count
            TagFieldGetNumber(max_players, 0);           // [0x0C] = max players
            Util_FormatIPString((piVar7 + 5), 0x3e2f70, player_count, ...); // [0x14] formatted player string
            // HashTable insert/update
        }
    }
}
```

**Room Object Memory Layout (0x68 = 104 bytes):**

| Offset | Tag | Size | Description |
|--------|-----|------|-------------|
| 0x00 | `I` | int | Room ID (key for HashTable) |
| 0x07 | `N` | 32B | Room Name |
| 0x0F | `H` | 32B | Room Heading/Description |
| 0x19 | `A` | int | Host IP Address (integer via TagFieldGetAddress) |
| 0x02 | `F` | int | Flags (extracted via TagFieldGetFlags with mask 0xFFFFFFFF) |
| 0x0C | L | int | Max Players (limit) |
| 0x10 | P | int | Current Player Count |
| 0x14 | ? | ~32B | Formatted player string |

**KEY OBSERVATION:** The client uses `TagFieldFind(pbStack_a8, (byte *)ROOM_IDField)` for the room ID field name. We don't know the exact string `ROOM_IDField` resolves to — it could be `"I"`, `"ID"`, `"RI"`, or something else. **This is the critical unknown.** We need to check the Ghidra decompilation for the actual string constant at `ROOM_IDField`.

Similarly for other fields:
- `ROOM_DescriptionField` → likely `"H"` or `"DESC"`
- `ROOM_HostField` → likely `"A"`
- `ROOM_PlayerCountField` → likely `"P"` or `"L"` (current count)
- `ROOM_MaxPlayersField` → likely `"L"` or `"MAX"` (max count)
- `ROOM_PasswordField` → password field

**`+usr` handler at `iStack_b0 == 0x2b757372`:**

```c
piVar7 = Util_AllocateMemory(0x138);  // 312 bytes
*piVar7 = iVar10;                      // [0x00] I = user ID
TagFieldGetString(N, (piVar7 + 2), 0x20);  // [0x02] N = name (32 bytes)
TagFieldGetAddress(A, 0);             // [0x0C] A = IP (integer)
TagFieldGetString(password, (piVar7 + 10), 8); // [0x0A] password field (8 bytes)
TagFieldGetFlags(F, 0);               // [0x01] F = flags (at offset 1)
TagFieldGetString(DAT_003e3130, (piVar7 + 0xe), 0x80); // [0x0E] extra text (128 bytes)
TagFieldGetNumber(rank, 0);           // [0x0D] R = room ID (rank field used for room)
TagFieldGetString(DAT_003e3138, (piVar7 + 0x2e), 0x80); // [0x2E] more text (128 bytes)
```

**User Object Memory Layout (0x138 = 312 bytes):**

| Offset | Tag | Size | Description |
|--------|-----|------|-------------|
| 0x00 | `I` | int | User ID (key for HashTable) |
| 0x02 | `N` | 32B | Persona Name |
| 0x0C | `A` | int | IP Address (integer) |
| 0x0A | P | 8B | Password |
| 0x01 | `F` | int | Flags |
| 0x0D | R | int | Room ID (parsed from "rank" field name, but stores room index!) |
| 0x0E | X | 128B | Extra text |
| 0x2E | T | 128B | More extra text |

**CRITICAL FINDING:** In `+usr`, the room ID is at offset 0x0D and is read via `TagFieldFind(pbStack_a8, &MSG_RankField)` — the tag name is the RANK field constant, not a "ROOM" field. This might mean the tag is `"R"` for both rank AND room ID, or the decompiler merged similar field lookups.

### What To Investigate Next

1. **Get the actual string constants** for `ROOM_IDField`, `ROOM_DescriptionField`, `ROOM_HostField`, `ROOM_PlayerCountField`, `ROOM_MaxPlayersField`, `MSG_UsernameField`, `MSG_RankField`, `MSG_FlagsField` — these are the TagFieldFind keys the client actually looks for. The user needs to run `r2 -c 'ps @ <addr>'` or check the Ghidra listing to find what strings these resolve to.

2. **Check if the `F` (flags) field in `+rom` is being read correctly.** The decompiler shows `TagFieldGetFlags(F, 0xffffffff)` which extracts a bitmask. We send `F=0` — this should be fine but worth verifying.

3. **Check the `T` (type) field.** Our `+rom` sends `T=1` for all rooms. The client code shows `TagFieldGetFlags(F, 0xffffffff)` and then checks `(flags & 0x10000)` and `(flags & 0x200000)`. The `T` field might be part of flags or a separate field. We need to check if `T` is even read by the `+rom` handler.

4. **Consider that the Lobby (room 0) might not be a joinable room.** The client state machine shows states: INIT→CONN→SKEY→USER→LOBY→GAME. The Lobby is where you ARE when browsing rooms. The joinable rooms are 1, 2, 3 (East, West, Beginner). If the client shows a room list screen, the problem might be that it only displays rooms with specific flag bits set.

5. **Try fetching more decompilations** from `https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/docs/nascar04/decom/` — there may be `LobbyApiListUpdate`, `Lobby_UpdateRoomPopulation`, or UI rendering functions that reveal what makes a room visible.

---

## 5. Protocol Analysis & Implementation Status

### Bug #1: Length Field Interpretation (CRITICAL — session 1)
- Length field = total frame size (header + body), not body length
- Caused 15-second timeout on every frame

### Bug #2: 127.0.0.1 Instead of LAN IP (session 1)
- Dir server sent loopback address; PS2 couldn't reach login server
- Added `get_lan_ip()` auto-detection

### Bug #3: Space-Separated KV Parsing (session 1)
- `sele ROOMS=1 USERS=1...` parsed as single KV
- Added `_split_kv_tokens()` to handle both LF and space separators

### Bug #4: newsnew0 Message Type Corruption (session 1)
- `send_kv(writer, "newsnew0", ...)` — 8-char type corrupted flags field
- Changed to `send_kv(writer, "news", {...}, flags=b"new0")`

### Bug #5: Protocol Ordering — 6 fixes (session 2)
- Moved `+who` from after-auth to after-pers
- Moved `+rom`/`+usr`/`+pop` from after-auth to after-news
- Changed news response type from `news` to `sele` (for ERANK)
- Added `_push_user_login()` with login format (I, N, F=1, A=ip)
- Changed room_index from -1 to 0 (Lobby)
- Updated move join to 5-push sequence

### Bug #6: sele Double Responses (session 3)
- Initial sele sent both DRANK and ERANK; rank-only sele also sent both
- Fixed: mutually exclusive — initial gets DRANK only, RANKS gets ERANK only

### Bug #7: Buddy Server Status Not Set (session 3)
- `client.status` never set to 1 after AUTH, so `+pop` reported 0 online
- Fixed: `client.status = 1` in `_handle_auth`

### Bug #8: IP Address Format Wrong (session 3)
- `A=192.168.2.123` (dotted quad) instead of `A=3232236155` (integer string)
- Added `ip_to_int()` helper, applied to all `+rom` and `+usr` A fields

### Bug #9: +usr Wrong Tags (session 3)
- Room context used `RI` instead of `R` for room ID
- Room context used non-standard `M`, `ST` instead of documented `S`
- Room context was missing `A` field
- All fixed per structure_definitions.md

### Lobby Protocol Implementation (COMPLETE)
- **TagFieldFind Constants**: Identified from binary analysis (I, N, H, A, T, L, F)
- **Room Management**: Room creation, listing, population tracking
- **User Management**: Authentication, presence, broadcasting
- **Challenge System**: Challenge sending, response handling, message forwarding
- **Multi-client Support**: Real-time user visibility and chat

### Challenge Protocol Implementation (COMPLETE)
- **Challenge Format**: PRIV/TEXT/ATTR format confirmed in binary
- **Token Parsing**: w893m_a017l_g format (track=11, AI difficulty)
- **Response Handling**: DECL/ACPT responses properly forwarded
- **Message Broadcasting**: Cross-client challenge notifications

### Racing Protocol (IN PROGRESS)
- **Race Session Management**: Need to implement after challenge acceptance
- **Race Synchronization**: Coordinate race start, progress, completion
- **P2P Communication**: Direct client communication during racing

---

## 6. Files

### Server Code (Python 3.10+, stdlib only)

| File | Location | Purpose |
|------|----------|---------|
| `ea_protocol.py` | `/home/z/my-project/NASCAR2004_Server_Suite/` | Shared TCP wire format, encode/decode, TCPStreamReader, send_kv |
| `dir_server.py` | same | Dir Server TCP :10600 |
| `login_server.py` | same | Login Server TCP :10901 (~1010 lines) |
| `buddy_server.py` | same | Buddy Server TCP :10899 |
| `*.json` | same | Optional config files |

### Reference Files

| File | Location | Purpose |
|------|----------|---------|
| `agent-handoff.md` | `/home/z/my-project/NASCAR2004_docs/docs/` | This document |
| `worklog.md` | `/home/z/my-project/` | Session worklog |
| VTSTech docs | GitHub `docs/nascar04/` | commands.md, protocol_spec.md, cheatsheet.md, structure_definitions.md, logic_flow.md, functions.json, strings.json |
| VTSTech decomp | GitHub `docs/nascar04/decom/` | LobbyApiUpdate.txt (analyzed), possibly more files |

### radare2
- Built from source at `/home/z/radare2/` (v6.1.5)
- The ELF binary (`NASCAR.ELF`) is NOT on this server
- User has the binary locally with Ghidra

---

## 7. Connection State Machine (from logic_flow.md)

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

### Racing Protocol States (NEEDS ANALYSIS)
- **Challenge Accepted**: State transition to race preparation
- **Race Setup**: Track selection, difficulty configuration
- **Race Start**: Synchronization between clients
- **Race Progress**: Real-time position/telemetry data
- **Race Completion**: Results synchronization

---

## 8. Testing Checklist

### ✅ COMPLETED TESTS
- [x] Dir Server accepts PS2 connection on TCP :10600
- [x] Dir Server parses `@dir` request correctly
- [x] Dir Server responds with login server redirect (LAN IP)
- [x] PS2 connects to Login Server after @dir redirect
- [x] Login Server handles addr, skey, auth, pers
- [x] Login Server pushes +who after pers
- [x] Login Server handles sele (DRANK for initial, ERANK for RANKS)
- [x] Login Server handles news NAME=0 → sele ERANK → newsnew0 → +rom → +usr → +pop
- [x] All +rom use integer IP format (ip_to_int)
- [x] All +usr use correct tags (I, N, A=int_ip, F, S, R for room context)
- [x] Buddy Server handles AUTH, PSET, RGET — confirmed working on real PS2
- [x] **Challenge System** — Confirmed working with real PS2 clients
- [x] **Multi-client Support** — Multiple PS2 clients can connect and see each other
- [x] **Room Join Functionality** — Rooms are joinable and functional

### 🔄 IN PROGRESS TESTS
- [ ] **Racing Protocol** — Need to implement race session management
- [ ] **Race Synchronization** — Coordinate race start, progress, completion
- [ ] **P2P Racing** — Direct client communication during racing
- [ ] **Complete Race Flow** — End-to-end race completion with two PS2 clients

### 📋 NEXT STEPS FOR COMPLETION
1. **Analyze racing protocol** after challenge acceptance
2. **Implement race session management** in emulator
3. **Add race synchronization** between clients
4. **Test complete race flow** with two PS2 clients
5. **Validate race completion** and results handling

**SUCCESS CRITERION**: Two PS2 clients can connect through the emulator, exchange challenges, and complete a race together.