# NASCAR Thunder 2004 PS2 — Agent Handoff Document

**Project:** Reverse-engineering and emulating the online server infrastructure for NASCAR Thunder 2004 (PS2, SLUS-20824).
**Date:** 2026-04-20 (slimmed — detailed sections extracted to companion docs)
**Status:** MULTI-CLIENT WORKING on real PS2 hardware. Two PS2 clients can join the same room, see each other, exchange buddy messages. Keepalive stable, no disconnects.

---

## 1. Project Overview

NASCAR Thunder 2004 for PS2 used EA's online lobby service (now defunct). This project reverse-engineers the protocol from the binary (`NASCAR.ELF`, MIPS R3000, stripped) and PCAP captures of real server traffic, then implements emulated servers in Python so the game can connect online again.

### Critical Rule
**Client packets = ground truth. Server packets in PCAPs = hints only.** The Ghidra/r2 decompilation of `LobbyApiUpdate` is the most authoritative reference for what the client expects.

### VTSTech's Documentation (GitHub)
`https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/docs/nascar04`

Key files (5 markdown + 2 JSON):
- `commands.md` — Command/tag reference for all 4-char commands
- `protocol_spec.md` — Wire format, tag types (long vs short), IP address format
- `cheatsheet.md` — Common pitfalls (IP format, null terminators, zero IDs)
- `structure_definitions.md` — Client memory layout for User/Room objects
- `logic_flow.md` — State machine, HashTable bridge, challenge sequence
- `functions.json` — 1,096 named functions from ELF (reference for r2)
- `strings.json` — 3,330+ strings from binary

Decompilations: `https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/docs/nascar04/decom/`
- `LobbyApiUpdate.txt` — Main lobby protocol dispatcher (FULLY ANALYZED)

---

## 2. Wire Format (CRITICAL)

```
[4 bytes] type    — ASCII message type (e.g. @dir, auth, +rom)
[4 bytes] flags   — usually 0x00000000; e.g. b"new0" for news sub-type
[4 bytes] length  — TOTAL frame size INCLUDING the 12-byte header, big-endian uint32
[N bytes] body    — text KEY=VALUE pairs separated by 0x0A (LF), null terminated 0x00
```

### Critical Tag Rules
- **Long Tags** for handshake/auth: `NAME`, `PASS`, `ADDR`, `PORT`, `SESS`, `MASK`
- **Short Tags** for lobby updates: `N`, `I`, `A`, `F`, `S`, `R`, `X`, `T`, `L`, `H`, `P`
- **Wrong tag type = client ignores the packet** (e.g. `NAME=` instead of `N=` in `+usr`)

### IP Address Format (CRITICAL)
- **A tag MUST be integer string**, NOT dotted-quad
- `A=3232236155` ✅ — `A=192.168.2.123` ❌
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
| 8 | `SEND` | C→S | TYPE=C, USER=target, BODY=message, SECS=259200 | ✅ |
| 9 | `SEND` | S→C | S=0 (ack) | ✅ |
| 10 | `~png` | S→C | TIME=2, NAME=username, STATUS=1 (every 20s) | ✅ |

---

## 4. Binary Discrepancies (CRITICAL — Read Before Any RE)

Tags and fields the server sends but the binary does not recognize. Client silently ignores unknown tags via `TagFieldFind` returning NULL.

| Discrepancy | Impact |
|-------------|--------|
| `STATUS` tag — not in binary (only `STAT` at 0x3e34a8 as message type) | None. Dead weight. |
| `DRANK`/`ERANK` — not in binary (only `RANKS` exists) | Rank display may not work. Not blocking. |
| `+snp` stats tags (W, T5, T10, LL, LC, STRK, AS, AF) — not in binary | Stats not displayed. Not blocking. |
| MASK signed/unsigned mismatch (0xFFFFFFFF → -1650254874) | No known issues. |



---

## 5. Implementation Notes (Extracted)

The following completed features are documented in `implementation_notes.md`:
- **§1 ~png Keepalive** — Server sends every 20s, silent handler, TREF removed (not in binary)
- **§2 Room Presence & Multi-Client** — `_room_population()`, `_push_existing_room_users()`, `_broadcast_room_join/leave()`, move handler join path
- **§3 Buddy Messaging SEND** — TYPE=C relay, FROM/TIME delivery, limitations
- **§4 Testing Checklist** — Full checklist of all confirmed and pending tests

---

## 6. Handler Analysis — Key Findings (from r2 disassembly)

- **TagFieldFind String Constants** — All lobby protocol tags with .sdata addresses
- **`+rom` handler** — 13-step disassembly, Room Object memory layout (0x68 bytes)
- **`+usr` handler** — 13-step disassembly, User Object memory layout (0x138 bytes)
- **`+who` handler** — RI (room index) used ONLY here, R used for rank
- **`+pop` handler** — Uses `"___"` delimiter

**Key findings to remember:**
- `T` tag = **current player count**, NOT room type
- `RI` = room index in `+who` ONLY; `R` = room ID in `+usr`
- `F` tag bit 0 = password locked ("No"/"Yes")
- `FROM` at `0x3e3088` (also alt ref at `0x3e3090`)

---

## 7. r2 Binary Verification — Summary

All auth/handshake tags confirmed via r2. STATUS, DRANK, ERANK, and most +snp stats tags NOT in binary (harmless — client silently ignores unknown tags). Buddy server tags all confirmed except STATUS.

**Complete String Constant Map** (all protocol tags in NASCAR.ELF) and detailed r2 session commands are in the r2 analysis output files (`disasm_*.txt`, `r2_*.txt`).

---

## 8. +msg / Lobby Chat Bug (ACTIVE — Session 9–11)

**Current state:** Server relays lobby messages as `+msg`. PS2 client processes them (handler at `0x31c6f8` runs) but only displays a **red `:`** in chat area. The message type IS dispatched correctly, the callback IS invoked, but the payload format is wrong.

**Detailed analysis:** `r2_plusmsg_analysis.md`

**Key findings from r2:**
- Handler looks up `F` tag (0x3e30a8) to determine message type (cast/priv/chat)
- `WHEN` (0x3e30a0) is near `FROM` in .sdata — may be used instead of `TIME` for timestamp
- The callback at `*(s2+0x51c)` may need `FlowModuleUISChatC` to register

**Hypotheses to try next session:**
1. Try `WHEN` instead of `TIME`
2. Try adding `F=` tag to relay payload
3. Try `BODY` instead of `TEXT` (matching buddy SEND)
4. Disassemble callback target at `*(s2+0x51c)`

---

## 9. Connection State Machine

```
State   Hex          Trigger
INIT    0x00         Connection established
CONN    0x636f6e6e   addr command received
SKEY    0x736b6579   skey command sent/received
USER    0x75736572   auth/pers complete
LOBY    0x6c6f6279   sele/+rom sequence
GAME    0x67616d65   strt command (P2P racing)
```

Also: `0x74696d65` = "time" (timeout), `0x7465726d` = "term" (terminated), `0x6f66666c` = "loff" (offline)

---

## 10. Files

### Server Code (Python 3.10+, stdlib only)
**GitHub:** `https://github.com/VTSTech/VTSTech-SRVEmu/tree/main/ai_clean_rewrite`

| File | Purpose |
|------|---------|
| `ea_protocol.py` | Shared TCP wire format, encode/decode, TCPStreamReader, send_kv |
| `dir_server.py` | Dir Server TCP :10600 |
| `login_server.py` | Login Server TCP :10901 (~1080 lines) |
| `buddy_server.py` | Buddy Server TCP :10899 (~400 lines) |
| `*.json` | Optional config files |

**Local copy:** `/home/z/my-project/upload/server/`

### Companion Docs (this directory)

| File | Content |
|------|---------|
| `r2_plusmsg_analysis.md` | +msg handler deep dive, hypotheses, chat bug analysis |
| `implementation_notes.md` | ~png keepalive, room presence, buddy messaging, testing checklist |
| `NASCAR_Function_Map.md` | Function address map from ELF |
| `NASCAR_EA_Lobby_Protocol.md` | EA lobby protocol overview |
| `NASCAR_P2P_Protocol.md` | P2P racing protocol (UDP :1073) |

### Binary & Tools

| Item | Location |
|------|----------|
| `NASCAR.ELF` | `/home/z/my-project/upload/nascar/NASCAR.ELF` (3.01 MB, MIPS R3000) |
| radare2 v6.1.5 | `/home/z/my-project/radare2/binr/radare2/radare2` |
| r2 libs | `/home/z/my-project/radare2/install/usr/local/lib/radare2/` |
| r2 run cmd | `LD_LIBRARY_PATH=/home/z/my-project/radare2/install/usr/local/lib/radare2/ /home/z/my-project/radare2/binr/radare2/radare2 -e scr.color=0 -e bin.cache=true NASCAR.ELF` |
| r2 analysis files | `disasm_*.txt`, `r2_*.txt`, `class_hierarchy.txt` (this directory) |

---

## 11. Remaining Work

1. **P2P racing protocol** — `strt` command triggers P2P over UDP port 1073. See `NASCAR_P2P_Protocol.md`.
2. **Custom room creation** — `room` handler implemented but untested on real PS2.
3. **Game invitations** — Buddy SEND works for chat (TYPE=C) but invitations (SUBJ, ROOM, SEED, ACPT, DECL) not yet implemented.
4. **Lobby chat +msg** — Relay shows white `:` on PS2 (both `BODY` and `TEXT` ruled out) — see §8.
5. **Offline message store** — Buddy SEND drops messages for offline users.
6. **Snap/stats and user lookup** — Implemented but untested on real PS2.
7. **RADD (add buddy)** — Buddy server doesn't handle friend add/remove yet.
