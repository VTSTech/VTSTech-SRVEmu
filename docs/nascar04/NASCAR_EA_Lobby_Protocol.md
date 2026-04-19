# EA Sports Lobby/Buddy Protocol — NASCAR Thunder 2004 (PS2)

**Game:** NASCAR Thunder 2004
**Platform:** PlayStation 2
**Disc ID:** SLUS-20824
**Build Date:** Jul 2 2003
**Protocol Type:** TCP text-based key-value over 12-byte binary header
**Scope:** Lobby, matchmaking, chat, friends, room management (NOT in-race P2P)

---

## Table of Contents

1. [Introduction & Scope](#1-introduction--scope)
2. [Architecture Overview](#2-architecture-overview)
3. [Wire Format Specification](#3-wire-format-specification)
4. [Connection Flow](#4-connection-flow)
5. [Protocol Key Reference](#5-protocol-key-reference)
6. [Server Response Format](#6-server-response-format)
7. [GameServer Protocol](#7-gameserver-protocol)
8. [BuddyServer Protocol](#8-buddyserver-protocol)
9. [Authentication System](#9-authentication-system)
10. [Profanity Filter](#10-profanity-filter)
11. [Network State Machine](#11-network-state-machine)
12. [Client-Side Class Map](#12-client-side-class-map)
13. [Debug Strings Reference](#13-debug-strings-reference)
14. [Error Codes & Messages](#14-error-codes--messages)
15. [Data Sources & Methodology](#15-data-sources--methodology)

---

## 1. Introduction & Scope

### 1.1 Purpose

This document specifies the TCP lobby/buddy protocol used by **NASCAR Thunder 2004** (PS2, SLUS-20824) for online matchmaking, chat, friends, and room management. It is intended to support the development of server emulators for legacy online play.

### 1.2 What This Document Covers

| Covered (This Protocol) | Not Covered (Separate) |
|---|---|
| TCP lobby connections (3-server chain) | UDP P2P racing protocol |
| Room creation/joining/listing | In-race game state sync |
| Text-based chat & friends | `ProtocolChatC` binary race chat |
| Matchmaking & ranked matching | Voice chat |
| Authentication & session management | Game data transfer |

### 1.3 Key Clarifications

- **Port 1073** (hardcoded in binary) is likely the P2P racing port, **NOT** the lobby port. Lobby uses TCP:10600.
- **`ProtocolChatC`** (in `.rodata`) is the IN-RACE binary chat protocol — lobby chat uses `TEXT`/`PRIV`/`CHAT` keys from this text-based buddy protocol.
- The **0xFEFEFEFE** magic value is for P2P crypto; the lobby `MASK` value from emulated capture was **0xAE46F19A**.
- The **skey** field sends a literal hex encoding of the string `"Public Key"` — this is NOT actual encryption, it is the EA lobby's public key identification mechanism.

### 1.4 Product Identifiers

| Field | Value | Notes |
|---|---|---|
| Product Name | `NASCAR` | Sent as `PROD` key |
| Version | `2004` | Sent as `VERS` key |
| Disc ID | `BASLUS-20824` | Sent as `SLUS` key (note `B` prefix) |
| Namespace | `/cso/nascar-ps2-2004` | Buddy server user namespace |
| Hostname | `ps2nascar04.ea.com` | Original DNS hostname |
| EA System | `EA Login` | Authentication system name |
| Buddy ID | `EASB` | EA Sports Buddy identifier |

---

## 2. Architecture Overview

### 2.1 Three-Server Connection Chain

The game establishes a strict sequential chain of three TCP connections:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     NASCAR Thunder 2004 — PS2                       │
│                                                                     │
│  ┌──────────┐    TCP:10600     ┌────────────┐    TCP:dynamic     ┌──────────────┐
│  │   PS2     │ ──────────────► │ Dir Server  │ ───────────────► │  GameServer   │
│  │  Client   │ ◄────────────── │ (static IP) │ ◄─────────────── │  (dynamic)    │
│  │           │                 └────────────┘                  └──────────────┘
│  │           │                                                      │
│  │           │              hands off ADDR+PORT+LKEY                │
│  │           │              hands off BUDDY_PORT+BUDDY_URL          │
│  │           │                                                      │
│  └──────────┘                                        │             │
│       │                                              │             │
│       │                          TCP:dynamic          │             │
│       │           ┌──────────────────────────────────┘             │
│       │           ▼                                                  │
│       │  ┌──────────────┐                                          │
│       └──│ BuddyServer  │                                          │
│          │ (dynamic)    │                                          │
│          └──────────────┘                                          │
│                                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Server Roles

| # | Server | Default Port | Protocol Prefix | Purpose |
|---|---|---|---|---|
| 1 | **Dir Server** | TCP 10600 (static) | `@dir` | Initial handshake, provides GameServer address and session credentials |
| 2 | **GameServer** | TCP dynamic (e.g. 10901) | None | Room management, matchmaking, subscriptions, hands off BuddyServer info |
| 3 | **BuddyServer** | TCP dynamic (e.g. 10899) | None | Persistent chat, friends list, presence, matchmaking notifications |

### 2.3 Connection Dependency Graph

```
Connection 1 (Dir Server)          Connection 2 (GameServer)         Connection 3 (BuddyServer)
        │                                  │                                  │
        ├─► Receives ADDR, PORT           ├─► Receives ROOMS, USERS,         ├─► Receives presence,
        │   LKEY, SESS, MASK              │   RANKS, BUDDY_PORT,             │   buddy list, chat,
        │                                  │   BUDDY_URL                      │   game invitations
        │                                  │                                  │
        └──► Closes connection            └──► May stay open or close        └──► Persistent
            after GameServer                  after BuddyServer                  connection for
            info received                     info received                     session lifetime
```

### 2.4 Known Hostname

```
ps2nascar04.ea.com   (0x3d8bf8 in .rodata)
```

This is the original DNS hostname the client resolves to find the Dir Server at port 10600.

---

## 3. Wire Format Specification

### 3.1 Packet Structure

Every message on all three connections uses the same binary header followed by a text-based key-value payload:

```
Offset  Size  Field         Description
──────  ────  ────────────  ─────────────────────────────────────────────
0x00    4B    Type          ASCII message type (e.g. "keys", "resp", "mesg")
0x04    4B    Reserved      Always 0x00000000
0x08    4B    Length        Payload length, big-endian uint32
0x0C    var   Payload       Key-value text block, null-terminated
```

### 3.2 Payload Format

The payload is a series of newline-delimited key-value pairs, terminated by a null byte (`\0`):

```
KEY1=VALUE1\n
KEY2=VALUE2\n
KEY3=VALUE3\n
\0
```

- Keys and values are separated by `=` (ASCII 0x3D)
- Pairs are separated by `\n` (ASCII 0x0A)
- The entire payload is null-terminated
- Values may contain spaces, special characters, and escaped sequences
- Empty values are valid (e.g., `PASS=\n`)

### 3.3 Message Type Codes (4-byte ASCII)

The binary header's first 4 bytes indicate the message category. Known types inferred from debug strings and binary analysis:

| Type Code | Direction | Purpose | Confidence |
|---|---|---|---|
| `keys` | Client → Server | Key-value request (login, room ops) | Confirmed (binary) |
| `resp` | Server → Client | Key-value response | Confirmed (binary) |
| `mesg` | Bidirectional | Chat/message payload | Confirmed (binary) |
| `pres` | Server → Client | Presence/buddy status update | Confirmed (binary) |
| `~png` | Bidirectional | Keepalive (server-initiated) | ✅ Confirmed (real PS2) |
| `bye` | Either | Disconnect notification | Inferred |

### 3.4 Subtype (from Debug Log)

The debug string at 0x3df250:
```
recv: %c%c%c%c/%c%c%c%c\n
```

This shows the client logs **both a 4-char type and a 4-char subtype** on receive. The subtype likely indicates the specific operation within a message category (e.g., `keys`/`login`, `keys`/`room`).

### 3.5 Payload Length

The `Length` field at offset 0x08 is a **big-endian 32-bit unsigned integer** representing the byte count of the payload (including the trailing null byte but NOT the 12-byte header itself).

### 3.6 Example Wire Capture (Reconstructed)

```
Hex view of a Dir Server login request:

00000000  6b 65 79 73  00 00 00 00  00 00 00 2a  keys.... ...*
0000000c  50 52 4f 44 3d 4e 41 53  PROD=NASC
00000014  43 41 52 0a  56 45 52 53  CAR.VERS
0000001c  3d 32 30 30  34 0a 53 4c  =2004.SL
00000024  55 53 3d 42  41 53 4c 55  US=BASLU
0000002c  53 2d 32 30  38 32 34 0a  S-20824.
00000034  00                              .

Header:  type="keys"  reserved=0x00000000  length=42 (0x2a)
Payload: PROD=NASCAR\nVERS=2004\nSLUS=BASLUS-20824\n\0
```

---

## 4. Connection Flow

### 4.1 Overview

The client follows a strict sequential three-phase connection process:

```
Phase 1: Dir Server Handshake
Phase 2: GameServer Authentication & Room Setup
Phase 3: BuddyServer Persistent Connection
```

### 4.2 Phase 1 — Dir Server (TCP:10600)

The client connects to the Dir Server at the well-known port 10600 (resolved from `ps2nascar04.ea.com`).

#### Step 1: Client → Dir Server (Login Request)

The client sends its product identification keys:

```
PROD=NASCAR
VERS=2004
LANG=en        ← (inferred; language code)
SLUS=BASLUS-20824
```

| Key | Address | Value | Notes |
|---|---|---|---|
| `PROD` | 0x3e31c8 | `NASCAR` | Product identifier |
| `VERS` | 0x3e31d0, 0x3e2fa8 | `2004` | Version string |
| `LANG` | 0x3e31d8 | Language code | System language |
| `SLUS` | 0x3e31e0 | `BASLUS-20824` | Disc ID with `B` prefix |

#### Step 2: Dir Server → Client (Session Response)

The Dir Server responds with connection handoff data:

```
ADDR=10.0.0.1
PORT=10901
LKEY=<hex session key>
SESS=<session id>
MASK=AE46F19A
```

| Key | Address | Purpose | Notes |
|---|---|---|---|
| `ADDR` | 0x3e2f90, 0x3d8a70 | GameServer IP address | Handoff address |
| `PORT` | 0x3e3018 | GameServer TCP port | Dynamic (e.g., 10901) |
| `LKEY` | 0x3e34c8 | Login key | Hex authentication token for subsequent connections |
| `SESS` | 0x3e3020 | Session ID | Server-assigned session identifier |
| `MASK` | 0x3e2fe0 | Hardware/network mask | Observed as `0xAE46F19A` in emulated capture |

#### Step 3: Dir Server Connection Closes

After sending the response, the Dir Server connection is typically closed. The client initiates a new TCP connection to the GameServer at the provided `ADDR`:`PORT`.

### 4.3 Phase 2 — GameServer (TCP:dynamic)

The client connects to the GameServer at the address and port received from the Dir Server.

#### Step 1: Client → GameServer (Authentication)

```
skey=5075626c6963204b6579
addr=<client local IP>
auth=<authentication token>
pers=<persona name>
sele=<selection info>
```

| Key | Address | Value | Notes |
|---|---|---|---|
| `skey` | 0x3e3030 | `5075626c6963204b6579` | Hex encoding of ASCII `"Public Key"` |
| `addr` | — | Client's local IP | Self-reported |
| `auth` | — | Auth token | Derived from LKEY or EA Login |
| `pers` | — | Persona name | Player's chosen screen name |
| `sele` | — | Selection info | Game mode or room selection |

**IMPORTANT:** The `skey` value `5075626c6963204b6579` is the hexadecimal ASCII encoding of the literal string `"Public Key"`. This is NOT cryptographic — it is the EA lobby protocol's public key identification mechanism. The 512-byte hex table at 0x3df2c8 in the binary likely represents a static lookup table associated with this key.

The auth credential format follows the pattern (from 0x3d82e8):
```
%s:$%s    →    username:$token
```

#### Step 2: GameServer → Client (Room Data & Buddy Handoff)

The GameServer responds with room listings and BuddyServer connection info:

```
ROOMS=1 USERS=1 RANKS=1 MESGS=1
BUDDY_PORT=10899
BUDDY_URL=buddy.ea.com
```

| Key | Address | Purpose | Notes |
|---|---|---|---|
| `ROOMS=` | 0x3e2fb0 | Room subscription flag | Part of composite subscription string |
| `RANKS=` | 0x3e2fb8 | Rankings subscription flag | Part of composite subscription string |
| `USERS=` | 0x3e2fc0 | Users subscription flag | Part of composite subscription string |
| `BUDDY_PORT` | 0x3c1520 | BuddyServer TCP port | Dynamic port for Connection 3 |
| `BUDDY_URL` | 0x3c1508 | BuddyServer hostname | DNS name for Connection 3 |

The composite subscription string `ROOMS=1 USERS=1 RANKS=1 MESGS=1` (at 0x3e0370) tells the server which data subscriptions the client wants.

#### Step 3: GameServer → Client (Data Pushes)

The GameServer may then push room data, user lists, and rank data as separate messages:

```
ROOM=room_01
NAME=NASCAR Thunder Lobby
DESC=Official NASCAR room
SLOTS=4/16
HOST=PlayerOne
```

### 4.4 Phase 3 — BuddyServer (TCP:dynamic)

The client connects to the BuddyServer using the `BUDDY_URL` and `BUDDY_PORT` from the GameServer response.

#### Step 1: Client → BuddyServer (Buddy Login)

```
USER=VTSTech/cso/nascar-ps2-2004
PROD=NASCAR
VERS=2004
PRES=online
LKEY=<login key from Dir Server>
EASB=1
```

| Key | Address | Value | Notes |
|---|---|---|---|
| `USER` | 0x3e3330 | `VTSTech/cso/nascar-ps2-2004` | Namespaced username |
| `PROD` | 0x3e34a0 | `NASCAR` | Product identifier |
| `VERS` | 0x3e34b8 | `2004` | Version |
| `PRES` | 0x3e34c0 | `online` | Initial presence status |
| `LKEY` | 0x3e34c8 | (from Dir Server) | Reuse login key for session continuity |
| `EASB` | 0x3e33b0 | `1` | EA Sports Buddy protocol flag |

#### Step 2: BuddyServer → Client (Persistent Stream)

The BuddyServer maintains a persistent connection and pushes:
- Presence updates for buddies
- Chat messages (`TEXT`, `PRIV`)
- Game invitations
- Buddy list updates

The BuddyServer connection stays open for the duration of the online session.

### 4.5 Connection Timing Summary

```
Time →

[Dir Server Connect]──[Recv ADDR/PORT/LKEY]──[Dir Server Close]
                                              │
                    [GameServer Connect]──────┘
                    │
                    ├──[Send skey/auth/pers]──[Recv ROOMS/BUDDY_*]
                    │
                    │                         [BuddyServer Connect]
                    │                         ├──[Send USER/LKEY/EASB]
                    │                         └──[Persistent connection open]
                    │
                    ├──[Room operations, chat via GameServer]
                    └──[Chat, presence, friends via BuddyServer]
```

---

## 5. Protocol Key Reference

This is the complete catalog of every protocol key identified from the NASCAR Thunder 2004 binary (SLUS-20824), organized by functional category. Memory addresses are from the `.sdata` and `.rodata` sections of NASCAR.ELF.

### 5.1 Connection 1 — Dir Server Client Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|---|
| `PROD` | 0x3e31c8 | String | Client → Dir | Product identifier | `NASCAR` |
| `VERS` | 0x3e31d0, 0x3e2fa8 | String | Client → Dir | Game version | `2004` |
| `LANG` | 0x3e31d8 | String | Client → Dir | Language code | `en` |
| `SLUS` | 0x3e31e0 | String | Client → Dir | Disc identifier (B-prefixed) | `BASLUS-20824` |

### 5.2 Connection 1 — Dir Server Response Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|---|
| `ADDR` | 0x3e2f90, 0x3d8a70 | IP String | Dir → Client | GameServer IP address | `10.0.0.1` |
| `PORT` | 0x3e3018 | Integer | Dir → Client | GameServer TCP port | `10901` |
| `LKEY` | 0x3e34c8 | Hex String | Dir → Client | Login key for session auth | `a1b2c3d4e5` |
| `SESS` | 0x3e3020 | String | Dir → Client | Session identifier | `sess_12345` |
| `MASK` | 0x3e2fe0 | Hex String | Dir → Client | Hardware/network mask | `AE46F19A` |

### 5.3 Connection 2 — GameServer Client Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|---|
| `skey` | 0x3e3030 | Hex String | Client → GS | "Public Key" hex (NOT encryption) | `5075626c6963204b6579` |
| `addr` | — | IP String | Client → GS | Client's self-reported local IP | `192.168.1.100` |
| `auth` | — | String | Client → GS | Authentication token | `username:$token` |
| `pers` | — | String | Client → GS | Player persona/screen name | `SpeedRacer42` |
| `sele` | — | String | Client → GS | Selection/game mode info | `race` |

### 5.4 Connection 2 — GameServer Response Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|---|
| `ROOMS=` | 0x3e2fb0 | Integer Flag | GS → Client | Room subscription count | `1` |
| `RANKS=` | 0x3e2fb8 | Integer Flag | GS → Client | Rankings subscription count | `1` |
| `USERS=` | 0x3e2fc0 | Integer Flag | GS → Client | User list subscription count | `1` |
| `BUDDY_PORT` | 0x3c1520 | Integer | GS → Client | BuddyServer TCP port | `10899` |
| `BUDDY_URL` | 0x3c1508 | String | GS → Client | BuddyServer hostname | `buddy.ea.com` |

### 5.5 Connection 3 — BuddyServer Client Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|---|
| `USER` | 0x3e3330 | String | Client → BS | Namespaced username | `VTSTech/cso/nascar-ps2-2004` |
| `PROD` | 0x3e34a0 | String | Client → BS | Product identifier | `NASCAR` |
| `VERS` | 0x3e34b8 | String | Client → BS | Game version | `2004` |
| `PRES` | 0x3e34c0 | String | Client → BS | Initial presence status | `online` |
| `LKEY` | 0x3e34c8 | Hex String | Client → BS | Login key (from Dir Server) | (reused) |
| `EASB` | 0x3e33b0 | String | Client → BS | EA Sports Buddy flag | `1` |

### 5.6 Room Management Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|---|
| `ROOM` | 0x3d8380 | String | Either | Room ID | `room_01` |
| `NAME` | 0x3e2f80, 0x3d8314 | String | Either | Room or player display name | `NASCAR Lobby` |
| `DESC` | 0x3d8318 | String | Either | Room description | `Official room` |
| `PASS` | 0x3e2fd8, 0x3e3460 | String | Either | Room password (empty if none) | (empty) |
| `PERS` | 0x3e3048, 0x3e3258 | String | Either | Persona name | `SpeedRacer42` |
| `HOST` | 0x3e3058 | String | Either | Room host identifier | `PlayerOne` |
| `OPPO` | 0x3e3060 | String | Either | Opponent identifier | `PlayerTwo` |
| `SELF` | 0x3e3050 | String | Either | Self-reference | `SpeedRacer42` |
| `SLOTS` | 0x3e3040 | String | Either | Available slots (e.g., `4/16`) | `4/16` |
| `PRIV` | 0x3d8390, 0x3d94e8 | Flag | Either | Private message flag | `1` |
| `TEXT` | 0x3d8388, 0x3d94e0 | String | Either | Chat text content | `Hello everyone!` |
| `ATTR` | 0x3d93a0 | String | Either | Room/player attributes | (key-value blob) |
| `EWBC` | 0x3d9388 | String | Either | Room-related field (unknown) | (unknown) |
| `BLOC` | 0x3d93b0 | Flag | Either | Block flag | `1` |
| `DECL` | 0x3d93c0 | Flag | Client → BS | Decline invitation | `1` |
| `ACPT` | 0x3d93c8 | Flag | Client → BS | Accept invitation | `1` |
| `CHAN` | 0x3e2ff8, 0x3d9138 | String | Either | Channel identifier | `lobby` |
| `FIND` | 0x3d9148 | String | Client → GS | Find/search query | `PlayerName` |
| `TITLE` | 0x3d9358 | String | Either | Room or game title | `NASCAR Race` |

### 5.7 User/Profile Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|
| `TYPE` | 0x3e3338 | String | Either | User type classification | `normal` |
| `BODY` | 0x3e3510 | String | Either | Message body text | `Join my race!` |
| `SUBJ` | 0x3e3518 | String | Either | Message subject | `Race Invite` |
| `FROM` | 0x3e3090 | String | BS → Client | Message sender | `PlayerOne` |
| `TIME` | 0x3e3008 | String | Either | Timestamp | `2003.7.2 14:30:00` |
| `SIZE` | 0x3e3520 | Integer | Either | Data size | `256` |
| `FUSR` | 0x3e3528 | String | Either | From-user identifier | `VTSTech/...` |
| `MAIL` | 0x3e3280 | String | Either | Email address | `user@example.com` |
| `SPAM` | 0x3e3288 | Flag | Either | Spam flag | `0` |
| `CPAT` | 0x3e3290 | String | Either | Chat pattern/mask | (pattern) |
| `ALTS` | 0x3e32a8 | String | Either | Alternate personas | (list) |
| `BORN` | 0x3e32b0 | String | Either | Birthday (registration) | `1990.1.15` |
| `GEND` | 0x3e32b8 | String | Either | Gender | `M` |
| `MINAGE` | 0x3e32c0 | Integer | Either | Minimum age filter | `13` |
| `PMAIL` | 0x3e32c8 | String | Either | Parent email (COPPA) | `parent@example.com` |
| `CHNG` | 0x3e32d0 | String | Either | Change/update indicator | (value) |
| `OPTS` | 0x3e32d8 | String | Either | User options/settings | (settings blob) |
| `CDEV` | 0x3e3260 | String | Either | Creation device | `PS2` |
| `PERSONAS` | 0x3e0410 | String | GS → Client | List of user's personas | (comma list) |

### 5.8 Status & Presence Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|
| `STAT` | 0x3d7a38 | String | Either | User connection status | `online` |
| `INFO` | 0x3d7a68 | String | Either | User info string | `SpeedRacer42 is online` |
| `SHOW` | 0x3e3498 | Integer | Either | Show/visibility status | `1` |
| `DISC` | 0x3e3460 | String | Either | Disconnect reason | `timeout` |
| `CHAT` | 0x3e3458 | String | Either | Chat message type indicator | `public` |
| `AWAY` | 0x3e3450 | String | Either | Away status | `afk` |
| `SEED` | 0x3e3098 | Integer | Either | Random seed value | `12345` |
| `WHEN` | 0x3e30a0 | String | Either | When/timestamp | `2003.7.2 14:30:00` |

### 5.9 Miscellaneous Protocol Keys

| Key | Address | Type | Direction | Purpose | Example Value |
|---|---|---|---|---|
| `IDENT` | 0x3e3160 | String | Either | Identity/token | (identifier) |
| `COUNT` | 0x3e3168 | Integer | Either | Count of items | `5` |
| `FLAGS` | 0x3e3180 | Integer | Either | Bit flags | `0x01` |
| `DIRECT` | 0x3e3010 | Flag | Either | Direct connection mode | `1` |
| `DOWN` | 0x3e3028 | String | Either | Download indicator | (url or id) |
| `MORE` | 0x3e3040 | Flag | GS → Client | More data follows | `1` |
| `@server` | 0x3e3000 | Prefix | GS → Client | Server-directed message prefix | `@server ...` |
| `bogus` | 0x3e2ff8 | Marker | Either | Bogus/error marker | `bogus` |
| `slogin` | 0x3e3380 | Method | Client → BS | Secure login method | `slogin` |
| `LIDENT` | 0x3e3148 | String | Either | Local identity | (local id) |
| `LCOUNT` | 0x3e3150 | Integer | Either | Local count | `3` |
| `LIST` | 0x3e34d8 | String | Either | Generic list data | (items) |
| `GROUP` | 0x3e3500 | String | Either | Buddy group name | `Friends` |
| `LRSC` | 0x3e34d0 | String | Either | Lobby resource | (resource id) |
| `RSRC` | 0x3e3490 | String | Either | Resource identifier | (resource id) |
| `DOMN` | 0x3e3488 | String | Either | Domain identifier | `easports.ea.com` |
| `PS2D` | 0x3e3388, 0x3e33a0 | String | Client → BS | PS2 device identifier | (device id) |

### 5.10 Hardware Identification Keys

| Key | Address | Type | Direction | Purpose | Notes |
|---|---|---|---|---|---|
| `HWFLAG` | 0x3d81a0 | Integer | Client → Dir | Hardware flag | PS2 hardware identification |
| `HWMASK` | 0x3d81a8 | Hex String | Client → Dir | Hardware mask | PS2 network adapter MAC or ID |

---

## 6. Server Response Format

### 6.1 Dir Server Response (Connection 1)

From emulated capture analysis, the Dir Server responds with a single message containing handoff credentials:

```
Message Type: resp (or keys, server-sent)

ADDR=10.0.0.1
PORT=10901
LKEY=a1b2c3d4e5f6
SESS=session_abc123
MASK=AE46F19A
```

| Field | Data Type | Description | Source |
|---|---|---|---|
| `ADDR` | Dotted-quad IP | GameServer address | Binary string (confirmed) |
| `PORT` | Integer string | GameServer TCP port | Binary string (confirmed) |
| `LKEY` | Hex string | Session authentication key | Binary string (confirmed) |
| `SESS` | Alphanumeric string | Session identifier | Binary string (confirmed) |
| `MASK` | Hex string | Network/hardware mask | Emulated capture value: `0xAE46F19A` |

### 6.2 GameServer Response (Connection 2)

The GameServer sends a multi-part response:

**Part A — Subscription Confirmation:**
```
ROOMS=1 USERS=1 RANKS=1 MESGS=1
```

This composite string (at 0x3e0370) confirms which data channels the client is subscribed to.

**Part B — BuddyServer Handoff:**
```
BUDDY_PORT=10899
BUDDY_URL=buddy.ea.com
```

**Part C — Room Data (pushed separately):**
```
ROOM=room_01
NAME=NASCAR Thunder 2004 Official
DESC=Welcome to NASCAR Thunder!
SLOTS=4/16
HOST=AdminPlayer
PASS=
```

**Part D — User List (pushed separately):**
```
USERS=12
PERS=SpeedRacer42
PERS=LeftTurnFan
PERS=DaleJr8
...
```

**Part E — Rank Data (pushed separately):**
```
RANKS=1
PERS=ChampionX
SEED=98765
...
```

### 6.3 BuddyServer Response (Connection 3)

The BuddyServer sends a persistent stream of messages:

**Initial Response — Login Confirmation:**
```
STAT=online
INFO=Logged in as SpeedRacer42
```

**Presence Updates (pushed):**
```
PRES: buddy=LeftTurnFan, show=1, prod=NASCAR, pres=online, lang=en
```

This matches the debug format at 0x3e2300:
```
PRES: buddy=%s, show=%d, prod=%s, pres=%s, lang=%s\n
```

**Chat Messages (pushed):**
```
FROM=LeftTurnFan
TEXT=Hey, want to race?
PRIV=0
TIME=2003.7.2 14:30:00
```

### 6.4 Response Timing Patterns

| Phase | Response Pattern | Notes |
|---|---|---|
| Dir Server | Single response, then close | Fast; no keepalive |
| GameServer | Initial response, then async pushes | May push room updates, user joins/leaves |
| BuddyServer | Continuous stream | Presence, chat, invitations pushed asynchronously |

### 6.5 Null Data / Binary Data Handling

The binary contains logging strings that reveal payload type classification:

| Debug String | Address | Meaning |
|---|---|---|
| `[null data]\n` | — | Empty or null payload received |
| `[binary data]\n` | — | Non-text payload (possibly embedded binary) |
| `[long data]\n` | — | Payload exceeds normal display length |

---

## 7. GameServer Protocol

### 7.1 Overview

The GameServer handles all room-based interactions: listing rooms, creating rooms, joining rooms, searching for players, and providing subscription data. It also hands off the BuddyServer connection info.

### 7.2 Room Operations

#### Creating a Room

Client sends:
```
NAME=My Race Room
DESC=Casual racing, all welcome
PASS=
SLOTS=8
```

Debug string at 0x3d8328: `"creating room"`

Server responds with:
```
ROOM=room_42
NAME=My Race Room
HOST=SpeedRacer42
SLOTS=1/8
```

#### Entering a Room

Client sends:
```
ROOM=room_42
```

Debug string at 0x3d8348: `"entering room"`

Server responds with room state:
```
ROOM=room_42
NAME=My Race Room
HOST=SpeedRacer42
SLOTS=2/8
PERS=SpeedRacer42
PERS=LeftTurnFan
```

#### Exiting a Room

Client sends:
```
ROOM=room_42
DISC=leave
```

Debug string at 0x3d8338: `"exiting room"`

#### Room Listing

The GameServer pushes room data after subscription:
```
ROOM=room_01
NAME=Official NASCAR Room
DESC=The official NASCAR Thunder lobby
SLOTS=4/16
HOST=AdminPlayer
PASS=

ROOM=room_02
NAME=Casual Races
DESC=For fun, no pressure
SLOTS=1/8
HOST=RacerBob
PASS=password123
```

### 7.3 Player Search

Debug string at 0x3d9360: `"searching for user"`

Client sends:
```
FIND=PlayerName
```

Server responds:
```
PERS=PlayerName
STAT=online
INFO=PlayerName is playing NASCAR Thunder 2004
```

Or if not found (from 0x3e0420):
```
STAT=none found
```

### 7.4 Matchmaking & Ranked Play

Debug string at 0x3d9c88: `"set_ranked"`

The client can request ranked matchmaking:
```
SEED=<random seed>
RANKS=1
```

The server responds with matched players or room assignment.

### 7.5 News/Announcements

Debug strings at 0x3c13b8, 0x3c1508: `"checking for news..."`

The `news` key (Connection 2 client key) likely triggers server-push news:
```
news=check
```

Server responds:
```
SUBJ=Server News
BODY=Welcome to NASCAR Thunder 2004 online!
TIME=2003.7.2 00:00:00
```

The placeholder at 0x3b91f0: `"News Placeholder"` suggests the server may return this when no news is available.

### 7.6 Challenge Registration

Debug string at 0x3d9400: `"registering challenge"`

The client can register a challenge (race invitation):
```
OPPO=LeftTurnFan
SEED=54321
ROOM=room_42
```

### 7.7 IP:Port Format

From 0x3c25d8 and 0x3d93e8:
```
%u.%u.%u.%u:%d
```

The GameServer may send direct connection addresses in this format (possibly for P2P handoff within the lobby context).

---

## 8. BuddyServer Protocol

### 8.1 Overview

The BuddyServer (also known as EASB — EA Sports Buddy) provides persistent presence, chat, friends list management, and game invitation functionality. The connection remains open for the entire online session.

### 8.2 Login

The BuddyServer login reuses the `LKEY` from the Dir Server for session continuity:

```
USER=VTSTech/cso/nascar-ps2-2004
PROD=NASCAR
VERS=2004
PRES=online
LKEY=<reused from Dir Server>
EASB=1
```

The `USER` key uses the **namespace format**: `VTSTech/cso/nascar-ps2-2004` where:
- `VTSTech` — EA account namespace prefix
- `/cso/nascar-ps2-2004` — Product-specific path (from 0x3d7978)

The `EASB=1` flag (from 0x3e33b0) indicates the client supports the EA Sports Buddy protocol extensions.

### 8.3 Presence System

The BuddyServer continuously pushes presence updates for buddies on the player's friends list.

#### Presence Update Format

From the debug string at 0x3e2300:
```
PRES: buddy=%s, show=%d, prod=%s, pres=%s, lang=%s\n
```

Server pushes:
```
PERS=LeftTurnFan
PRES=online
SHOW=1
PROD=NASCAR
INFO=LeftTurnFan is online
```

#### Presence States

| State | String (from binary) | Address | Meaning |
|---|---|---|---|
| Online | `"is online"` | 0x3d7968 | Buddy is connected |
| Offline | `"is offline"` | 0x3d7990 | Buddy disconnected |
| Playing | `"is playing"` | 0x3d89a8 | Buddy is in a game |
| Racing | `"is currently racing"` | 0x3d8a18 | Buddy is actively racing |
| In NASCAR | `"is playing NASCAR Thunder%s 2004"` | 0x3d89f0 | Buddy is in NASCAR Thunder (with possible subtitle `%s`) |

The format string at 0x3d89f0: `"is playing NASCAR Thunder%s 2004"` suggests the game may append a subtitle (e.g., "2004" becomes "NASCAR Thunder 2004").

#### Setting Own Presence

Client sends:
```
PRES=online
```

or:
```
PRES=away
AWAY=brb
```

### 8.4 Chat System

Lobby chat is text-based, using the buddy protocol. This is distinct from in-race binary chat (`ProtocolChatC`).

#### Public Chat (Room)

Client sends:
```
TEXT=Hello everyone!
CHAT=public
CHAN=lobby
```

Server broadcasts to all room members:
```
FROM=SpeedRacer42
TEXT=Hello everyone!
CHAT=public
TIME=2003.7.2 14:30:00
```

#### Private Chat (Direct Message)

Client sends:
```
TEXT=Hey, want to race?
PRIV=1
OPPO=LeftTurnFan
```

Server delivers to target:
```
FROM=SpeedRacer42
TEXT=Hey, want to race?
PRIV=1
TIME=2003.7.2 14:30:00
```

### 8.5 Friends List Management

#### Adding a Buddy

Client sends:
```
FIND=LeftTurnFan
GROUP=Friends
```

#### Buddy List Response

Server pushes buddy list:
```
LIST=3
PERS=LeftTurnFan
PRES=online
PERS=DaleJr8
PRES=offline
PERS=RacerBob
PRES=playing
```

### 8.6 Game Invitations

#### Sending an Invitation

Client sends:
```
OPPO=LeftTurnFan
BODY=Join my race room!
ROOM=room_42
SEED=54321
```

#### Receiving an Invitation

Server pushes:
```
FROM=RacerBob
SUBJ=Race Invitation
BODY=Join my race room!
ROOM=room_42
SEED=54321
TIME=2003.7.2 14:35:00
```

#### Responding to Invitations

Accept (from 0x3d93c8):
```
ACPT=1
ROOM=room_42
```

Decline (from 0x3d93c0):
```
DECL=1
```

### 8.7 Messaging (Mail-like)

The BuddyServer supports asynchronous messages:

```
FROM=AdminPlayer
SUBJ=Welcome!
BODY=Welcome to NASCAR Thunder 2004 Online!
TIME=2003.7.2 00:00:00
SIZE=42
```

### 8.8 Block/Accept User Management

Block (from 0x3d93b0):
```
BLOC=1
OPPO=AnnoyingPlayer
```

### 8.9 Channel Operations

The `CHAN` key (0x3e2ff8, 0x3d9138) may support channel-based chat rooms on the BuddyServer:

```
CHAN=lobby
TEXT=Hello!
```

---

## 9. Authentication System

### 9.1 Overview

The authentication system spans all three connections using a layered credential approach:

```
Dir Server ──issues──► LKEY + SESS + MASK
                              │
GameServer ◄──uses──────────┘
                              │
BuddyServer ◄──reuses───────┘
```

### 9.2 EA Login

The binary references `"EA Login"` (0x3d75d0) as the authentication system. The EA Login system handles user account credentials on the PS2.

The credential format (from 0x3d82e8):
```
%s:$%s     →    username:$token
```

This suggests the `auth` field sent to the GameServer contains the username and an authentication token separated by `:$`.

### 9.3 skey — Public Key Mechanism

| Property | Value |
|---|---|
| Key name | `skey` |
| Address | 0x3e3030 |
| String reference | `"Public Key"` at 0x3df2b8 |
| Hex table | 512-byte hex table at 0x3df2c8 |
| Sent value | `5075626c6963204b6579` |
| Decoded value | `Public Key` (ASCII) |

**This is NOT encryption.** The `skey` field sends the literal hex encoding of the ASCII string `"Public Key"`. The 512-byte hex table at 0x3df2c8 likely contains a static lookup table used for some form of challenge-response or session token derivation, but the actual mechanism is not yet reverse-engineered.

### 9.4 LKEY — Login Key

The `LKEY` (at 0x3e34c8) is issued by the Dir Server and reused across GameServer and BuddyServer connections. It serves as a session continuity token.

### 9.5 MASK — Hardware/Network Mask

| Property | Value |
|---|---|
| Key name | `MASK` |
| Address | 0x3e2fe0 |
| Observed value | `0xAE46F19A` (from emulated capture) |
| Related keys | `HWFLAG` (0x3d81a0), `HWMASK` (0x3d81a8) |

The `MASK` value is likely derived from the PS2's hardware identifier (network adapter MAC address or console ID). The related `HWFLAG` and `HWMASK` keys are used for PS2 hardware identification.

**Important:** The `MASK` value `0xAE46F19A` is NOT the same as the P2P crypto magic `0xFEFEFEFE`. These are completely different protocol layers.

### 9.6 Secure Login (slogin)

The `slogin` key (0x3e3380) references a secure login method used with the BuddyServer:

```
slogin=method
```

### 9.7 PS2 Device Identifier

The `PS2D` key (0x3e3388, 0x3e33a0) sends a PS2-specific device identifier, likely derived from the console's unique hardware ID.

---

## 10. Profanity Filter

### 10.1 Overview

NASCAR Thunder 2004 includes a client-side profanity filter for chat messages. The filter words are stored as plaintext strings in the binary and are applied to outgoing and/or incoming chat text.

### 10.2 Filter Word List

The following profanity filter words were extracted from the binary:

| # | Word | Notes |
|---|---|---|
| 1 | `PISS` | Profanity |
| 2 | `FUCK` | Strong profanity |
| 3 | `SHIT` | Profanity |
| 4 | `COCK` | Profanity |
| 5 | `PUSSY` | Strong profanity |
| 6 | `TWAT` | Profanity |
| 7 | `BITCH` | Profanity |
| 8 | `CUNT` | Strong profanity |
| 9 | `DICK` | Profanity |
| 10 | `LESBIAN` | Sexual term |
| 11 | `MUFF` | Sexual term |
| 12 | `RIMJOB` | Sexual term |
| 13 | `RAPE` | Sexual violence |
| 14 | `JERKOFF` | Sexual term |
| 15 | `TESTICLES` | Anatomical |
| 16 | `PENIS` | Anatomical |
| 17 | `JIZZ` | Sexual term |
| 18 | `TITS` | Anatomical |
| 19 | `NIGG` | Racial slur prefix (likely catches `NIGGER`, `NIGGA`, etc.) |

### 10.3 Filter Behavior

The profanity filter likely:
1. Scans all outgoing chat text (`TEXT` values) before sending
2. May replace matched words with asterisks or block the message
3. The `CPAT` (chat pattern, 0x3e3290) key may be related to filter patterns
4. The `SPAM` (spam flag, 0x3e3288) key may be set when a message triggers the filter

---

## 11. Network State Machine

### 11.1 State Definitions

The game's network subsystem implements a linear state machine with the following states, found in the `.rodata` string area around 0x3d8568:

```
┌──────────────────────────────────────────────────────────────────────┐
│                    NASCAR Thunder 2004 — Network State Machine       │
│                                                                      │
│  ┌───────────────┐                                                  │
│  │ Network       │   Initial state; network subsystem not started   │
│  │ Offline       │                                                  │
│  └───────┬───────┘                                                  │
│          │  [User selects "Online" from menu]                        │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Network       │   PS2 network adapter initialized                │
│  │ Started       │                                                  │
│  └───────┬───────┘                                                  │
│          │  [Network adapter ready]                                  │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Network       │   Querying network configuration (DHCP/PPPoE)   │
│  │ Querying      │                                                  │
│  └───────┬───────┘                                                  │
│          │  [Config obtained]                                        │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Network       │   Establishing ISP connection (dial-up/BB)       │
│  │ IspConnect    │                                                  │
│  └───────┬───────┘                                                  │
│          │  [ISP connection established]                             │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Network       │   Internet connectivity confirmed                │
│  │ Online        │                                                  │
│  └───────┬───────┘                                                  │
│          │  [User initiates game connection]                         │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Network       │   Connecting to Dir Server (TCP:10600)           │
│  │ Connecting    │                                                  │
│  │ Game          │                                                  │
│  └───────┬───────┘                                                  │
│          │  [Dir Server → GameServer handoff complete]               │
│          ▼                                                          │
│  ┌───────────────┐                                                  │
│  │ Network       │   Connected to GameServer, in lobby              │
│  │ Lobby         │                                                  │
│  └──┬────────┬───┘                                                  │
│     │        │                                                      │
│     │        │  [User joins/hosts race]                              │
│     │        ▼                                                      │
│     │  ┌───────────────┐                                            │
│     │  │ Network       │  Connected as game server (host)           │
│     │  │ GameServer    │                                            │
│     │  └───────────────┘                                            │
│     │                                                              │
│     │  [User joins race as client]                                  │
│     │  ┌───────────────┐                                            │
│     │  │ Network       │  Connected as game client                  │
│     │  │ GameClient    │                                            │
│     │  └───────────────┘                                            │
│     │                                                              │
│     │  [Race ends / user returns to lobby]                          │
│     └──┘                                                            │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 11.2 State Transition Table

| From State | To State | Trigger | Protocol Action |
|---|---|---|---|
| Offline | Started | User selects "Online" | Initialize PS2 network adapter |
| Started | Querying | Adapter ready | DHCP/PPPoE configuration query |
| Querying | IspConnect | Config obtained | Establish ISP connection |
| IspConnect | Online | ISP connected | Internet connectivity confirmed |
| Online | Connecting Game | User initiates | TCP connect to Dir Server :10600 |
| Connecting Game | Lobby | Dir Server handoff | Connect to GameServer, then BuddyServer |
| Lobby | GameServer | Host race | P2P race server setup |
| Lobby | GameClient | Join race | P2P race client connection |
| GameServer | Lobby | Race ends | Return to lobby |
| GameClient | Lobby | Race ends / disconnect | Return to lobby |
| (Any) | Offline | Error / user cancel | Tear down all connections |

### 11.3 Connection Timeout

From the binary:
```
"server ICMP timeout\n"
```

If the server does not respond, the client generates an ICMP timeout error and may transition back to `Connecting Game` or `Online` state for retry.

### 11.4 Disconnect Handling

From the binary (0x3b73a8):
```
"disconnected. Please reconnect to continue."
```

When a connection drops unexpectedly, the client displays this message and may attempt automatic reconnection or prompt the user.

---

## 12. Client-Side Class Map

### 12.1 Lobby Layer Class Hierarchy

The following classes are identified from `.rodata` vtable and RTTI analysis. These are **lobby-layer only** — race/P2P classes are excluded.

| Priority | Class Name | Purpose | Protocol Scope |
|---|---|---|---|
| 10 | `FGNetworkC` | Base flow group for network state machine | All network states |
| 11 | `FMNetLobbyC` | Lobby/room management module | Room operations, user list |
| 12 | `FMNetOnlineC` | Online state machine controller | Connection state transitions |
| 15 | `FlowModuleEASBC` | EA Sports Buddy integration module | BuddyServer protocol |
| 18 | `FlowModuleUISChatC` | In-game chat UI (lobby variant) | Lobby chat display/input |
| 21 | `FlowModuleUISChatC` | In-game chat UI (alternate variant) | Lobby chat display/input |
| 25a | `FMNetworkGameConnectionsC` | Connection manager | TCP connection lifecycle |
| 25b | `FlowModuleNetworkProtocolC` | Protocol dispatch/router | KV message parsing/handling |
| 26 | `FlowModuleNetworkQualifyC` | Qualifying module | Ranked match qualification |
| 27 | `ProtocolRaceWeekendSessionC` | Race weekend session | Multi-session race events |
| 34 | `FlowModuleNetworkConnectionEscrowC` | Transactional connection manager | Atomic connection operations |

### 12.2 Class Responsibilities

#### FGNetworkC (Priority 10)
Base flow group managing the overall network state machine transitions. Owns the state progression from Offline through Lobby.

#### FMNetLobbyC (Priority 11)
Handles room listing, creation, joining, exiting, and user searching within the lobby. Parses `ROOM`, `NAME`, `DESC`, `SLOTS`, `HOST`, `FIND` keys.

#### FMNetOnlineC (Priority 12)
Drives the connection chain: Dir Server → GameServer → BuddyServer. Manages `ADDR`, `PORT`, `LKEY`, `SESS`, `MASK`, `BUDDY_PORT`, `BUDDY_URL`.

#### FlowModuleEASBC (Priority 15)
Implements the EA Sports Buddy protocol: presence, friends list, chat, invitations. Parses `USER`, `PRES`, `SHOW`, `TEXT`, `PRIV`, `FROM`, `ACPT`, `DECL`, `BLOC`, `GROUP`.

#### FlowModuleNetworkProtocolC (Priority 25b)
Core protocol dispatcher. Parses the 12-byte binary header, extracts the 4-char type and subtype, routes KV payloads to appropriate handlers. Contains the recv logging at 0x3df250.

#### FlowModuleNetworkConnectionEscrowC (Priority 34)
Manages transactional connection operations — ensuring atomic connect/disconnect sequences across the 3-server chain.

### 12.3 Excluded Classes

The following classes found in the binary are **NOT** part of the lobby protocol:

| Class | Reason |
|---|---|
| `ProtocolChatC` | In-race P2P binary chat (UDP) |
| Any P2P/car sync classes | UDP racing protocol |
| `FlowModuleNetworkProtocolC` race handlers | Race state, not lobby state |

---

## 13. Debug Strings Reference

### 13.1 Connection Logging

| String | Address | Format | Purpose |
|---|---|---|---|
| `connecting to %08x:%d\n` | 0x3df238, 0x3e22e8 | IP as hex, port decimal | TCP connection attempt log |
| `recv: %c%c%c%c/%c%c%c%c\n` | 0x3df250 | 4-char type / 4-char subtype | Incoming message classification |

### 13.2 Payload Type Logging

| String | Meaning |
|---|---|
| `[null data]\n` | Received empty/null payload |
| `[binary data]\n` | Received non-text (binary) payload |
| `[long data]\n` | Received oversized payload |

### 13.3 Error/Status Logging

| String | Context |
|---|---|
| `server ICMP timeout\n` | Server unreachable or no response |
| `disconnected. Please reconnect to continue.` | Connection lost (0x3b73a8) |
| `The Server is currently down for maintenance. Please try again later.` | Server maintenance message (0x3e0430) |
| `PSCD10088` | Server error code (0x3e04e0) |
| `none found` | Search returned no results (0x3e0420) |
| `Required` | Required field missing (0x3e03e8) |

### 13.4 Presence Debug Logging

| String | Address | Format |
|---|---|---|
| `PRES: buddy=%s, show=%d, prod=%s, pres=%s, lang=%s\n` | 0x3e2300 | Buddy presence update debug |

### 13.5 UI/State Strings

| String | Address | Context |
|---|---|---|
| `creating room` | 0x3d8328 | Room creation UI state |
| `entering room` | 0x3d8348 | Room join UI state |
| `exiting room` | 0x3d8338 | Room leave UI state |
| `searching for user` | 0x3d9360 | User search UI state |
| `registering challenge` | 0x3d9400 | Challenge registration UI state |
| `checking for news...` | 0x3c13b8, 0x3c1508 | News check UI state |
| `is online` | 0x3d7968 | Buddy online status |
| `is offline` | 0x3d7990 | Buddy offline status |
| `is playing` | 0x3d89a8 | Buddy in-game status |
| `is currently racing` | 0x3d8a18 | Buddy racing status |
| `is playing NASCAR Thunder%s 2004` | 0x3d89f0 | Buddy in NASCAR status (%s = subtitle) |
| `set_ranked` | 0x3d9c88 | Ranked match toggle |
| `News Placeholder` | 0x3b91f0 | Default news content |

### 13.6 Format Strings

| String | Address | Purpose |
|---|---|---|
| `%s:$%s` | 0x3d82e8 | Auth credential formatting (username:$token) |
| `%u.%u.%u.%u:%d` | 0x3c25d8, 0x3d93e8 | IP:port parsing/formatting |
| `%d.%d.%d %d:%02d:%02d` | 0x3dfd48 | Date/time formatting (YYYY.MM.DD HH:MM:SS) |

### 13.7 Protocol Identifiers

| String | Address | Context |
|---|---|---|
| `/cso/nascar-ps2-2004` | 0x3d7978 | Product namespace for USER key |
| `ps2nascar04.ea.com` | 0x3d8bf8 | Dir Server hostname |
| `BASLUS-20824` | Multiple | Disc identifier (multiple locations) |
| `NASCAR` | 0x3d9280 | Product name |
| `2004` | 0x3d9298 | Version string |
| `EASB` | — | EA Sports Buddy identifier |
| `EA Login` | 0x3d75d0 | Authentication system name |
| `Public Key` | 0x3df2b8 | skey mechanism label |
| `ROOMS=1 USERS=1 RANKS=1 MESGS=1` | 0x3e0370 | Default subscription string |

---

## 14. Error Codes & Messages

### 14.1 Server Error Codes

| Code/String | Address | Meaning | Severity |
|---|---|---|---|
| `PSCD10088` | 0x3e04e0 | Server error code | Fatal — connection terminated |
| `bogus` | 0x3e2ff8 | Bogus/invalid data marker | Warning — data ignored |
| `server ICMP timeout\n` | — | Server unreachable | Fatal — timeout |

### 14.2 Server Maintenance

| Message | Address | Context |
|---|---|---|
| `The Server is currently down for maintenance. Please try again later.` | 0x3e0430 | Server maintenance mode |

### 14.3 Client Error States

| Message | Address | Context |
|---|---|---|
| `disconnected. Please reconnect to continue.` | 0x3b73a8 | Unexpected disconnect |
| `none found` | 0x3e0420 | Search returned empty |
| `Required` | 0x3e03e8 | Mandatory field missing from request |

### 14.4 Error Handling Flow

```
Client receives error
    │
    ├── PSCD10088 ──► Display error, return to Online state
    ├── server ICMP timeout ──► Retry connection or return to Online state
    ├── maintenance message ──► Display maintenance notice, return to menu
    ├── bogus ──► Log warning, ignore malformed data
    ├── none found ──► Display "no results" in search UI
    └── Required ──► Reject request, prompt for missing field
```

---

## 15. Data Sources & Methodology

### 15.1 Analysis Methods

This document was produced using two complementary analysis approaches:

| Method | Tool | Output | Coverage |
|---|---|---|---|
| Static binary analysis | radare2 | String extraction, RTTI, vtable analysis | Protocol vocabulary, class hierarchy, debug strings |
| Emulated capture | Network emulation/proxy | Wire captures | Message formats, field values, timing |

### 15.2 Confidence Levels

| Level | Marker | Meaning |
|---|---|---|
| **Confirmed** | Binary string at known address | String exists in binary; purpose inferred from context |
| **Confirmed (capture)** | Observed in emulated network capture | Actual wire data from running game |
| **Inferred** | Logical deduction from binary structure | Likely correct but not directly observed |
| **Speculative** | Educated guess based on EA protocol patterns | Needs verification |

### 15.3 Confidence by Section

| Section | Primary Source | Confidence | Notes |
|---|---|---|---|
| Wire format (header) | Binary analysis | **Confirmed** | 12-byte header structure verified |
| Wire format (payload) | Binary analysis + capture | **Confirmed** | KV format verified from both sources |
| Dir Server keys | Binary strings | **Confirmed** | All 4 client keys at known addresses |
| Dir Server response | Capture + binary | **Confirmed** | ADDR/PORT/LKEY/SESS/MASK verified |
| GameServer keys | Binary strings | **Confirmed** | skey/auth/pers/sele at known addresses |
| GameServer response | Binary strings + capture | **Confirmed** | Subscription string, BUDDY_* keys |
| BuddyServer keys | Binary strings | **Confirmed** | USER/PROD/VERS/PRES/LKEY/EASB at known addresses |
| BuddyServer responses | Binary strings + format analysis | **Inferred** | Presence/chat format from debug strings |
| Room operations | Binary strings | **Inferred** | Operation names confirmed, exact protocol flow inferred |
| skey mechanism | Binary analysis | **Confirmed** | Hex value decoded to "Public Key" |
| MASK value | Capture only | **Confirmed (capture)** | `0xAE46F19A` from emulated capture |
| Profanity filter | Binary strings | **Confirmed** | Word list extracted directly |
| State machine | Binary strings | **Confirmed** | State names in order at 0x3d8568 |
| Class hierarchy | RTTI/vtable analysis | **Confirmed** | Class names and priorities from RTTI |
| Message type codes | Debug strings | **Inferred** | 4-char types inferred from recv format |
| Error codes | Binary strings | **Confirmed** | Error strings at known addresses |

### 15.4 Known Gaps

| Gap | Description | How to Resolve |
|---|---|---|
| Exact message type codes | Only `keys`/`resp`/`mesg`/`pres` inferred; full type list unknown | Capture more traffic from emulated sessions |
| skey 512-byte table | Hex table at 0x3df2c8 not fully analyzed | Dump and analyze the 512-byte table |
| GameServer push format | Room/user/rank push message format partially known | Capture GameServer responses during room operations |
| BuddyServer full protocol | Invitation, buddy list add/remove details incomplete | Capture BuddyServer traffic during social operations |
| P2P handoff | How lobby transitions to P2P racing not documented | Capture the full connection sequence through race start |
| KEEPALIVE format | ~~Ping/pong keepalive format unknown~~ | ✅ RESOLVED: `~png` with TIME, SESS, NAME, STATUS. Server sends every 20s. TREF field does NOT exist in binary. Game only checks message type, does not parse TREF/SESS/NAME/STATUS. |
| Authentication flow | Exact derivation of `auth` token from EA Login unknown | Trace authentication code path in disassembly |
| MASK derivation | How `0xAE46F19A` is generated from PS2 hardware unknown | Trace hardware ID code path |

### 15.5 Binary Reference

| Property | Value |
|---|---|
| File | NASCAR.ELF (SLUS-20824) |
| Platform | PlayStation 2 |
| Build date | Jul 2 2003 |
| Analysis tool | radare2 |
| Key sections | `.sdata` (protocol keys), `.rodata` (debug strings, class RTTI) |
| Key address ranges | 0x3d7xxx–0x3e3xxx (protocol vocabulary), 0x3c1xxx (config strings) |

---

## Appendix A: Quick Reference — Connection Cheat Sheet

### Connection 1: Dir Server (TCP:10600)

```
SEND:                        RECV:
─────                        ─────
PROD=NASCAR                  ADDR=<GameServer IP>
VERS=2004                    PORT=<GameServer port>
LANG=en                      LKEY=<session key>
SLUS=BASLUS-20824            SESS=<session id>
                             MASK=<hardware mask>
```

### Connection 2: GameServer (TCP:<from Dir>)

```
SEND:                        RECV:
─────                        ─────
skey=5075626c6963204b6579    ROOMS=1 USERS=1 RANKS=1 MESGS=1
addr=<client IP>             BUDDY_PORT=<buddy port>
auth=<username:$token>       BUDDY_URL=<buddy host>
pers=<persona>               [+ room data pushes]
sele=<selection>             [+ user list pushes]
```

### Connection 3: BuddyServer (TCP:<from GS>)

```
SEND:                        RECV:
─────                        ─────
USER=VTSTech/cso/nascar-ps2-2004    STAT=online
PROD=NASCAR                        [+ presence pushes]
VERS=2004                          [+ chat message pushes]
PRES=online                        [+ invitation pushes]
LKEY=<reused from Dir>
EASB=1
```

---

## Appendix B: Key Address Cross-Reference

### .sdata Section Protocol Keys

| Address | Key | Category |
|---|---|---|
| 0x3d7968 | `"is online"` | Presence status string |
| 0x3d7990 | `"is offline"` | Presence status string |
| 0x3d7a38 | `STAT` | Status key |
| 0x3d7a68 | `INFO` | Info key |
| 0x3d7978 | `"/cso/nascar-ps2-2004"` | User namespace |
| 0x3d81a0 | `HWFLAG` | Hardware identification |
| 0x3d81a8 | `HWMASK` | Hardware mask |
| 0x3d8314 | `NAME` | Room/player name |
| 0x3d8318 | `DESC` | Room description |
| 0x3d8328 | `"creating room"` | UI state string |
| 0x3d8338 | `"exiting room"` | UI state string |
| 0x3d8348 | `"entering room"` | UI state string |
| 0x3d8380 | `ROOM` | Room ID |
| 0x3d8388 | `TEXT` | Chat text |
| 0x3d8390 | `PRIV` | Private message |
| 0x3d89a8 | `"is playing"` | Presence status string |
| 0x3d8a18 | `"is currently racing"` | Presence status string |
| 0x3d8a70 | `ADDR` | GameServer address |
| 0x3d8bf8 | `"ps2nascar04.ea.com"` | DNS hostname |
| 0x3d9138 | `CHAN` | Channel |
| 0x3d9148 | `FIND` | Search |
| 0x3d9280 | `"NASCAR"` | Product name |
| 0x3d9298 | `"2004"` | Version |
| 0x3d9358 | `TITLE` | Title |
| 0x3d9360 | `"searching for user"` | UI state string |
| 0x3d9388 | `EWBC` | Room-related |
| 0x3d93a0 | `ATTR` | Attributes |
| 0x3d93b0 | `BLOC` | Block |
| 0x3d93c0 | `DECL` | Decline |
| 0x3d93c8 | `ACPT` | Accept |
| 0x3d93e8 | `"%u.%u.%u.%u:%d"` | IP:port format |
| 0x3d9400 | `"registering challenge"` | UI state string |
| 0x3d94e0 | `TEXT` | Chat text (alt ref) |
| 0x3d94e8 | `PRIV` | Private message (alt ref) |
| 0x3d9c88 | `"set_ranked"` | Ranked match |
| 0x3d75d0 | `"EA Login"` | Auth system |
| 0x3d82e8 | `"%s:$%s"` | Auth credential format |
| 0x3d89f0 | `"is playing NASCAR Thunder%s 2004"` | Game presence |

### .sdata Section (continued, 0x3e range)

| Address | Key | Category |
|---|---|---|
| 0x3e0410 | `PERSONAS` | Persona list |
| 0x3e0420 | `"none found"` | No results |
| 0x3e0430 | `"The Server is currently down..."` | Maintenance |
| 0x3e04e0 | `"PSCD10088"` | Error code |
| 0x3e0370 | `"ROOMS=1 USERS=1 RANKS=1 MESGS=1"` | Subscription |
| 0x3e03e8 | `"Required"` | Required field |
| 0x3e2f80 | `NAME` | Name (alt ref) |
| 0x3e2f90 | `ADDR` | Address (alt ref) |
| 0x3e2fa8 | `VERS` | Version (alt ref) |
| 0x3e2fb0 | `ROOMS=` | Room subscription |
| 0x3e2fb8 | `RANKS=` | Rank subscription |
| 0x3e2fc0 | `USERS=` | User subscription |
| 0x3e2fd8 | `PASS` | Password |
| 0x3e2fe0 | `MASK` | Hardware mask |
| 0x3e2ff8 | `CHAN` / `bogus` | Channel / error marker |
| 0x3e3000 | `@server` | Server prefix |
| 0x3e3008 | `TIME` | Timestamp |
| 0x3e3010 | `DIRECT` | Direct mode |
| 0x3e3018 | `PORT` | Port |
| 0x3e3020 | `SESS` | Session |
| 0x3e3028 | `DOWN` | Download |
| 0x3e3030 | `skey` | Security key |
| 0x3e3040 | `SLOTS` / `MORE` | Slots / more data |
| 0x3e3048 | `PERS` | Persona |
| 0x3e3050 | `SELF` | Self reference |
| 0x3e3058 | `HOST` | Host |
| 0x3e3060 | `OPPO` | Opponent |
| 0x3e3090 | `FROM` | Message sender |
| 0x3e3098 | `SEED` | Seed value |
| 0x3e30a0 | `WHEN` | When timestamp |
| 0x3e3148 | `LIDENT` | Local identity |
| 0x3e3150 | `LCOUNT` | Local count |
| 0x3e3160 | `IDENT` | Identity |
| 0x3e3168 | `COUNT` | Count |
| 0x3e3180 | `FLAGS` | Flags |
| 0x3e3258 | `PERS` | Persona (alt ref) |
| 0x3e3260 | `CDEV` | Creation device |
| 0x3e3280 | `MAIL` | Email |
| 0x3e3288 | `SPAM` | Spam flag |
| 0x3e3290 | `CPAT` | Chat pattern |
| 0x3e32a8 | `ALTS` | Alternates |
| 0x3e32b0 | `BORN` | Birthday |
| 0x3e32b8 | `GEND` | Gender |
| 0x3e32c0 | `MINAGE` | Minimum age |
| 0x3e32c8 | `PMAIL` | Parent email |
| 0x3e32d0 | `CHNG` | Change |
| 0x3e32d8 | `OPTS` | Options |
| 0x3e3330 | `USER` | Username |
| 0x3e3338 | `TYPE` | User type |
| 0x3e3380 | `slogin` | Secure login |
| 0x3e3388 | `PS2D` | PS2 device |
| 0x3e33a0 | `PS2D` | PS2 device (alt ref) |
| 0x3e33b0 | `EASB` | EA Sports Buddy |
| 0x3e3450 | `AWAY` | Away status |
| 0x3e3458 | `CHAT` | Chat type |
| 0x3e3460 | `DISC` / `PASS` | Disconnect / Password |
| 0x3e3488 | `DOMN` | Domain |
| 0x3e3490 | `RSRC` | Resource |
| 0x3e3498 | `SHOW` | Show status |
| 0x3e34a0 | `PROD` | Product (BuddyServer) |
| 0x3e34b8 | `VERS` | Version (BuddyServer) |
| 0x3e34c0 | `PRES` | Presence |
| 0x3e34c8 | `LKEY` | Login key |
| 0x3e34d0 | `LRSC` | Lobby resource |
| 0x3e34d8 | `LIST` | List |
| 0x3e3500 | `GROUP` | Buddy group |
| 0x3e3510 | `BODY` | Message body |
| 0x3e3518 | `SUBJ` | Message subject |
| 0x3e3520 | `SIZE` | Size |
| 0x3e3528 | `FUSR` | From user |
| 0x3e31c8 | `PROD` | Product (Dir Server) |
| 0x3e31d0 | `VERS` | Version (Dir Server) |
| 0x3e31d8 | `LANG` | Language |
| 0x3e31e0 | `SLUS` | Disc identifier |

### .rodata Section

| Address | Content | Purpose |
|---|---|---|
| 0x3b73a8 | `"disconnected. Please reconnect..."` | Disconnect message |
| 0x3b91f0 | `"News Placeholder"` | Default news |
| 0x3c13b8 | `"checking for news..."` | News check |
| 0x3c1508 | `"checking for news..."` | News check (alt) |
| 0x3c1520 | `BUDDY_PORT` | Buddy port key |
| 0x3c25d8 | `"%u.%u.%u.%u:%d"` | IP:port format |
| 0x3d8568+ | Network state names | State machine |
| 0x3df238 | `"connecting to %08x:%d\n"` | Connection log |
| 0x3df250 | `"recv: %c%c%c%c/%c%c%c%c\n"` | Receive log |
| 0x3df2b8 | `"Public Key"` | skey label |
| 0x3df2c8 | 512-byte hex table | Key lookup table |
| 0x3dfd48 | `"%d.%d.%d %d:%02d:%02d"` | Date format |
| 0x3e0410 | `PERSONAS` | Persona list |
| 0x3e22e8 | `"connecting to %08x:%d\n"` | Connection log (alt) |
| 0x3e2300 | `"PRES: buddy=%s, show=%d..."` | Presence debug |

---

## Appendix C: Emulated Capture — Observed MASK Value

| Property | Value |
|---|---|
| Observed MASK | `0xAE46F19A` |
| Source | Emulated network capture |
| Context | Dir Server response, Connection 1 |
| NOT equivalent to | P2P crypto magic `0xFEFEFEFE` |
| Likely derivation | PS2 hardware identifier (MAC/console ID) |

---

*Document generated for NASCAR Thunder 2004 (PS2, SLUS-20824) reverse engineering project.*
*Protocol analysis based on radare2 static binary analysis and emulated network capture.*
