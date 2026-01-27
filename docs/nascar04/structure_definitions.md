# VTSTech NASCAR 2004 Network Engine Specification
**Version:** 1.0 (Modular Engine Rev)
**Target:** PlayStation 2 / MIPS Memory Mapping

---

## I. LOBBY CONTEXT STRUCTURE
**Size:** 0x540 (1344 bytes)  
**Primary Object:** Managed by the AresSocket/Lobby handler.

| OFFSET | TYPE | NAME | DESCRIPTION |
| :--- | :--- | :--- | :--- |
| **0x00** | void* | socket_handle | Pointer to active AresSocket object. |
| **0x08** | int | flags | **CRITICAL:** State bitmask. `0x400` = In-Game. |
| **0x0C** | int | state_id | 4-char ASCII State (e.g., `IDLE`, `AUTH`). |
| **0x1C** | int | ping_interval | Latency delay requested by server. |
| **0x30** | byte[16] | rc4_key | 128-bit session key (from `skey`). |
| **0x40** | int | key_flags | Status of key (0=Plain, 1=Encrypted). |
| **0x44** | char[64] | username | Logged-in Username (`USER=` in auth). |
| **0x84** | char[64] | persona | Current active Persona (`PERS=`). |
| **0xC4** | int | room_id | Current active room ID (Numeric). |
| **0xD4** | void* | user_table | Ptr to HashTable (ID -> UserEntry). |
| **0xF4** | char[256]| server_info | Metadata cache from `@dir` and `news`. |
| **0x1F4** | char[16] | session_id | String representation of 13-digit `SESS`. |
| **0x2B0** | byte[272]| session_data | **THE BLOB:** Binary parameters for the race. |
| **0x3C0** | int | auth_state | Handshake progress (Target: 3). |
| **0x400** | void* | buddy_ptr | Pointer to secondary Buddy Context. |
| **0x500** | void* | msg_callback | Function ptr for incoming `mesg` processing. |

---

## II. SESSION DATA BLOB (+ses)
**Size:** 272 bytes (0x110)  
**Location:** Sub-structure starting at LobbyContext + `0x2B0`.



| OFFSET | TYPE | NAME | DESCRIPTION |
| :--- | :--- | :--- | :--- |
| **0x00** | int | host_id | Numeric User ID of the race host. |
| **0x04** | int | sess_id_high | 13-digit `SESS` high word. |
| **0x08** | int | sess_id_low | 13-digit `SESS` low word. |
| **0x18** | short | track_id | Track Index (e.g., 0=Daytona, 9=NY). |
| **0x1A** | short | lap_count | Number of laps (Big Endian). |
| **0x1C** | byte | difficulty | 0=Rookie, 1=Pro, 2=Veteran. |
| **0x20** | char[32] | host_name | Persona string of the host. |
| **0x30** | uint32 | host_ip | **CRITICAL:** Public IP of Host for UDP. |
| **0x44** | uint16 | host_port | UDP Port (Default: 11000). |
| **0x46** | byte | ai_count | Number of AI drivers (extracted from token). |
| **0x50** | byte[192]| ext_data | Rules (Damage, Yellows, Car IDs). |

---

## III. USER ENTRY STRUCTURE
**Allocation:** Managed in Pool by `user_table` (LobbyContext + `0xD4`).

| OFFSET | TYPE | NAME | DESCRIPTION |
| :--- | :--- | :--- | :--- |
| **0x00** | int | id | Unique ID from server (`I=`). |
| **0x04** | char[32] | persona | Player name shown in lobby. |
| **0x24** | int | flags | `F=` mask. `0x4` = Currently In-Race. |
| **0x28** | uint32 | ip_addr | Cached IP address of this user. |
| **0x2C** | int | ping_ms | Calculated round-trip time. |

---

## IV. STATE FLOW LOGIC

1. **Discovery:** Client reads `BUDDY_URL` from `news` command.
2. **Buddy Handshake:** Client connects to Port 10899. Server must respond with `STATUS=0` and `RGET`.
3. **Challenge Initiation:** Host sends `mesg` with token (e.g., `wf9xu_a017l_g`) to Target.
4. **Acceptance:** Target responds with `mesg` where `TEXT=ACPT`.
5. **Session Push:** Server pushes the raw binary **+ses** packet (272 bytes) to both parties.
6. **Engine Transition:** PS2 firmware sets LobbyContext `+0x08` to `0x400`. 
   - TCP Socket is kept alive for heartbeat.
   - UDP Socket is opened on Port `11000` to the IP at `SessionBlob + 0x30`.