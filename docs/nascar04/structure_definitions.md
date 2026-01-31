# Internal Structures

## 1. User Object (LobbyUser)
Created via `+usr` and stored in the `HashTable`.

| Offset | Tag | Type | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | `I` | int | User ID (Key). |
| `0x02` | `N` | string | Persona Name. |
| `0x0C` | `A` | int | IP Address (Integer). |
| `0x0D` | `R` | int | Room ID. |
| `0x0E` | `S` | string | Status text ("Online"). |
| `0x2E` | `X` | string | Extra text. |

## 2. Room Object
Created via `+rom`.

| Offset | Tag | Type | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | `I` | int | Room ID. |
| `0x07` | `N` | string | Room Name. |
| `0x0F` | `H` | string | Host Name. |
| `0x19` | `A` | int | Host IP Address. |

Global Connection Context (piVar24)

The following offsets are critical for state tracking and were corrected based on the LobbyApiUpdate loop:  

    0x04: Tick Counter (Current system time + 60,000 for timeouts).

    0x05: Last Event Timestamp (Used to detect 5s timeout).

    0x4D: Authenticated Username (String copy from auth command).

    0x5D: Active Persona Name (String copy from pers or +who commands).

    0x6E: Current Room ID (Integer retrieved from move or +who).

    0x70: Current Room Name (String copy).

    0x12E: Session ID (10-digit numeric).

    0x141: "More" Flag (Indicates if further sele results are available).

    0x142: Active Broadcast Channel (Extracted from snap command).

    0x14D: Play Callback Pointer (Executed during +ses transition). 