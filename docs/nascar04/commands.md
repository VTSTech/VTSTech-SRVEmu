# **Aries Protocol: Command and Parameter Specification**

This document serves as the authoritative reference for the 4-character command codes and their associated tag-value parameters used in the Aries Lobby and Buddy systems.

## ---

**1\. Connection and Handshake Commands**

Used during the initial session establishment and redirection phases.

| Command | Direction | Tags / Parameters | Functional Description |
| :---- | :---- | :---- | :---- |
| **@dir** | S → C | ADDR, PORT, SESS, MASK, DOWN, DIRECT | **Director Redirect:** Provides the target lobby server address and initial session metadata. 1 |
| **addr** | C → S | ADDR, PORT | **Address Acknowledge:** Sent by the client to confirm connection to the redirected node. 1 |
| **skey** | C ↔ S | SKEY | **Security Key:** Establishes XOR obfuscation key. Use SKEY=0 for plaintext. 1 |
| **acct** | C → S | NAME,MAIL,SPAM,CPAT,TOS | **Account Creation:** Creates an account that can be saved to the Memory Card.  |
| **auth** | C → S | NAME, PASS, TOS, MYip, ADDR | **Authentication:** Submits credentials and accepts Terms of Service. 1 |
| **news** | C → S | NAME=1 (respond news new1 sub cmd) | **News Request:** Requests the Message of the Day or Buddy server connection details. 1 |
| **edit** | C → S | NAME, MAIL, SPAM | **Account Edit:** Modifies existing account or persona metadata. (Dispatcher Case 0xa5).  |

## ---

**2\. Lobby & Room Management Commands**

These commands synchronize the state of users and rooms within the active lobby channel.

| Command | Direction | Tags / Parameters | Functional Description |
| :---- | :---- | :---- | :---- |
| **\+usr** | S → C | I, N, A, P, F, S, R, X, T | **User Sync:** Adds/updates a user in the local HashTable. (ID, Name, IP, Status, Room, Extra). 1 |
| **\+rom** | S → C | I, N, H, F, A, T, L, P | **Room Sync:** Updates room list (ID, Name, Host, Flags, IP, Type, Latency, Pop). 1 |
| **\+who** | S → C | N, F, RI, RT, R, RF | **User Context:** Updates the current user's room occupancy and local flags. 1 |
| **\+ses** | S → C | NAME, SELF, HOST, OPPO, P1-P4, ADDR, SEED, WHEN | **Session Bridge:** Provides full P2P session details once a challenge is accepted. 1 |
| **move** | S → C | IDENT, COUNT, NAME, FLAGS | **Room Transition:** Triggers client movement between lobby rooms or channels. 1 |
| **room** | S → C | LIDENT, LCOUNT | **Room Population Update:** Synchronizes user counts for specific room IDs without moving the client.  |
| **\+pop** | S → C | Z | **Population Update:** A dense string of room ID and count pairs for global lobby overview. 1 |
| **sele** | S → C | MORE, SLOTS | **Capacity Sync:** Updates available slots and pagination for the current room list. 1 |
| **snap** | S → C | CHAN | **Snapshot:** Synchronizes the client's current broadcast channel index. 1 |
| **\~png** | C ↔ S | TIME | **Lobby Heartbeat:** Measures RTT and maintains persistent TCP connection. 1 |

## ---

**3\. Buddy and Presence Commands**

Handled by the BuddyApiUpdate routine, these manage social connectivity and friend lists.

| Command | Direction | Tags / Parameters | Functional Description |
| :---- | :---- | :---- | :---- |
| **RGET** | C → S | LRSC, ID, LIST | **Roster Get:** Requests the initial friend or ignore list from the presence server. 1 |
| **ROST** | S → C | ID, USER, GROUP | **Roster Entry:** Populates a single buddy entry in the client's roster. 1 |
| **RADD** | C → S | ID, USER, GROUP, LIST | **Roster Add:** Adds a new persona to the buddy/ignore list or updates a name. 1 |
| **RDEL** | C → S | ID, USER | **Roster Delete:** Removes an entry from the roster and frees associated memory. 1 |
| **PGET** | C → S | USER | **Player Get:** Requests detailed presence data for a specific persona. 1 |
| **PING** | C ↔ S | N/A | **Buddy Heartbeat:** Independent keep-alive for the buddy server connection. 1 |
| **SEND** | C → S | BODY, SUBJ | **Buddy Message:** Sends a persistent message to a roster contact. 1 |
| **cper** | C → S | `NAME`, `MAIL`, `SPAM`, `CPAT` | **Create Persona:** Client request to create a new persona linked to the account.  |
| **dper** | C → S | `NAME` | **Delete Persona:** Likely counterpart to `cper` for profile management.  |
| **pers** | C ↔ S | `PERS` | **Persona Assignment:** Confirms the active persona name for the session. |

## ---

**4\. Messaging and Challenge Commands**

Facilitates communication and the transition to P2P game sessions.

| Command | Direction | Tags / Parameters | Functional Description |
| :---- | :---- | :---- | :---- |
| **auxi** | C → S | TEXT | **Auxiliary Data:** Transmits additional hex-encoded binary data during a challenge or session.  |
| **chal** | C → S | PRIV, TEXT, ATTR=3 | **Challenge Command:** Initiates the competitive invitation sequence. |
| **mesg** | C → S | PRIV, TEXT, ATTR=3 | **Challenge Initiation:** Request to invite a target persona to a game. 1 |
| **\+msg** | S → C | FROM, TEXT, ATTR=3, F | **Challenge Received:** Delivers the invitation to the target. ATTR=3 is mandatory for the UI. 1 |
| **\+rnk** | S → C | D, A, N, S | **Rank Sync:** Updates the rank and standing for the persona in the lobby view. 1 |
| **\+snp** | S → C | R, P, N, S | **Snapshot Update:** Refreshes presence/status for users in the current snapshot. 1 |

## ---

**Tag Definitions Reference**

* **ATTR=3**: Identifies a mesg or \+msg packet as a game invitation rather than standard text chat. 1  
* **TEXT**: A hex-encoded binary blob containing game-specific rules (track, car, etc.) used in challenges. 1  
* **F (Flags)**: A bitmask defining user status (e.g., 0x04 for broadcast, 0x10000 for private). 1  
* **LRSC**: The resource identifier used by the Buddy system to categorize roster types (Buddy vs Ignore). 1

#### **Works cited**

1. the\_blob.txt