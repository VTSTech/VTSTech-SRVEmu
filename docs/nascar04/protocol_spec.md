# Aries Protocol Specification (NASCAR 2004)

## 1. Physical Layer & Framing
The Aries protocol utilizes a persistent TCP connection. All multi-byte integers are transmitted in **Big-Endian** (Network Byte Order).

### Packet Header (12 Bytes)
All packets **must** begin with this 12-byte header.

| Offset | Size | Type | Name | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0x00 | 4 | char | **Command** | Four-character command identifier (e.g., `+usr`, `mesg`). |
| 0x04 | 4 | char | **SubCmd** | Usually `0x00000000`. Must be 4 bytes. |
| 0x08 | 4 | uint32 | **Length** | Total packet size in bytes (Header + Payload). |

**Critical Note on Length:**
The `Length` field at offset 0x08 **must** include the size of the header itself (12 bytes) plus the length of the data payload.
* *Example:* A 20-byte payload results in a Length field of `32` (`0x00000020`).

## 2. Payload Encoding
Payloads are ASCII text using "Tag=Value" pairs, separated by newlines (`\n`).

* **Format:** ASCII Text using the "Tag-Field" format (`TAG=VALUE`).
* **Separator:** Newline character `\n` (`0x0A`) denotes the end of a field.
* **Termination:** The payload string **must** be null-terminated (`\0`) if the receiver uses `TagFieldFind` or `TagFieldGetString`.
* **Escaping:** String values containing reserved characters (like `"` or `\`) must be URL-encoded or escaped, though simple alphanumeric IDs typically do not require this.

### Critical Tag Distinction
The game uses **Long Tags** for handshake/auth and **Short Tags** for lobby updates.
* **Long Tags:** `NAME`, `PASS`, `ADDR`, `PORT`, `SESS`, `MASK`
* **Short Tags:** `N`, `I`, `A`, `F`, `S`, `R`, `X`

*Sending the wrong tag type (e.g., `NAME=` instead of `N=` in a `+usr` packet) will cause the client to ignore the data.*

---

## 3. Data Types
* **String:** Raw text (e.g., `N=Player1`).
* **Integer:** Decimal string (e.g., `I=12345`). [cite_start]Parsed via `TagFieldGetNumber`[cite: 1264].
* **IP Address:** Integer string (e.g., `A=3232236155`). [cite_start]Parsed via `TagFieldGetAddress`[cite: 1264].
* **Blob:** Binary data found in `mesg` packets, often determining race parameters.