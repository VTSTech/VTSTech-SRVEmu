# Server Dev Cheat Sheet

## 1. Hex Magic Numbers
* **Packet Header Size**: 12 Bytes (`0xC`)
* **Integer IP (192.168.1.1)**: `3232235777`
* **Game Product ID**: `NASCAR-PS2-2004`
* **Challenge Attribute**: `ATTR=3`
* **Chat Attribute**: `ATTR=1`

## 2. Python Helpers

**Calculate Integer IP (The "A" Tag):**
```python
import socket, struct
def get_int_ip(ip_string):
    # '192.168.1.123' -> 3232235899
    return struct.unpack("!I", socket.inet_aton(ip_string))[0]

Packet Builder (Safe):
Python

def build_packet(cmd, sub, payload):
    if isinstance(payload, str):
        payload = payload.encode('latin1')
    
    # Pad subcommand to 4 bytes
    if isinstance(sub, str):
        sub_bytes = sub.encode('latin1').ljust(4, b'\0')
    else:
        sub_bytes = b'\0\0\0\0'
        
    # Length = Header (12) + Payload
    total_len = 12 + len(payload)
    
    header = struct.pack(">4s4sI", cmd.encode('latin1'), sub_bytes, total_len)
    return header + payload

3. Common Pitfalls

    Missing Nulls: The game's parser often overruns if \0 is missing at the end of a payload.

    Zero IDs: Sending ID=0 breaks the Lobby logic. Always generate a real ID.

    Wrong IP Format: Sending A=192.168.1.1 (string) will fail. It must be the integer value as a string (e.g., A=3232235899).

    Subcommand Crashes: Ensure the 2nd header field is 4 bytes of data, not a raw integer 0.