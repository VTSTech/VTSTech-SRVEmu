# Complete NASCAR Thunder 2004 Server with RC4 Encryption
import asyncio
import struct
import json
import os
import random
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field

# ============================================================================
# RC4 IMPLEMENTATION (from your extracted table)
# ============================================================================

# Load the extracted RC4 table
try:
    from rc4_table import RC4_TABLE
    print(f"Loaded RC4 table with {len(RC4_TABLE)} entries")
except ImportError:
    print("Warning: rc4_table.py not found, using placeholder")
    # Placeholder - use your extracted values
    RC4_TABLE = [0x00000000] * 256  # Replace with actual extracted table

class GameRC4:
    """Custom RC4 implementation matching game's Crypto_RC4_* functions"""
    
    def __init__(self, rc4_table):
        self.rc4_table = rc4_table
        self.S = bytearray(256)  # S-box
        self.i = 0               # Current i index (8-bit)
        self.j = 0               # Current j value (32-bit)
        
        # Initialize S-box
        for i in range(256):
            self.S[i] = i
    
    def initialize(self, key: bytes, iterations: int = 4096):
        """Initialize RC4 state matching Crypto_RC4_Initialize"""
        # Reset S-box
        for i in range(256):
            self.S[i] = i
        
        self.i = 0
        self.j = 0
        
        if len(key) == 0:
            return
        
        temp_j = 0
        k = 0
        
        for idx in range(iterations):
            # Get indices
            i_idx = idx & 0xFF
            key_idx = idx % len(key)
            
            # Get current values
            s_val = self.S[i_idx]
            key_byte = key[key_idx]
            
            # Update using RC4 table (matching decompilation)
            temp_j = (temp_j >> 8) ^ self.rc4_table[(k ^ key_byte) & 0xFF]
            k = temp_j & 0xFF
            temp_j = (temp_j >> 8) ^ self.rc4_table[(k ^ s_val) & 0xFF]
            k = temp_j & 0xFF
            
            # Swap S[i] and S[k]
            self.S[i_idx], self.S[k] = self.S[k], s_val
    
    def process(self, data: bytes) -> bytes:
        """Process data matching Crypto_RC4_Process"""
        result = bytearray(data)
        
        for n in range(len(data)):
            # Increment i
            self.i = (self.i + 1) & 0xFF
            
            # Get S[i]
            si = self.S[self.i]
            
            # Update j using RC4 table
            self.j = (self.j >> 8) ^ self.rc4_table[(self.j & 0xFF) ^ si]
            k = self.j & 0xFF
            
            # Get S[j]
            sj = self.S[k]
            
            # Swap S[i] and S[j]
            self.S[self.i] = sj
            self.S[k] = si
            
            # Generate keystream byte (using (si - sj) & 0xFF)
            keystream_idx = (si - sj) & 0xFF
            keystream_byte = self.S[keystream_idx]
            
            # XOR with data
            result[n] ^= keystream_byte
        
        return bytes(result)
    
    def encrypt_password(self, password: str, key: bytes) -> str:
        """Encrypt password matching Crypto_RC4_EncryptPassword"""
        # Create local RC4 state
        local_rc4 = GameRC4(self.rc4_table)
        local_rc4.initialize(key, 4096)
        
        # Create global RC4 state (simulated at 0x50a8d0)
        global_rc4 = GameRC4(self.rc4_table)
        global_rc4.initialize(key, 4096)
        
        # Re-initialize with "ru paranoid?"
        global_rc4.initialize(b"ru paranoid?", 4096)
        
        encrypted_chars = []
        
        for char in password:
            # Get keystream byte from local state
            keystream_byte = local_rc4.process(b'\x00')[0]
            
            # Apply custom formula from decompilation:
            # ((password_char + (keystream_byte % 0x60) + 0x40) % 0x60) + 0x20
            char_code = ord(char)
            encrypted_code = ((char_code + (keystream_byte % 0x60) + 0x40) % 0x60) + 0x20
            
            # Ensure printable ASCII
            if encrypted_code > 0x7E:
                encrypted_code = 0x7F
            
            encrypted_chars.append(chr(encrypted_code))
        
        return ''.join(encrypted_chars)
    
    def decrypt_password(self, encrypted_password: str, key: bytes) -> str:
        """Decrypt password (reverse of encryption)"""
        # Create local RC4 state (same as encryption)
        local_rc4 = GameRC4(self.rc4_table)
        local_rc4.initialize(key, 4096)
        
        decrypted_chars = []
        
        for char in encrypted_password:
            # Get keystream byte from local state
            keystream_byte = local_rc4.process(b'\x00')[0]
            
            # Reverse the encryption formula
            encrypted_code = ord(char)
            
            # Subtract the 0x20 that was added during encryption
            X = encrypted_code - 0x20
            
            # Calculate k_mod = keystream_byte % 0x60
            k_mod = keystream_byte % 0x60
            
            # Reverse: (password_char + k_mod + 0x40) % 0x60 = X
            # So: password_char ? X - k_mod - 0x40 (mod 0x60)
            password_code = (X - k_mod - 0x40) % 0x60
            
            # Original password should be in printable ASCII range
            # Adjust if necessary
            if password_code < 0x20:
                password_code += 0x60
            
            decrypted_chars.append(chr(password_code))
        
        return ''.join(decrypted_chars)

# ============================================================================
# SERVER DATA STRUCTURES
# ============================================================================

@dataclass
class ClientState:
    """Client connection state"""
    transport: asyncio.Transport
    addr: Tuple[str, int]
    public_key: Optional[bytes] = None
    rc4_state: Optional[GameRC4] = None
    username: str = ""
    persona: str = ""
    state: str = "connected"  # connected, skey_sent, authenticated, ingame
    last_activity: float = field(default_factory=time.time)
    room_id: int = -1

@dataclass
class Room:
    """Game room/chat room"""
    id: int
    name: str
    password: str = ""
    host: str = ""
    max_players: int = 8
    current_players: int = 0
    players: list = field(default_factory=list)

# ============================================================================
# MAIN SERVER IMPLEMENTATION
# ============================================================================

class NASCARServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 10780):
        self.host = host
        self.port = port
        self.rc4 = GameRC4(RC4_TABLE)
        self.clients: Dict[asyncio.Transport, ClientState] = {}
        self.rooms: Dict[int, Room] = {}
        self.next_room_id = 1
        self.next_user_id = 1000
        
        # Configuration
        self.server_ip = "192.168.1.100"  # Your server's external IP
        self.game_port = 10781            # Game server port
        self.master_port = 10600          # Master server port
        
        # Stats
        self.stats = {
            "connections": 0,
            "authentications": 0,
            "rooms_created": 0
        }
    
    def generate_public_key(self) -> bytes:
        """Generate 16-byte public key for RC4"""
        return os.urandom(16)
    
    async def send_message(self, writer, msg_type: bytes, subtype: int, data: str):
        """Send Ares protocol message"""
        # Ensure null termination
        if not data.endswith('\0'):
            data += '\0'
        
        # Build packet: type(4) + subtype(4) + length(4) + data
        total_length = len(data) + 12
        packet = struct.pack('>4sII', msg_type, subtype, total_length)
        packet += data.encode('ascii')
        
        writer.write(packet)
        await writer.drain()
    
    def parse_tag_field(self, message: str, field: str) -> str:
        """Parse tag field like "NAME=value\PASS=password\" """
        pattern = f"{field}="
        start = message.find(pattern)
        if start == -1:
            return ""
        
        start += len(pattern)
        end = message.find('\\', start)
        if end == -1:
            end = len(message)
        
        return message[start:end]
    
    async def handle_client(self, reader, writer):
        """Main client connection handler"""
        client_addr = writer.get_extra_info('peername')
        client_id = f"{client_addr[0]}:{client_addr[1]}"
        
        print(f"[{client_id}] Client connected")
        
        # Create client state
        client_state = ClientState(
            transport=writer.transport,
            addr=client_addr,
            last_activity=time.time()
        )
        self.clients[writer] = client_state
        self.stats["connections"] += 1
        
        try:
            # Send initial directory response
            await self.handle_directory(client_state, writer)
            
            # Main message loop
            while True:
                try:
                    # Read header (12 bytes)
                    header = await asyncio.wait_for(reader.read(12), timeout=30.0)
                    if not header:
                        break
                    
                    # Parse header
                    msg_type_bytes = header[0:4]
                    msg_type = struct.unpack('>I', msg_type_bytes)[0]
                    subtype = struct.unpack('>I', header[4:8])[0]
                    total_length = struct.unpack('>I', header[8:12])[0]
                    
                    # Read data
                    data_length = total_length - 12
                    if data_length > 0:
                        data = await asyncio.wait_for(reader.read(data_length), timeout=5.0)
                    else:
                        data = b''
                    
                    # Convert to string
                    message_str = data.decode('ascii', errors='ignore').rstrip('\x00')
                    msg_type_str = msg_type_bytes.decode('ascii', errors='ignore')
                    
                    print(f"[{client_id}] Received: {msg_type_str} (0x{msg_type:08x})")
                    
                    # Update activity time
                    client_state.last_activity = time.time()
                    
                    # Handle message
                    await self.handle_message(client_state, writer, msg_type, subtype, message_str)
                    
                except asyncio.TimeoutError:
                    print(f"[{client_id}] Timeout, disconnecting")
                    break
                except Exception as e:
                    print(f"[{client_id}] Error: {e}")
                    break
                    
        except Exception as e:
            print(f"[{client_id}] Connection error: {e}")
        finally:
            print(f"[{client_id}] Client disconnected")
            if writer in self.clients:
                del self.clients[writer]
            writer.close()
    
    async def handle_message(self, client_state, writer, msg_type: int, subtype: int, data: str):
        """Route messages to appropriate handlers"""
        msg_type_str = struct.pack('>I', msg_type).decode('ascii', errors='ignore')
        
        # Ping handler
        if msg_type_str == '~png':
            await self.handle_ping(client_state, writer, data)
        
        # Directory request
        elif msg_type_str == '@dir':
            await self.handle_directory(client_state, writer)
        
        # Authentication
        elif msg_type_str == 'auth':
            await self.handle_auth(client_state, writer, data)
        
        # Persona selection
        elif msg_type_str == 'pers':
            await self.handle_persona(client_state, writer, data)
        
        # Room creation
        elif msg_type_str == 'room':
            await self.handle_room(client_state, writer, data)
        
        # Room movement
        elif msg_type_str == 'move':
            await self.handle_move(client_state, writer, data)
        
        # Challenge
        elif msg_type_str == 'CHAL':
            await self.handle_challenge(client_state, writer, data)
        
        # Unknown message
        else:
            print(f"Unknown message type: {msg_type_str}")
            print(f"Data: {data}")
    
    async def handle_ping(self, client_state, writer, data: str):
        """Handle ping message"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        # Simple ping response
        response = f"TIME={int(time.time() * 1000)}"
        await self.send_message(writer, b'~png', 0, response)
        
        print(f"[{client_id}] Ping response sent")
    
    async def handle_directory(self, client_state, writer):
        """Handle directory request - send server info"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        # Send directory response with game server info
        response = f"ADDR={self.server_ip}\\PORT={self.game_port}\\SESS=1\\DOWN=NASCAR Thunder 2004 Emulator"
        await self.send_message(writer, b'@dir', 0, response)
        
        print(f"[{client_id}] Directory response sent")
        
        # After directory, client will connect to game server
        # For simplicity, we'll handle game server messages on same connection
    
    async def send_session_key(self, client_state, writer):
        """Send SKEY message with public key"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        # Generate and store public key
        public_key = self.generate_public_key()
        client_state.public_key = public_key
        
        # Create RC4 state for this client
        client_state.rc4_state = GameRC4(RC4_TABLE)
        client_state.rc4_state.initialize(public_key, 4096)
        
        # Send SKEY with hex-encoded key (prefixed with $ for binary)
        hex_key = public_key.hex()
        response = f"${hex_key}"
        await self.send_message(writer, b'skey', 0, response)
        
        client_state.state = "skey_sent"
        print(f"[{client_id}] SKEY sent (key: {hex_key[:16]}...)")
    
    async def handle_auth(self, client_state, writer, data: str):
        """Handle authentication with password decryption"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        # Parse fields
        username = self.parse_tag_field(data, "NAME")
        encrypted_pass = self.parse_tag_field(data, "PASS")
        
        print(f"[{client_id}] Auth attempt: username={username}, pass_len={len(encrypted_pass)}")
        
        # Check if we have a public key
        if client_state.public_key and client_state.rc4_state:
            try:
                # Decrypt password
                password = client_state.rc4_state.decrypt_password(encrypted_pass, client_state.public_key)
                print(f"[{client_id}] Decrypted password: {password}")
            except Exception as e:
                print(f"[{client_id}] Decryption failed: {e}")
                password = "[decryption failed]"
        else:
            # No encryption (client didn't receive SKEY or it was empty)
            password = encrypted_pass
            print(f"[{client_id}] No encryption, plain password: {password}")
        
        # Store username
        client_state.username = username
        
        # Send auth response (success)
        response = f"NAME={username}\\ADDR={client_state.addr[0]}"
        await self.send_message(writer, b'auth', 0, response)
        
        # Send persona selection
        await self.send_message(writer, b'pers', 0, f"PERS={username}")
        
        client_state.state = "authenticated"
        self.stats["authentications"] += 1
        
        print(f"[{client_id}] Authentication successful")
        
        # Send room list
        await self.send_room_list(client_state, writer)
    
    async def handle_persona(self, client_state, writer, data: str):
        """Handle persona selection"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        persona = self.parse_tag_field(data, "PERS")
        client_state.persona = persona
        
        print(f"[{client_id}] Persona selected: {persona}")
        
        # Acknowledge persona
        await self.send_message(writer, b'pers', 0, f"PERS={persona}")
    
    async def handle_room(self, client_state, writer, data: str):
        """Handle room creation"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        room_name = self.parse_tag_field(data, "NAME")
        room_pass = self.parse_tag_field(data, "PASS")
        room_desc = self.parse_tag_field(data, "DESC")
        max_players = self.parse_tag_field(data, "MAX") or "8"
        
        # Create room
        room_id = self.next_room_id
        self.next_room_id += 1
        
        room = Room(
            id=room_id,
            name=room_name,
            password=room_pass,
            host=client_state.username,
            max_players=int(max_players),
            current_players=1
        )
        room.players.append(client_state)
        
        self.rooms[room_id] = room
        client_state.room_id = room_id
        
        self.stats["rooms_created"] += 1
        
        # Send room creation response
        room_info = f"I={room_id}\\NAME={room_name}\\L={max_players}\\T=1\\HOST={client_state.addr[0]}"
        await self.send_message(writer, b'+rom', 0, room_info)
        
        print(f"[{client_id}] Room created: {room_name} (ID: {room_id})")
        
        # Broadcast room list update to all clients
        await self.broadcast_room_list()
    
    async def handle_move(self, client_state, writer, data: str):
        """Handle room movement"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        room_name = self.parse_tag_field(data, "NAME")
        room_pass = self.parse_tag_field(data, "PASS")
        
        print(f"[{client_id}] Move request: room={room_name}")
        
        # Find room by name
        target_room = None
        for room in self.rooms.values():
            if room.name == room_name:
                target_room = room
                break
        
        if target_room:
            # Check password
            if target_room.password and target_room.password != room_pass:
                await self.send_message(writer, b'move', 1, "STAT=Invalid password")
                return
            
            # Leave current room
            if client_state.room_id != -1:
                old_room = self.rooms.get(client_state.room_id)
                if old_room:
                    old_room.players.remove(client_state)
                    old_room.current_players -= 1
            
            # Join new room
            target_room.players.append(client_state)
            target_room.current_players += 1
            client_state.room_id = target_room.id
            
            # Send success response
            response = f"NAME={target_room.name}\\T={target_room.current_players}"
            await self.send_message(writer, b'move', 0, response)
            
            print(f"[{client_id}] Moved to room: {target_room.name}")
            
            # Update room population broadcast
            await self.broadcast_population_update(target_room.id, target_room.current_players)
        else:
            await self.send_message(writer, b'move', 1, "STAT=Room not found")
    
    async def handle_challenge(self, client_state, writer, data: str):
        """Handle challenge system"""
        client_id = f"{client_state.addr[0]}:{client_state.addr[1]}"
        
        print(f"[{client_id}] Challenge received: {data}")
        
        # Parse challenge type
        if data.startswith("BLOC"):
            response = "STAT=Challenge blocked"
        elif data.startswith("DECL"):
            response = "STAT=Challenge declined"
        elif data.startswith("ACPT"):
            response = "STAT=Challenge accepted"
        else:
            # New challenge
            response = "STAT=Challenge delivered"
        
        await self.send_message(writer, b'CHAL', 0, response)
    
    async def send_room_list(self, client_state, writer):
        """Send current room list to client"""
        for room in self.rooms.values():
            room_info = f"I={room.id}\\NAME={room.name}\\L={room.max_players}\\T={room.current_players}\\HOST={room.host}"
            await self.send_message(writer, b'+rom', 0, room_info)
    
    async def broadcast_room_list(self):
        """Broadcast room list to all connected clients"""
        for client_state in self.clients.values():
            if client_state.state == "authenticated":
                writer = asyncio.StreamWriter(
                    transport=client_state.transport,
                    protocol=None,
                    reader=None,
                    loop=asyncio.get_event_loop()
                )
                await self.send_room_list(client_state, writer)
    
    async def broadcast_population_update(self, room_id: int, population: int):
        """Broadcast population update (+pop message)"""
        pop_data = f"Z={room_id}:{population}"
        
        for client_state in self.clients.values():
            if client_state.state == "authenticated":
                writer = asyncio.StreamWriter(
                    transport=client_state.transport,
                    protocol=None,
                    reader=None,
                    loop=asyncio.get_event_loop()
                )
                await self.send_message(writer, b'+pop', 0, pop_data)
    
    async def run_server(self):
        """Start the server"""
        print("=" * 60)
        print("NASCAR Thunder 2004 Server")
        print(f"Host: {self.host}:{self.port}")
        print(f"RC4 Table loaded: {len(RC4_TABLE)} entries")
        print("=" * 60)
        
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        # Start stats logging task
        asyncio.create_task(self.log_stats())
        
        async with server:
            print(f"Server started on {self.host}:{self.port}")
            await server.serve_forever()
    
    async def log_stats(self):
        """Periodically log server statistics"""
        while True:
            await asyncio.sleep(60)  # Every minute
            print("\n" + "=" * 60)
            print("Server Statistics:")
            print(f"  Connections: {self.stats['connections']}")
            print(f"  Active Clients: {len(self.clients)}")
            print(f"  Authentications: {self.stats['authentications']}")
            print(f"  Rooms Created: {self.stats['rooms_created']}")
            print(f"  Active Rooms: {len(self.rooms)}")
            print("=" * 60)

# ============================================================================
# TEST CLIENT (for development)
# ============================================================================

async def test_client():
    """Simple test client to verify server functionality"""
    print("Testing server connection...")
    
    reader, writer = await asyncio.open_connection('127.0.0.1', 10780)
    
    # Send ping
    print("Sending ping...")
    await send_message(writer, b'~png', 0, "ping")
    
    response = await read_message(reader)
    print(f"Ping response: {response}")
    
    # Send directory request
    print("Sending directory request...")
    await send_message(writer, b'@dir', 0, "")
    
    response = await read_message(reader)
    print(f"Directory response: {response}")
    
    writer.close()
    await writer.wait_closed()

async def send_message(writer, msg_type: bytes, subtype: int, data: str):
    """Helper to send message"""
    if not data.endswith('\0'):
        data += '\0'
    
    total_length = len(data) + 12
    packet = struct.pack('>4sII', msg_type, subtype, total_length)
    packet += data.encode('ascii')
    
    writer.write(packet)
    await writer.drain()

async def read_message(reader):
    """Helper to read message"""
    header = await reader.read(12)
    if not header:
        return None
    
    msg_type, subtype, total_length = struct.unpack('>4sII', header)
    data_length = total_length - 12
    
    if data_length > 0:
        data = await reader.read(data_length)
        return data.decode('ascii', errors='ignore').rstrip('\x00')
    
    return ""

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Run test client
        asyncio.run(test_client())
    else:
        # Run server
        server = NASCARServer(host="0.0.0.0", port=10600)
        
        try:
            asyncio.run(server.run_server())
        except KeyboardInterrupt:
            print("\nServer shutdown requested")
        except Exception as e:
            print(f"Server error: {e}")