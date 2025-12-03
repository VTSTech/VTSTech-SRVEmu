# state_trigger.py - Send MultiplayerCommand_Dispatcher commands
import time
import struct

class StateTrigger:
    def __init__(self, create_packet_func, server_ip, ports, room_manager):
        self.create_packet = create_packet_func
        self.server_ip = server_ip
        self.ports = ports
        self.room_manager = room_manager
        
    def send_multiplayer_commands(self, session):
        """Send commands to MultiplayerCommand_Dispatcher"""
        if not session.connection:
            return False
            
        print(f"MULTIPLAYER COMMANDS: Sending to {session.clientNAME}")
        
        # Step 1: Send "conn" command with param=6 to set DAT_MultiplayerMode=1
        print(f"\nSTEP 1: Sending 'conn' command (set mode=1)")
        self._send_conn_command(session)
        time.sleep(1)
        
        # Step 2: Send "auth" command with success to set DAT_MultiplayerMode=3
        print(f"\nSTEP 2: Sending 'auth' command (set mode=3)")
        self._send_multiplayer_auth_command(session)
        time.sleep(1)
        
        # Step 3: Send other commands that might help
        print(f"\nSTEP 3: Sending other multiplayer commands")
        self._send_other_commands(session)
        time.sleep(2)
        
        print(f"\nMULTIPLAYER COMMANDS: Complete for {session.clientNAME}")
        return True
    
    def _send_conn_command(self, session):
        """Send 'conn' command (0x636f6e6e) with param=6 at offset 4"""
        # Structure: [4 bytes: "conn"] [4 bytes: param] [rest...]
        # param=6 sets DAT_MultiplayerMode=1
        
        data = bytearray()
        
        # Command: "conn" (0x636f6e6e)
        data.extend(struct.pack('>I', 0x636f6e6e))  # Big-endian?
        
        # Parameter at offset 4: 6
        data.extend(struct.pack('>I', 6))
        
        # Send as raw binary or wrapped?
        self._send_binary_command(session, data, "conn")
    
    def _send_multiplayer_auth_command(self, session):
        """Send multiplayer 'auth' command (0x61757468) with success"""
        # Structure: [4 bytes: "auth"] [4 bytes: ?] [4 bytes: status at offset 8]
        # status at offset 8 must be 0 for success
        
        data = bytearray()
        
        # Command: "auth" (0x61757468)
        data.extend(struct.pack('>I', 0x61757468))
        
        # Unknown at offset 4 (maybe 0?)
        data.extend(struct.pack('>I', 0))
        
        # Status at offset 8: 0 = success
        data.extend(struct.pack('>I', 0))
        
        # Send
        self._send_binary_command(session, data, "auth")
    
    def _send_other_commands(self, session):
        """Send other multiplayer commands"""
        
        # Try "addu" (add user) command
        print(f"  Sending 'addu' command")
        data = bytearray()
        data.extend(struct.pack('>I', 0x61646475))  # "addu"
        data.extend(struct.pack('>I', 1))  # Some parameter
        self._send_binary_command(session, data, "addu")
        time.sleep(0.2)
        
        # Try "chat" command
        print(f"  Sending 'chat' command")
        data = bytearray()
        data.extend(struct.pack('>I', 0x63686174))  # "chat"
        data.extend(struct.pack('>I', 0))  # Parameter
        self._send_binary_command(session, data, "chat")
        time.sleep(0.2)
        
        # Try "rost" command (buddy roster)
        print(f"  Sending 'rost' command")
        data = bytearray()
        data.extend(struct.pack('>I', 0x726f7374))  # "rost"
        data.extend(struct.pack('>I', 0))
        self._send_binary_command(session, data, "rost")
    
    def _send_binary_command(self, session, data, cmd_name):
        """Send binary command to MultiplayerCommand_Dispatcher"""
        # Try different methods of sending binary commands
        
        methods = [
            self._send_as_sysc,
            self._send_as_raw,
            self._send_as_special,
        ]
        
        for method in methods:
            if method(session, data, cmd_name):
                return True
        
        return False
    
    def _send_as_sysc(self, session, data, cmd_name):
        """Send as sysc command"""
        try:
            # sysc might be "system command"
            # Use first 4 bytes of data as subcommand?
            if len(data) >= 4:
                subcmd = data[:4]
                payload = data[4:] if len(data) > 4 else b''
                sysc_packet = self.create_packet('sysc', subcmd, payload)
                session.connection.sendall(sysc_packet)
                print(f"    Sent as sysc with subcmd {cmd_name}")
                return True
        except Exception as e:
            print(f"    Error sending as sysc: {e}")
        return False
    
    def _send_as_raw(self, session, data, cmd_name):
        """Send as raw binary"""
        try:
            # Try sending raw binary
            session.connection.sendall(data)
            print(f"    Sent {len(data)} bytes raw binary")
            return True
        except Exception as e:
            print(f"    Error sending raw: {e}")
        return False
    
    def _send_as_special(self, session, data, cmd_name):
        """Send as special command"""
        try:
            # Try using the command name directly
            if cmd_name == "auth":
                # Already used for authentication, try different
                return False
            
            # Try as binary payload in a message
            hex_data = data.hex()
            msg_payload = f"FROM=Server\nTEXT=MPCMD_{cmd_name}\nDATA={hex_data}\n"
            msg_packet = self.create_packet('+msg', '', msg_payload)
            session.connection.sendall(msg_packet)
            print(f"    Sent as message with hex data")
            return True
        except Exception as e:
            print(f"    Error sending as special: {e}")
        return False
    
    def trigger_lobby_state(self, session):
        """Main entry - send multiplayer commands"""
        return self.send_multiplayer_commands(session)