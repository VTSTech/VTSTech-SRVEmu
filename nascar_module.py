# nascar_module.py - NASCAR Thunder 2004 specific handlers
import time
import struct

class NascarHandlers:
    def __init__(self, create_packet_func, server_ip):
        self.create_packet = create_packet_func
        self.server_ip = server_ip
        
    def handle_rank(self, data, session):
        """Handle rank command (race configuration)"""
        print(f"RANK: Race configuration from {session.clientNAME}")
        
        # Parse race settings
        race_config = {}
        if data:
            data_str = data.decode('latin1') if data else ""
            for line in data_str.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    race_config[key] = value
        
        # Store race config in session
        for key in ['SET_TRACK', 'SET_RACELEN', 'SET_AIDIFF', 'SET_DAMAGE', 
                    'SET_RANKED', 'SET_SETUPS', 'SET_NUMAI', 'SET_ASSISTS',
                    'SET_CAUTIONS', 'SET_CONSUME', 'SET_TRACKID']:
            if key in race_config:
                setattr(session, key, race_config[key])
        
        session.race_config = race_config
        print(f"RANK: Race config saved: {list(race_config.keys())}")
        
        return self.create_packet('rank', '', "STATUS=1\n")
    
    def create_272_byte_session_data(self, session):
        """Create 272-byte session data for NASCAR"""
        session_data = bytearray(272)
        
        # NASCAR-specific session structure
        # Offset 0: Version/Status (1)
        session_data[0:4] = struct.pack(">I", 1)
        
        # Offset 4: Room ID
        session_data[4:8] = struct.pack(">I", session.current_room_id or 1)
        
        # Offset 8-16: Some NASCAR-specific data
        session_data[8:12] = struct.pack(">I", 0x1001)  # Game mode flag
        
        # Fill remaining with placeholder data
        for i in range(16, 272, 4):
            session_data[i:i+4] = struct.pack(">I", (i * 37) % 256)
        
        session.session_data_ready = True
        return bytes(session_data)
    
    def get_news_response(self, name_value):
        """Get NASCAR-specific news response"""
        if name_value == 0:
            return [
                "BUDDY_URL=vtstech.servegame.com",
                "BUDDY_PORT=10899",
                "STATUS=1"
            ]
        elif name_value == 1:
            return [
                "NEWS_TEXT=VTSTech NASCAR Server Online",
                "NEWS_TEXT=Buddy System Active",
                "NEWS_TEXT=Challenge System Ready",
                "NEWS_TEXT=Room Creation Available",
                "COUNT=4",
                "STATUS=1"
            ]
        else:
            return [
                "STATUS=0",
                f"ERROR=Unknown news type {name_value}"
            ]