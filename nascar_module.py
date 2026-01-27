# nascar_module.py - NASCAR Thunder 2004 specific handlers
import time
import struct
import random
import socket

class NascarHandlers:
    def __init__(self, create_packet_func, server_ip):
        self.create_packet = create_packet_func
        self.server_ip = server_ip
        self.rankings = {}  # user -> rank data
    
    def handle_rank(self, data, session):
        """Handle RANK command - ranking and statistics"""
        data_str = data.decode('latin1') if data else ""
        print(f"RANK: Ranking request from {session.clientNAME}")
        
        # Parse configuration fields
        config = {}
        if data_str:
            for line in data_str.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key] = value
        
        # Store race config in session
        for key in ['SET_TRACK', 'SET_RACELEN', 'SET_AIDIFF', 'SET_DAMAGE', 
                    'SET_RANKED', 'SET_SETUPS', 'SET_NUMAI', 'SET_ASSISTS',
                    'SET_CAUTIONS', 'SET_CONSUME', 'SET_TRACKID']:
            if key in config:
                setattr(session, key, config[key])
        
        session.race_config = config
        print(f"RANK: Race config saved: {list(config.keys())}")
        
        # Generate ranking response
        username = session.clientNAME
        if username not in self.rankings:
            self.rankings[username] = {
                'rank': random.randint(500, 2000),
                'wins': random.randint(0, 50),
                'losses': random.randint(0, 30),
                'rating': random.randint(1000, 2500)
            }
        
        rank_data = self.rankings[username]
        
        response_lines = [
            f"USER={username}",
            f"RANK={rank_data['rank']}",
            f"WINS={rank_data['wins']}",
            f"LOSS={rank_data['losses']}",
            f"RATING={rank_data['rating']}",
            f"TRACK={config.get('SET_TRACK', 'DAYTONA')}",
            f"LAPS={config.get('SET_RACELEN', '10')}",
            "STATUS=1"
        ]
        
        return self.create_packet('rank', '', '\n'.join(response_lines) + '\n')
    
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