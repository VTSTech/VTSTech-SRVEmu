# nbav3_module.py - NBA Street v3 specific handlers
import time
import struct

class NBAv3Handlers:
    def __init__(self, create_packet_func, server_ip):
        self.create_packet = create_packet_func
        self.server_ip = server_ip
        
    def handle_gpro(self, data, session):
        """gpro - send binary profile data for NBA Street v3"""
        print(f"GPRO: Sending binary profile for {session.clientNAME}")
        
        # Create INFO and STAT data
        info_data = self.create_info_data(session)
        stat_data = self.create_stat_data(session)
        
        # Build response in NBA Street v3 format
        response = bytearray()
        response.extend(b"INFO=")
        response.extend(info_data)
        response.extend(b'\n')
        response.extend(b"STAT=")
        response.extend(stat_data)
        response.extend(b'\n')
        response.extend(f"STATUS=0\nPERS={session.current_persona}\n".encode('ascii'))
        
        return self.create_packet('gpro', '', bytes(response))
    
    def handle_cbal(self, data, session):
        """Character Balance - parse binary character data for NBA Street v3"""
        data_str = data.decode('latin1', errors='ignore') if data else ""
        
        print(f"CBAL: Character data from {session.clientNAME}")
        
        # Parse fields
        fields = {}
        for line in data_str.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                fields[key] = value
        
        # Check for binary version
        if 'BVER' in fields:
            print(f"  Binary version: {fields['BVER']}")
        
        # Check if new character
        if 'BNEW' in fields:
            is_new = fields['BNEW'] == '1'
            print(f"  New character: {is_new}")
        
        # Acknowledge
        return self.create_packet('cbal', '', "STATUS=0\nBVER=42730930\n")
        
    def handle_ccrt(self, data, session):
        """Handle Court Creation/Selection command"""
        print(f"CCRT: Court data from {session.clientNAME}")
        
        data_str = data.decode('latin1', errors='ignore') if data else ""
        
        # Parse fields
        fields = {}
        lines = data_str.split('\n')
        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                fields[key] = value
        
        # Log court information
        if 'CVER' in fields:
            print(f"  Court version: {fields['CVER']}")
        if 'COURT' in fields:
            court_info = fields['COURT']
            print(f"  Court: {court_info}")
        if 'CLOCK' in fields:
            clock_data = fields['CLOCK']
            print(f"  Clock data: {len(clock_data)} characters")
        
        # Store court data in session
        session.court_data = fields
        
        # Acknowledge
        return self.create_packet('ccrt', '', "STATUS=0\nCVER=1612\n")
        
    def handle_uatr(self, data, session):
        """User Attributes for NBA Street v3"""
        print(f"UATR: Attributes from {session.clientNAME}")
        
        data_str = data.decode('latin1', errors='ignore') if data else ""
        
        # Parse client hardware info
        hwflag = 0
        hwmask = 0
        
        for line in data_str.split('\n'):
            if line.startswith('HWFLAG='):
                try: hwflag = int(line[7:])
                except: pass
            elif line.startswith('HWMASK='):
                try: hwmask = int(line[7:])
                except: pass
        
        print(f"  Client HWFLAG=0x{hwflag:08x}, HWMASK=0x{hwmask:08x}")
        
        # Set response flags for NBA Street v3
        sysflags = 0x4  # Basic online capability
        caps = 0x400104  # Extended capabilities
        
        response_lines = [
            f"HWFLAG={sysflags}",
            f"HWMASK={hwmask}",
            f"SYSFLAGS={sysflags}",
            f"CAPS={caps}",
            "STATUS=0"
        ]
        
        return self.create_packet('uatr', '', '\n'.join(response_lines) + '\n')
    
    def handle_usld(self, data, session):
        """Handle User Session Load command for NBA Street v3"""
        print(f"USLD: Session load from {session.clientNAME}")
        return self.create_packet('usld', '', "STATUS=0\n")
    
    def create_info_data(self, session):
        """Create 620-byte INFO data for NBA Street v3"""
        data = bytearray(620)
        
        # NBA Street v3 specific structure
        struct.pack_into(">I", data, 0, 1)  # Version
        
        # Player name at offset 20
        name = session.current_persona[:31].encode('ascii')
        data[20:20+len(name)] = name
        
        # Stats for NBA Street v3
        # Fill with plausible basketball stats
        for i in range(100, 600, 4):
            struct.pack_into(">I", data, i, (i * 51) % 100)
        
        return bytes(data)
    
    def create_stat_data(self, session):
        """Create 64-byte STAT data for NBA Street v3"""
        data = bytearray(64)
        
        struct.pack_into(">I", data, 0, 1)  # Status
        struct.pack_into(">I", data, 4, 0x100)  # NBA Street specific flag
        
        return bytes(data)
    
    def create_session_data(self, session):
        """Create session data for NBA Street v3 (might be different size)"""
        # NBA Street v3 might use different session data format
        session_data = bytearray(256)  # Example size
        
        struct.pack_into(">I", session_data, 0, 1)
        struct.pack_into(">I", session_data, 4, session.current_room_id or 1)
        
        # NBA Street specific data
        struct.pack_into(">I", session_data, 8, 0x2001)  # Game mode
        
        session.session_data_ready = True
        return bytes(session_data)
    
    def get_news_response(self, name_value):
        """Get NBA Street v3 specific news response"""
        if name_value == 0:
            return [
                "BUDDY_URL=vtstech.servegame.com",
                "BUDDY_PORT=10899",
                "STATUS=1"
            ]
        elif name_value == 1:
            return [
                "NEWS_TEXT=VTSTech NBA Street v3 Server",
                "NEWS_TEXT=Create-a-Player System Active",
                "NEWS_TEXT=Online Tournaments Available",
                "NEWS_TEXT=Street Challenge Mode Ready",
                "COUNT=4",
                "STATUS=1"
            ]
        else:
            return [
                "STATUS=0",
                f"ERROR=Unknown news type {name_value}"
            ]