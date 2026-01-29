# buddy_system_r11.py - COMPLETE BUDDY API IMPLEMENTATION
import time, struct

class BuddyUser:
    def __init__(self, username, friendly_name=None, group="Default"):
        self.username = username
        self.friendly_name = friendly_name or username
        self.group = group
        self.online = False
        self.last_seen = time.time()
        
class BuddyHandlers:
    def __init__(self, create_packet_func, session_manager):
        self.create_packet = create_packet_func
        self.session_manager = session_manager
        self.buddy_lists = {}  # user -> list of BuddyUser objects
        self.user_profiles = {}  # user -> profile data
        
    def process_username(self, username):
        """Normalize username - strip @ and / characters and everything after"""
        if '@' in username:
            username = username.split('@')[0]
        if '/' in username:
            username = username.split('/')[0]
        return username
    
    def handle_buddy_command(self, command, data, session):
        """Processes NASCAR Buddy commands using the 12-byte header logic"""
        if len(data) < 12:
            print(f"BUDDY: Packet too short ({len(data)} bytes)")
            return None

        # 1. Extract command from the first 4 bytes of the HEADER
        #command = data[:4].decode('ascii', errors='ignore').strip()
        
        # 2. Extract the PAYLOAD (starts after the 12-byte header)
        payload = data[12:].decode('latin1', errors='ignore')
        
        print(f"[BuddyApi DEBUG] Command: {command} | Payload: {payload[:30]}...")

        handlers = {
            'AUTH': self.handle_auth,
            'RGET': self.handle_rget,
            'ROST': self.handle_rost,
            'PGET': self.handle_pget, 
            'RADD': self.handle_radd,
            'RDEL': self.handle_rdel,
            'PSET': self.handle_pset,
        }
        
        if command in handlers:
            # We pass the payload (params) to the specific handler
            return handlers[command](payload, session)
        else:
            print(f"BUDDY API: No handler for command: {command}")
            # Fallback to prevent client hanging
            return self.create_packet(command, '', "S=0\nSTATUS=1\n")

    def handle_auth(self, payload, session):
        """Handle the initial Buddy side-channel authentication"""
        params = self.parse_params(payload)
        user_raw = params.get('USER', 'VTSTech')
        username = self.process_username(user_raw)
        
        # Bridge the session identity
        self._bridge_session(username, session)
        
        print(f"BUDDY: Authenticated side-channel for {session.clientNAME}")
        response = f"NAME={session.clientNAME}\nS=0\nSTATUS=1\n"
        return self.create_packet("AUTH", "", response)

    def handle_pset(self, params, session):
        """Handle PSET - Set player status/presence"""
        param_dict = self.parse_params(params)
        req_id = param_dict.get('ID', '1')
        print(f"BUDDY PSET: {session.clientNAME} (ID={req_id})")
        
        # NASCAR needs NAME and ID mirrored to advance the state machine
        response = f"NAME={session.clientNAME}\nID={req_id}\nS=0\nSTATUS=1\n"
        return self.create_packet("PSET", "", response)

    def _bridge_session(self, user_name, buddy_session):
        """Copies identity from the Main Lobby session to the Buddy session"""
        for lobby_session in self.session_manager.client_sessions.values():
            lobby_name = getattr(lobby_session, 'clientNAME', None)
            if lobby_name == user_name:
                buddy_session.clientNAME = lobby_session.clientNAME
                return True
        buddy_session.clientNAME = user_name
        return False

    def handle_generic_success(self, session, cmd):
        """Acknowledges PSET/RGET to stop the retry loop"""
        print(f"BUDDY: Acknowledging {cmd} for {session.clientNAME}")
        # NASCAR often just needs STATUS=1 and S=0 (Sequence)
        response = "S=0\nSTATUS=1\n"
        return self.create_packet(cmd, '', response)
        
    def handle_list(self, payload, session, cmd_case):
        """NASCAR 2004 Buddy List response"""
        response_lines = [
            "S=0",
            "STATUS=1",
            "COUNT=0"
        ]
        return self.create_packet(cmd_case, '', '\n'.join(response_lines) + '\n')
    
    def handle_rget(self, params, session):
        """Handle RGET - Retrieve buddy/ignore data"""
        param_dict = self.parse_params(params)
        
        # ID=1 is Buddies, ID=2 is Ignores
        op_id = param_dict.get('ID', '1')
        list_type = param_dict.get('T', 'B') # B=Buddy, I=Ignore
        
        print(f"BUDDY RGET: {session.clientNAME} requesting {list_type} (ID={op_id})")

        # Mirror the NAME and ID. NASCAR's 'The Blob' requires these to match.
        response_lines = [
            f"NAME={session.clientNAME}",
            f"ID={op_id}",
            "S=0",
            "STATUS=1",
            "COUNT=0" # We return 0 for now to keep it simple
        ]
        
        return self.create_packet('RGET', '', '\n'.join(response_lines) + '\n')
    
    def handle_rost(self, params, session):
        """Handle ROST - Update roster/list"""
        print(f"BUDDY ROST: {session.clientNAME} - {params}")
        
        param_dict = self.parse_params(params)
        op_type = int(param_dict.get('ID', '1'))
        target_user = self.process_username(param_dict.get('USER', ''))
        group = param_dict.get('GROUP', 'Default')
        friendly_name = param_dict.get('FUSR', target_user)
        
        if not target_user:
            return self.create_packet('ROST', '', "STATUS=0\nERROR=No user specified\n")
            
        # Initialize buddy list if needed
        if session.clientNAME not in self.buddy_lists:
            self.buddy_lists[session.clientNAME] = []
            
        buddies = self.buddy_lists[session.clientNAME]
        
        # Check if user already in list
        existing_buddy = None
        for buddy in buddies:
            if buddy.username == target_user:
                existing_buddy = buddy
                break
                
        if op_type == 0x200:  # Roster management operation
            if existing_buddy:
                # Update existing buddy
                existing_buddy.friendly_name = friendly_name
                existing_buddy.group = group
                print(f"BUDDY: Updated {target_user} in {session.clientNAME}'s list")
            else:
                # Add new buddy
                new_buddy = BuddyUser(target_user, friendly_name, group)
                buddies.append(new_buddy)
                print(f"BUDDY: Added {target_user} to {session.clientNAME}'s list")
                
        response_lines = [
            f"ID={op_type}",
            f"USER={target_user}",
            f"FUSR={friendly_name}",
            f"GROUP={group}",
            "STATUS=1"
        ]
        
        return self.create_packet('ROST', '', '\n'.join(response_lines) + '\n')
    
    def handle_pget(self, params, session):
        """Handle PGET - Get player data"""
        print(f"BUDDY PGET: {session.clientNAME} - {params}")
        
        param_dict = self.parse_params(params)
        target_user = self.process_username(param_dict.get('USER', ''))
        
        if not target_user:
            return self.create_packet('PGET', '', "STATUS=0\nERROR=No user specified\n")
            
        # Check if user exists and is online
        is_online = target_user in [user.clientNAME for user in self.active_users.values() 
                                  if hasattr(user, 'clientNAME')]
        
        response_lines = [
            f"USER={target_user}",
            f"STATUS={1 if is_online else 0}",
            f"ONLINE={1 if is_online else 0}",
            "STATUS=1"
        ]
        
        return self.create_packet('PGET', '', '\n'.join(response_lines) + '\n')
    
    def handle_radd(self, payload, session):
        """Handle RADD - Add a user/resource to the buddy list"""
        params = self.parse_params(payload)
        
        # ID=101 in your log is the Transaction ID. 
        # We MUST mirror this back.
        req_id = params.get('ID', '100')
        lrsc = params.get('LRSC', '') # The 'Test' persona mapped to 'cso'
        list_type = params.get('LIST', 'B')
        
        print(f"BUDDY: RADD mirrored for {session.clientNAME} -> {lrsc} (ID={req_id})")
        
        # NASCAR 2004 check: The response should contain the mirrored fields.
        response_lines = [
            f"NAME={session.clientNAME}",
            f"USER={session.clientNAME}",
            f"LRSC={lrsc}",
            f"ID={req_id}",
            f"LIST={list_type}",
            "S=0",
            "STATUS=1"
        ]
        
        return self.create_packet('RADD', '', '\n'.join(response_lines) + '\n')
    
    def handle_rdel(self, params, session):
        """Handle RDEL - Delete from roster"""
        print(f"BUDDY RDEL: {session.clientNAME} - {params}")
        
        param_dict = self.parse_params(params)
        op_type = int(param_dict.get('ID', '1'))
        target_user = self.process_username(param_dict.get('USER', ''))
        
        if not target_user:
            return self.create_packet('RDEL', '', "STATUS=0\nERROR=No user specified\n")
            
        # Initialize buddy list if needed
        if session.clientNAME not in self.buddy_lists:
            self.buddy_lists[session.clientNAME] = []
            
        buddies = self.buddy_lists[session.clientNAME]
        
        # Remove buddy if exists
        for i, buddy in enumerate(buddies):
            if buddy.username == target_user:
                del buddies[i]
                print(f"BUDDY: Removed {target_user} from {session.clientNAME}'s list")
                break
                
        response_lines = [
            f"ID={op_type}",
            f"USER={target_user}",
            "STATUS=1"
        ]
        
        return self.create_packet('RDEL', '', '\n'.join(response_lines) + '\n')
    
    def parse_params(self, param_string):
        """Parse KEY=VALUE parameters into dictionary"""
        params = {}
        for line in param_string.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                params[key.strip()] = value.strip()
        return params
    
    def update_buddy_status(self, username, online=True):
        """Update online status for a user across all buddy lists"""
        for buddy_list in self.buddy_lists.values():
            for buddy in buddy_list:
                if buddy.username == username:
                    buddy.online = online
                    buddy.last_seen = time.time() if not online else buddy.last_seen