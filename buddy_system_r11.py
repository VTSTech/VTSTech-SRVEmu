# buddy_system_r11.py - COMPLETE BUDDY API IMPLEMENTATION
import time

class BuddyUser:
    def __init__(self, username, friendly_name=None, group="Default"):
        self.username = username
        self.friendly_name = friendly_name or username
        self.group = group
        self.online = False
        self.last_seen = time.time()
        
class BuddyHandlers:
    def __init__(self, create_packet_func, active_users_dict):
        self.create_packet = create_packet_func
        self.active_users = active_users_dict
        self.buddy_lists = {}  # user -> list of BuddyUser objects
        self.user_profiles = {}  # user -> profile data
        
    def process_username(self, username):
        """Normalize username - strip @ and / characters and everything after"""
        if '@' in username:
            username = username.split('@')[0]
        if '/' in username:
            username = username.split('/')[0]
        return username
    
    def handle_buddy_command(self, data, session):
		        """Modified to handle headerless login blocks found in NASCAR 2004"""
		        data_str = data.decode('latin1') if data else ""
		        
		        # HEADERLESS LOGIN DETECTOR
		        # If the packet starts with PROD= or USER=, it's the NASCAR login block
		        if data_str.startswith("PROD=") or data_str.startswith("USER="):
		            print(f"BUDDY API: Received Headerless Login Block")
		            params = self.parse_params(data_str)
		            
		            # Validate LKEY against the one stored in session from Lobby
		            incoming_lkey = params.get("LKEY", "$0")
		            print(f"BUDDY API: Login for {params.get('USER')} with LKEY {incoming_lkey}")
		            
		            # The PS2 expects a simple STATUS=0 to proceed to actual commands
		            return b"STATUS=0\n\0"

		        # STANDARD COMMAND DISPATCHER
		        if len(data_str) >= 4:
		            command = data_str[:4]
		            params_str = data_str[4:].strip()
		            params = self.parse_params(params_str)
		            
		            if command == 'RGET': return self.handle_rget(params, session)
		            # Add other handlers as needed (RADD, RDEL, etc.)
		            
		        print(f"BUDDY API: Unknown format or command: {data_str[:10]}...")
		        return b"STATUS=0\n\0"
    
    def handle_rget(self, params, session):
        """Handle RGET - Retrieve buddy data"""
        print(f"BUDDY RGET: {session.clientNAME} - {params}")
        
        # Parse parameters
        param_dict = self.parse_params(params)
        op_type = int(param_dict.get('ID', '1'))
        request_type = int(param_dict.get('SIZE', '0'))
        target_user = param_dict.get('USER', '')
        
        # Initialize buddy list if needed
        if session.clientNAME not in self.buddy_lists:
            self.buddy_lists[session.clientNAME] = []
            
        buddies = self.buddy_lists[session.clientNAME]
        
        response_lines = []
        
        if op_type == 2 and request_type == 0:
            # Return buddy count and list
            response_lines.extend([
                f"ID={op_type}",
                f"SIZE={len(buddies)}",
                f"COUNT={len(buddies)}"
            ])
            
            for i, buddy in enumerate(buddies):
                response_lines.extend([
                    f"USER{i}={buddy.username}",
                    f"FUSR{i}={buddy.friendly_name}",
                    f"GROUP{i}={buddy.group}",
                    f"STATUS{i}={1 if buddy.online else 0}"
                ])
                
        response_lines.append("STATUS=1")
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
    
    def handle_radd(self, params, session):
        """Handle RADD - Add to roster"""
        print(f"BUDDY RADD: {session.clientNAME} - {params}")
        return self.handle_rost(params, session)  # Same as ROST for adding
    
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