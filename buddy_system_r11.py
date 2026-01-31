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
        self.user_attributes = {}
        
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
        cmd_str = command.strip()
        payload = data[12:].decode('latin1', errors='ignore')
        print(f"[BuddyApi DEBUG] Command: {command} | Payload: {payload[:30]}...")
        if cmd_str == 'PSET':
            return self.handle_pset(payload, session)
        elif cmd_str == 'PGET':
            return self.handle_pget(payload, session)
        elif cmd_str == 'RADD':
            return self.handle_radd(payload, session)
        elif cmd_str == 'RGET':
            return self.handle_rget(payload, session)
        elif cmd_str == 'ROST':
            return self.handle_rost(payload, session)
        elif cmd_str == 'SEND':
            return self.handle_send(payload, session)
        elif cmd_str == 'AUTH':
            return self.handle_auth(payload, session)
        
        return self.create_packet(cmd_str, '', "STATUS=1\n")

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

    def handle_rget(self, payload, session):
        """Processes RGET: Returns specific roster categories"""
        params = self.parse_params(payload)
        list_type = params.get('T', 'B')
        
        # Return empty list if no buddies to avoid client hang
        response = f"T={list_type}\nCOUNT=0\nSTATUS=1\n"
        return self.create_packet('RGET', '', response)

    def handle_pset(self, payload, session):
        """Processes PSET: Updates attributes found via TagFieldGetString in the_blob"""
        params = self.parse_params(payload)
        persona = session.clientNAME
        
        if persona not in self.user_attributes:
            self.user_attributes[persona] = {}

        for k, v in params.items():
            # Store the attribute (e.g., AT="is playing NASCAR...")
            self.user_attributes[persona][k] = v
            print(f"BUDDY PSET: {persona} updated {k}")

        return self.create_packet('PSET', '', "STATUS=1\n")

    def handle_pget(self, payload, session):
        """Processes PGET: Returns persona data for P2P sync"""
        params = self.parse_params(payload)
        target = params.get('USER', session.clientNAME)
        
        # Look up stored attributes
        attrs = self.user_attributes.get(target, {})
        response = f"USER={target}\n"
        for k, v in attrs.items():
            response += f"{k}={v}\n"
        response += "STATUS=1\n"
        
        return self.create_packet('PGET', '', response)

    def handle_radd(self, payload, session):
        params = self.parse_params(payload)
        buddy_name = params.get('USER')
        list_type = params.get('LIST', 'B')
        
        if session.clientNAME not in self.buddy_lists:
            self.buddy_lists[session.clientNAME] = []

        if buddy_name and not any(b.username == buddy_name for b in self.buddy_lists[session.clientNAME]):
            self.buddy_lists[session.clientNAME].append(BuddyUser(buddy_name))
            print(f"BUDDY RADD: {session.clientNAME} added {buddy_name}")

        # The Blob insight: Echo back the exact context of the add
        response = (f"USER={buddy_name}\n"
                    f"LIST={list_type}\n"
                    f"STATUS=1\n")
        
        # We return the RADD ack, but we might need to bundle a +usr update
        radd_ack = self.create_packet('RADD', '', response)
        
        # Check if the buddy is online to send a status update immediately
        status_update = b""
        if self.is_user_online(buddy_name):
            # Send a +usr packet specifically for this new buddy 
            # so the "Adding..." dialog closes and the icon lights up
            status_update = self.create_packet('+usr', '', f"N={buddy_name}\nST=1\nF=0\n")
            
        return radd_ack + status_update

    def handle_rost(self, payload, session):
        my_buddies = self.buddy_lists.get(session.clientNAME, [])
        
        response = f"COUNT={len(my_buddies)}\n"
        for i, buddy in enumerate(my_buddies):
            online_status = "1" if self.is_user_online(buddy.username) else "0"
            # Insight: Some NASCAR versions check for the RI tag in the roster
            response += f"USER{i}={buddy.username}\nONLINE{i}={online_status}\nRI{i}=0\n"
        
        response += "STATUS=1\n"
        return self.create_packet('ROST', '', response)

    def is_user_online(self, username):
        """Helper to check session manager for online status"""
        with self.session_manager.session_lock:
            return any(s.clientNAME == username for s in self.session_manager.client_sessions.values())

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

    def handle_send(self, payload, session):
        """Processes SEND: Direct Message/Invite logic from Buddy_ProcessSendCommand"""
        params = self.parse_params(payload)
        target_user = params.get('USER') or params.get('TO')
        message_text = params.get('BODY', '')
        # SECS=259200 from your log (3 days) indicates a persistent or invite message
        expiry = params.get('SECS', '0') 
        
        # Determine the transaction ID to mirror (often passed in the raw header or payload)
        # Your log showed 'RADD | Payload: 106', mirroring that ID is key to clearing hangs.
        msg_id = params.get('ID', '0')

        # Delivery logic
        target_session = None
        with self.session_manager.session_lock:
            for s in self.session_manager.client_sessions.values():
                if s.clientNAME == target_user:
                    target_session = s
                    break

        status = "0"
        if target_session:
            # Mirroring the structure expected by MessageRouting_ChallengeHandler in the blob
            incoming_msg = (f"FROM={session.clientNAME}\n"
                            f"TEXT={message_text}\n"
                            f"ID={msg_id}\n"
                            f"PRIV=1\n")
            try:
                # Send as a notification (+not) or message (+msg)
                # NASCAR often uses +not for system-level invites (SECS > 0)
                cmd = '+msg'
                target_session.connection.sendall(self.create_packet(cmd, '', incoming_msg))
                status = "1"
                print(f"BUDDY SEND: {session.clientNAME} -> {target_user} ({cmd})")
            except: 
                pass
        
        # Return confirmation to the sender
        # Echoing the USER and ID back is what clears the sender's "Waiting" dialog
        return self.create_packet('SEND', '', f"USER={target_user}\nID={msg_id}\nSTATUS={status}\n")
        
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