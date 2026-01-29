# challenge_system_r11.py - OPTIMIZED CHALLENGE SYSTEM
import time, struct, threading, random, socket

class ChallengeSystem:
    def __init__(self, create_packet_func, active_users, client_sessions, session_manager, room_manager, message_handlers=None):
        self.create_packet = create_packet_func
        self.active_users = active_users
        self.client_sessions = client_sessions
        self.session_manager = session_manager
        self.room_manager = room_manager
        self.message_handlers = message_handlers
        self.ai_map = {"9zojk": 0, "a016o": 1, "a0dtt": 6, "a0qgx": 7}
        self.track_map = {
            "tys5u": 0, "u1laq": 1, "ue8eq": 2, "u2zv6": 3,
            "u77ki": 4, "utonm": 5, "v3imq": 6, "viyvm": 7,
            "w5fyq": 8, "wf9xu": 9, "wqihe": 10, "w893m": 11 # Added NY/Recent
        }
        self.states = {0: "INACTIVE", 1: "PENDING", 2: "DECLINED", 3: "BLOCKED", 4: "ACCEPTED", 6: "READY", 7: "NETWORK_VERIFYING", 9: "EXPIRED"}

    def create_packet(self, cmd, sub, data):
		        # Helper to mirror the server's packet creation
		        from server_r12 import create_packet
		        return create_packet(cmd, sub, data)
        
    def get_track_id_from_token(self, token):
		        """Maps NASCAR tokens to internal Track IDs for +ses blob."""
		        # Mapping the first 5 chars to track ID
		        track_map = {
		            "tys5u": 0,  # Daytona 500
		            "u1laq": 1,  # Darlington
		            "ue8eq": 2,  # Indianapolis
		            "u2zv6": 3,  # Bristol
		            "u77ki": 4,  # California
		            "utonm": 5,  # Homestead-Miami
		            "v3imq": 6,  # Chicagoland
		            "viyvm": 7,  # Dover
		            "w5fyq": 8,  # Atlanta
		            "wf9xu": 9,  # New York
		            "wqihe": 10, # Talladega
		            "w893m": 11, # Daytona
		        }
		        
		        prefix = token[:5].lower()
		        # Returns the found ID, or 11 (Daytona) if unknown
		        return track_map.get(prefix, 11)
    def find_user_session(self, persona_name):
        for session in self.client_sessions.values():
            if session.current_persona == persona_name:
                return session
        return None
        
    def handle_mesg(self, data, session):
        data_str = data.decode('latin1') if data else ""
        lines = [line.strip() for line in data_str.split('\n') if line.strip()]
        
        # Parse fields into a dictionary for easier access
        fields = {}
        for line in lines:
            if '=' in line:
                k, v = line.split('=', 1)
                fields[k] = v

        target_user = fields.get('PRIV') or fields.get('N')
        text_payload = fields.get('TEXT') or fields.get('T', "")

        # 1. PREVENT LOOPBACK (Challenging self)
        if target_user == session.current_persona:
            print(f"MESG: Blocked self-challenge for {session.clientNAME}")
            return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")

        # 2. HANDLE CHALLENGE RESPONSES (ACPT/DECL/BLOC)
        response_type = text_payload.upper()
        if response_type in ['ACPT', 'DECL', 'BLOC']:
            return self.handle_challenge_response(session, target_user, response_type)

        # 3. HANDLE CHALLENGE INITIATION (Token)
        if text_payload and fields.get('ATTR') == '3':
            return self.initiate_challenge(session, target_user, text_payload)

        # 4. ROUTE TO STANDARD CHAT
        if self.message_handlers:
            return self.message_handlers.handle_mesg(data, session)
        return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")

    def handle_auxi(self, data, session):
		        """Step 1: Store the track settings."""
		        # Extract TEXT=w893m_a016o_g
		        token = self.extract_param(data, "TEXT")
		        session.current_token = token
		        return create_packet('auxi', '', "S=0\nSTATUS=0\n")

    def handle_system_command(self, data, session):
        """Handles internal engine commands."""
        return self.create_packet('sysc', '', "S=0\nSTATUS=0\n")
        
    def handle_user(self, data_str, session):
		        params = self.parse_params(data_str)
		        search_term = params.get('PERS', '').strip()
		        
		        print(f"[CHALLENGE] Searching for persona: {search_term}")
		        
		        found_session = None
		        # Use the session_manager to find the real user
		        for s in self.session_manager.client_sessions.values():
		            name = getattr(s, 'clientNAME', '')
		            if name.lower() == search_term.lower():
		                found_session = s
		                break
		                
		        if found_session:
		            print(f"[CHALLENGE] Found user: {found_session.clientNAME}")
		            response = (
		                f"PERS={found_session.clientNAME}\n"
		                f"NAME={found_session.clientNAME}\n"
		                f"USERID={found_session.session_id}\n"
		                f"SESS={found_session.session_id}\n"
		                f"MASK=0\n"
		                f"STATUS=0\n"
		            )
		        else:
		            print(f"[CHALLENGE] User '{search_term}' not found.")
		            response = f"PERS={search_term}\nSTATUS=1\n"

		        # ENCODE TO BYTES HERE to prevent the "bytes-like object" error
		        return self.create_packet("user", "", response.encode('latin1'))
		        
    def initiate_challenge(self, session, target_user, token):
        target_session = self.find_user_session(target_user)
        if not target_session:
            return self.create_packet('mesg', '', "STATUS=102\nERROR=User Offline\n")

        # Get the numeric ID bridged from room_system
        sender_id = getattr(session, 'unique_id', 0)
        
        # Build the packet that triggers the Blue Modal
        notification = (
            f"FROM={sender_id}\n"
            f"TEXT={token}\n"
            f"PRIV=1\n"
            f"ATTR=3\n"
            f"RI={getattr(session, 'current_room_id', 0)}\n"
            f"S=0\n"
            f"STATUS=0\n"
        )
        
        # Push to the target client
        target_session.connection.sendall(self.create_packet('+msg', '', notification))
        
        # Update states
        session.challenge_state = 1
        target_session.challenge_state = 1
        target_session.challenger = session.current_persona
        
        return self.create_packet('mesg', '', f"TEXT={token}\nS=0\nSTATUS=0\n")

    def handle_challenge_response(self, session, target_user, response):
        print(f"[CHALLENGE] {session.clientNAME} responded: {response}")
        
        # If target_user isn't provided, check who challenged this session
        challenger_name = target_user or getattr(session, 'challenger', None)
        challenger_session = self.find_user_session(challenger_name)

        new_state = {'ACPT': 4, 'DECL': 2, 'BLOC': 3}.get(response, 0)
        session.challenge_state = new_state

        if challenger_session:
            challenger_session.challenge_state = new_state
            
            # If accepted, trigger race sequence
            if response == 'ACPT':
                # Pass the track ID stored in the challenger's session
                track_id = getattr(challenger_session, 'selected_track_id', 0)
                self.start_race_between_players(challenger_session, session, track_id)
            else:
                # Notify challenger of decline/block
                decl_msg = f"FROM={session.current_persona}\nTEXT={response}\nF=1\n"
                challenger_session.connection.sendall(self.create_packet('+msg', '', decl_msg))

        return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")

    def start_race_between_players(self, challenger, target, track_id):
        print(f"RACE START: {challenger.current_persona} (Host) vs {target.current_persona} (Guest)")
        
        # Build the session blob
        session_data = self.create_272_byte_session_data(challenger, target, track_id)
        
        # Core Play response
        play_response = (
            f"SELF=1\nHOST=1\nOPPO=0\n"
            f"FROM={challenger.current_persona}\n"
            f"SEED={int(time.time())}\nS=0\nSTATUS=0\n"
        )

        # Send to both. Timing is key: Play MUST arrive before +ses
        for s in [challenger, target]:
            s.challenge_state = 6 # READY
            s.connection.sendall(self.create_packet('play', '', play_response))
            time.sleep(0.1) 
            s.connection.sendall(self.create_packet('+ses', '', session_data))

    def create_272_byte_session_data(self, host_session, guest_session):
		        """Packs variables into the binary +ses structure defined in our spec."""
		        # Initialize 272 bytes of zeros
		        blob = bytearray(272)
		        
		        # Offset 0x00: Host ID (Assuming session IDs are numeric)
		        struct.pack_into(">I", blob, 0x00, int(host_session.connection_id or 0))
		        
		        # Offset 0x18: Track ID (Short)
		        struct.pack_into(">H", blob, 0x18, getattr(host_session, 'selected_track_id', 0))
		        
		        # Offset 0x20: Host Persona (32 bytes)
		        name_bytes = host_session.clientNAME.encode('latin1')[:31]
		        blob[0x20:0x20+len(name_bytes)] = name_bytes
		        
		        # Offset 0x30: Host IP (Critical for UDP P2P)
		        # Convert "192.168.1.1" to 4-byte integer
		        import socket
		        try:
		            ip_packed = socket.inet_aton(host_session.direct_address)
		            blob[0x30:0x34] = ip_packed
		        except: pass
		        
		        # Offset 0x44: UDP Port (Short)
		        struct.pack_into(">H", blob, 0x44, 11000)
		        
		        # Offset 0x46: AI Count (Byte)
		        blob[0x46] = getattr(host_session, 'ai_count', 0)
		        
		        return blob

    def find_user_session(self, persona_name):
        if not persona_name: return None
        for session in self.client_sessions.values():
            if session.current_persona == persona_name:
                return session
        return None

    def ChallengeState_Get(self, session):
		        """Returns the current numeric state of the challenge for the session."""
		        return getattr(session, 'challenge_state', 0)

    def ChallengeCallback_Cleanup(self, session):
        """Resets challenge variables when a client disconnects or the race finishes."""
        if hasattr(session, 'challenge_state'):
            print(f"[CHALLENGE] Cleaning up state for {session.current_persona}")
            session.challenge_state = 0
            session.challenger = None
            session.challenge_target = None
            session.challenge_token = None
            if hasattr(session, 'selected_track_id'):
                del session.selected_track_id

    def update_challenge_state(self, session):
        """Tick function called by the main loop to handle challenge timeouts."""
        current_time = time.time()
        if getattr(session, 'challenge_state', 0) == 1: # PENDING
            if hasattr(session, 'challenge_timeout') and current_time > session.challenge_timeout:
                print(f"CHALLENGE: Timeout for {session.current_persona}")
                session.challenge_state = 9 # EXPIRED
                self.ChallengeCallback_Cleanup(session)
                
    def parse_params(self, param_data):
		        """Safely parse parameters from bytes or string"""
		        if isinstance(param_data, bytes):
		            param_data = param_data.decode('latin1', errors='ignore')
		            
		        params = {}
		        for line in param_data.split('\n'):
		            if '=' in line:
		                key, value = line.split('=', 1)
		                params[key.strip()] = value.strip()
		        return params      