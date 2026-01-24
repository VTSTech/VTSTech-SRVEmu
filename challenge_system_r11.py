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
        self.states = {0: "INACTIVE", 1: "PENDING", 2: "DECLINED", 3: "BLOCKED", 4: "ACCEPTED", 6: "READY", 7: "NETWORK_VERIFYING", 9: "EXPIRED"}
    
    def handle_auxi(self, data, session):
        if not hasattr(session, 'selected_target') or not session.selected_target:
            print(f"AUXI ERROR: {session.clientNAME} has no selected target")
            return self.create_packet('auxi', '', "S=0\nSTATUS=0\nERROR=No target selected\n")
        
        data_str = data.decode('latin1') if data else ""
        print(f"AUXI: Challenge initiation from {session.clientNAME} to {session.selected_target}")
        
        challenge_token = ""
        for line in data_str.split('\n'):
            if line.startswith('TEXT='):
                challenge_token = line[5:].strip()
                break
        
        if not challenge_token:
            timestamp = int(time.time())
            random_num = random.randint(1000, 9999)
            challenge_token = f"{timestamp}_{random_num}_{session.current_persona}_{session.selected_target}"
        
        print(f"AUXI: Generated token: {challenge_token}")
        
        session.challenge_state = 1
        session.challenger = session.current_persona
        session.challenge_target = session.selected_target
        session.challenge_token = challenge_token
        session.challenge_timeout = time.time() + 30
        
        target_session = None
        target_conn_id = None
        
        for conn_id, user_data in self.active_users.items():
            if user_data.get('persona') == session.selected_target:
                target_conn_id = conn_id
                if conn_id in self.client_sessions:
                    target_session = self.client_sessions[conn_id]
                break
        
        if target_session and hasattr(target_session, 'connection'):
            notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=3\n"
            try:
                target_session.connection.sendall(self.create_packet('+msg', '', notification))
                print(f"AUXI: Sent challenge notification to {session.selected_target}")
                
                target_session.challenge_state = 1
                target_session.challenger = session.current_persona
                target_session.challenge_token = challenge_token
                target_session.challenge_timeout = time.time() + 30
            except Exception as e:
                print(f"AUXI: Error sending notification: {e}")
                return self.create_packet('auxi', '', "S=0\nSTATUS=0\nERROR=Could not send challenge\n")
        
        response = f"TEXT={challenge_token}\nS=0\nSTATUS=0\n"
        return self.create_packet('auxi', '', response)
    
    def handle_mesg(self, data, session):
		        data_str = data.decode('latin1') if data else ""
		        
		        is_challenge_response = False
		        response_type = ""
		        response_target = ""
		        
		        # 1. PARSE CHALLENGE RESPONSES (ACPT/DECL/BLOC)
		        for line in data_str.split('\n'):
		            line = line.strip()
		            if line.startswith('PRIV=') or line.startswith('N='):
		                response_target = line.split('=', 1)[1].strip()
		            elif line.startswith('TEXT=') or line.startswith('T='):
		                response_text = line.split('=', 1)[1].strip().upper()
		                if response_text in ['ACPT', 'DECL', 'BLOC']:
		                    is_challenge_response = True
		                    response_type = response_text
		        
		        if is_challenge_response:
		            print(f"MESG: Challenge response from {session.clientNAME}: {response_type} to {response_target}")
		            return self.handle_challenge_response(session, response_target, response_type)
		        
		        # 2. PARSE CHALLENGE INITIATION
		        is_challenge_initiation = False
		        target_user = ""
		        challenge_token = ""
		        
		        for line in data_str.split('\n'):
		            line = line.strip()
		            if line.startswith('PRIV=') or line.startswith('N='):
		                target_user = line.split('=', 1)[1].strip()
		            elif line.startswith('TEXT='):
		                challenge_token = line.split('=', 1)[1].strip()
		                # If it's a token and not a response keyword, it's an initiation
		                if challenge_token and challenge_token not in ['ACPT', 'DECL', 'BLOC']:
		                    is_challenge_initiation = True
		            elif line.startswith('ATTR='):
		                if line.split('=', 1)[1].strip() == '3':
		                    is_challenge_initiation = True
		        
		        # 3. HANDLE CHALLENGE INITIATION
		        if is_challenge_initiation and target_user and challenge_token:
		            print(f"MESG: Challenge initiation from {session.clientNAME} to {target_user} with token {challenge_token}")
		            
		            # Set Sender State
		            session.challenge_state = 1 # PENDING
		            session.challenger = session.current_persona
		            session.challenge_target = target_user
		            session.challenge_token = challenge_token
		            session.challenge_timeout = time.time() + 30
		            sender_room_id = getattr(session, 'room_id', 0)
		            target_session = None
		            for conn_id, other_session in self.client_sessions.items():
		                if hasattr(other_session, 'current_persona') and other_session.current_persona == target_user:
		                    target_session = other_session
		                    break
		            
		            if target_session and hasattr(target_session, 'connection'):
		                try:
		                    # FIX: Deliver UI Trigger to Target
		                    # We use F=3 and TYPE=CHALLENGE to trigger the Accept/Decline popup
		                    notification = (
													f"FROM={session.persona}\n"
													    f"TEXT={challenge_token}\n"
													    f"F=1\n" # Flag 1 often triggers the 'Proposal' state
													    f"ATTR=3\n"
													    f"RI={sender_room_id}\n" # Explicitly include the Room ID
													    f"PRIV={target_user}\n"
													)
		                    print(f"[DEBUG]", notification)
		                    target_session.connection.sendall(self.create_packet('+msg', '', notification))
		                    print(f"MESG: Sent UI Challenge notification to {target_user}")
		                    
		                    # Set Target State
		                    target_session.challenge_state = 1 # PENDING
		                    target_session.challenger = session.clientNAME
		                    target_session.challenge_token = challenge_token
		                    target_session.challenge_timeout = time.time() + 30
		                    
		                except Exception as e:
		                    print(f"MESG: Error sending notification: {e}")
		                    return self.create_packet('mesg', '', "S=0\nSTATUS=0\nERROR=Could not send challenge\n")
		            
		            # Response back to the Sender (VTSTech)
		            response = f"TEXT={challenge_token}\nS=0\nSTATUS=0\n"
		            return self.create_packet('mesg', '', response)
		        
		        # 4. ROUTE TO STANDARD CHAT
		        print(f"MESG: Routing to message system (non-challenge message)")
		        if hasattr(self, 'message_handlers'):
		            return self.message_handlers.handle_mesg(data, session)
		        else:
		            return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")

    
    def handle_user(self, data, session):
        data_str = data.decode('latin1') if data else ""
        print(f"USER: Target selection: {data_str}")
        
        target_persona = ""
        for line in data_str.split('\n'):
            if line.startswith('PERS='):
                target_persona = line[5:].strip()
                break
        
        if not target_persona:
            return self.create_packet('user', '', "S=0\nSTATUS=0\nERROR=No target specified\n")
        
        print(f"USER: {session.clientNAME} selected target: {target_persona}")
        session.selected_target = target_persona
        
        target_found = False
        target_conn_id = None
        
        for conn_id, user_data in self.active_users.items():
            if user_data.get('persona') == target_persona:
                target_found = True
                target_conn_id = conn_id
                break
        
        if not target_found:
            for conn_id, user_data in self.active_users.items():
                if user_data.get('username') == target_persona:
                    target_found = True
                    target_conn_id = conn_id
                    break
        
        if target_found and target_conn_id in self.client_sessions:
            target_session = self.client_sessions[target_conn_id]
            response = f"PERS={target_persona}\nTITLE=1\nS=0\nSTATUS=0\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n"
            print(f"USER: Found target {target_persona} in room {target_session.current_room}")
        else:
            response = f"PERS={target_persona}\nTITLE=0\nS=0\nSTATUS=0\nERROR=User not found\n"
            print(f"USER: Target {target_persona} not found")
        
        return self.create_packet('user', '', response)
    
    def handle_chal(self, data, session):
        current_state = getattr(session, 'challenge_state', 0)
        
        if current_state == 0:
            return self.create_packet('chal', '', "S=0\nSTATUS=0\n")
        else:
            session.challenge_state = 0
            session.challenger = ''
            return self.create_packet('chal', '', "S=0\nSTATUS=0\n")
    
    def handle_challenge_response(self, session, target_user, response):
        print(f"[CHALLENGE] {session.clientNAME} responded: {response} to {target_user}")
        
        challenger_session = None
        if target_user:
            challenger_session = self.find_user_session(target_user)
        elif hasattr(session, 'challenger'):
            challenger_session = self.find_user_session(session.challenger)
        
        state_map = {'ACPT': 4, 'DECL': 2, 'BLOC': 3}
        new_state = state_map.get(response, 0)
        session.challenge_state = new_state
        
        if challenger_session:
            challenger_session.challenge_state = new_state
            if response == 'ACPT':
                self.start_race_between_players(challenger_session, session)
        
        return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")
    
    def find_user_session(self, username):
        for session in self.client_sessions.values():
            if session.clientNAME == username:
                return session
        return None
    
    def start_race_between_players(self, challenger_session, target_session):
        print(f"STARTING RACE: {challenger_session.current_persona} vs {target_session.current_persona}")
        
        challenger_session.challenge_state = 6
        target_session.challenge_state = 6
        
        session_data = self.create_272_byte_session_data(challenger_session, target_session)
        play_response = f"SELF=1\nHOST=1\nOPPO=0\nP1=1\nP2=0\nP3=0\nP4=0\nAUTH=1\nFROM={challenger_session.current_persona}\nSEED={int(time.time())}\nWHEN={int(time.time())}\nS=0\nSTATUS=0\n"
        
        try:
            challenger_session.connection.sendall(self.create_packet('play', '', play_response))
            time.sleep(0.5)
            challenger_session.connection.sendall(self.create_packet('+ses', '', session_data))
            print(f"RACE: Sent play command to challenger {challenger_session.current_persona}")
        except Exception as e:
            print(f"RACE: Error sending to challenger: {e}")
        
        try:
            target_session.connection.sendall(self.create_packet('play', '', play_response))
            time.sleep(0.5)
            target_session.connection.sendall(self.create_packet('+ses', '', session_data))
            print(f"RACE: Sent play command to target {target_session.current_persona}")
        except Exception as e:
            print(f"RACE: Error sending to target: {e}")
    
    def create_272_byte_session_data(self, host_session, guest_session):
		    # Initialize 272 null bytes
		    blob = bytearray(272)
		    
		    try:
		        # Use the captured address from the 'addr' command
		        # If addr is "1.2.3.4", inet_aton converts it to \x01\x02\x03\x04
		        ip_addr = host_session.direct_address if host_session.direct_address else "0.0.0.0"
		        ip_bytes = socket.inet_aton(ip_addr)
		        
		        # Use the captured port (default for NC04 is often 10600 or what's in 'addr')
		        port = int(host_session.direct_port) if host_session.direct_port else 10600
		        
		        # Pack IP and Port at the start
		        struct.pack_into(">4sH", blob, 0, ip_bytes, port)
		        
		        # Pack Persona Name at 0x10 (Ghidra shows a 32-byte buffer)
		        persona = host_session.current_persona.encode('latin1')
		        struct.pack_into("32s", blob, 0x10, persona[:32])
		        
		        # Set the Host/Client flag at 0x30
		        # If this session is the one receiving the packet, tell it if it's host
		        is_host = 1 if host_session == guest_session else 0
		        struct.pack_into(">I", blob, 0x30, is_host)
		        
		        # NASCAR often expects a 'Seed' or 'Key' at 0x44 to sync the RNG
		        struct.pack_into(">I", blob, 0x44, int(time.time()) & 0xFFFFFFFF)

		    except Exception as e:
		        print(f"SESSION BLOB ERROR: {e}")
		        
		    return bytes(blob)
    
    def ChallengeCallback_Cleanup(self, session):
        if hasattr(session, 'challenge_state') and session.challenge_state != 0:
            print(f"[CHALLENGE] Cleaning up {session.connection_id}")
            session.challenge_state = 0
            session.challenger = ''
            session.challenge_target = None
    
    def update_challenge_state(self, session):
        current_time = time.time()
        
        if hasattr(session, 'challenge_state') and session.challenge_state == 1:
            if hasattr(session, 'challenge_timeout') and current_time > session.challenge_timeout:
                print(f"CHALLENGE: Timeout for {session.current_persona}")
                session.challenge_state = 9
                
                if hasattr(session, 'challenger'):
                    for conn_id, other_session in self.client_sessions.items():
                        if other_session.current_persona == session.challenger:
                            notification = f"FROM={session.current_persona}\nTEXT=Challenge expired\nF=0x3\n"
                            try:
                                other_session.connection.sendall(self.create_packet('+msg', '', notification))
                            except:
                                pass
                            break
    
    def ChallengeState_Get(self, session):
        return getattr(session, 'challenge_state', 0)