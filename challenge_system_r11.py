# challenge_system_r11.py - OPTIMIZED CHALLENGE SYSTEM
import time, struct, threading, random

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
            return self.create_packet('auxi', '', "STATUS=0\nERROR=No target selected\n")
        
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
                return self.create_packet('auxi', '', "STATUS=0\nERROR=Could not send challenge\n")
        
        response = f"TEXT={challenge_token}\nSTATUS=1\n"
        return self.create_packet('auxi', '', response)
    
    def handle_mesg(self, data, session):
        data_str = data.decode('latin1') if data else ""
        
        is_challenge_response = False
        response_type = ""
        response_target = ""
        
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
        
        is_challenge_initiation = False
        target_user = ""
        challenge_token = ""
        
        for line in data_str.split('\n'):
            line = line.strip()
            if line.startswith('PRIV=') or line.startswith('N='):
                target_user = line.split('=', 1)[1].strip()
            elif line.startswith('TEXT='):
                challenge_token = line.split('=', 1)[1].strip()
                if challenge_token and challenge_token not in ['ACPT', 'DECL', 'BLOC']:
                    is_challenge_initiation = True
            elif line.startswith('ATTR='):
                if line.split('=', 1)[1].strip() == '3':
                    is_challenge_initiation = True
        
        if is_challenge_initiation and target_user and challenge_token:
            print(f"MESG: Challenge initiation from {session.clientNAME} to {target_user} with token {challenge_token}")
            
            session.challenge_state = 1
            session.challenger = session.current_persona
            session.challenge_target = target_user
            session.challenge_token = challenge_token
            session.challenge_timeout = time.time() + 30
            
            target_session = None
            for conn_id, other_session in self.client_sessions.items():
                if hasattr(other_session, 'current_persona') and other_session.current_persona == target_user:
                    target_session = other_session
                    break
            
            if target_session and hasattr(target_session, 'connection'):
                try:
                    notification = f"TEXT={challenge_token}\n"
                    target_session.connection.sendall(self.create_packet('auxi', '', notification))
                    #notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\n"
                    #target_session.connection.sendall(self.create_packet('mesg', '', notification))
                    #notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\n"
                    #target_session.connection.sendall(self.create_packet('mesg', '', notification))
                    #notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\n"
                    #target_session.connection.sendall(self.create_packet('mesg', '', notification))                                        
                    notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\nF=4\n"
                    target_session.connection.sendall(self.create_packet('+msg', '', notification))
                    #notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\n"
                    #target_session.connection.sendall(self.create_packet('+msg', '', notification))
                    #notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\n"
                    #target_session.connection.sendall(self.create_packet('+msg', '', notification))
                    #notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=1073741824\n"
                    #target_session.connection.sendall(self.create_packet('+msg', '', notification))   
                    print(f"MESG: Sent challenge notification to {target_user}")
                    
                    target_session.challenge_state = 1
                    target_session.challenger = session.current_persona
                    target_session.challenge_token = challenge_token
                    target_session.challenge_timeout = time.time() + 30
                except Exception as e:
                    print(f"MESG: Error sending notification: {e}")
                    return self.create_packet('mesg', '', "STATUS=0\nERROR=Could not send challenge\n")
            
            response = f"TEXT={challenge_token}\nSTATUS=1\n"
            return self.create_packet('mesg', '', response)
        
        print(f"MESG: Routing to message system (non-challenge message)")
        
        if hasattr(self, 'message_handlers'):
            return self.message_handlers.handle_mesg(data, session)
        else:
            print(f"MESG ERROR: No message_handlers available")
            return self.create_packet('mesg', '', "STATUS=1\n")
    
    def handle_user(self, data, session):
        data_str = data.decode('latin1') if data else ""
        print(f"USER: Target selection: {data_str}")
        
        target_persona = ""
        for line in data_str.split('\n'):
            if line.startswith('PERS='):
                target_persona = line[5:].strip()
                break
        
        if not target_persona:
            return self.create_packet('user', '', "STATUS=0\nERROR=No target specified\n")
        
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
            response = f"PERS={target_persona}\nTITLE=1\nSTATUS=1\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n"
            print(f"USER: Found target {target_persona} in room {target_session.current_room}")
        else:
            response = f"PERS={target_persona}\nTITLE=0\nSTATUS=0\nERROR=User not found\n"
            print(f"USER: Target {target_persona} not found")
        
        return self.create_packet('user', '', response)
    
    def handle_chal(self, data, session):
        current_state = getattr(session, 'challenge_state', 0)
        
        if current_state == 0:
            return self.create_packet('chal', '', "STATUS=1\n")
        else:
            session.challenge_state = 0
            session.challenger = ''
            return self.create_packet('chal', '', "STATUS=0\n")
    
    def handle_peek(self, data, session):
		    """Handle peek command - get users in a specific ROOM"""
		    data_str = data.decode('latin1') if data else ""
		    
		    # Parse NAME field
		    target_name = ""
		    for line in data_str.split('\n'):
		        if line.startswith('NAME='):
		            target_name = line[5:].strip() # Added strip for safety
		            break
		    
		    print(f"[PEEK] from {session.clientNAME}: Looking for room '{target_name}'")
		    
		    # Find the room by name
		    target_room_id = None
		    target_room_data = None
		    
		    for room_id, room_data in self.room_manager.active_rooms.items():
		        if room_data.get('name') == target_name:
		            target_room_id = room_id
		            target_room_data = room_data
		            break
		    
		    if target_room_id is None:
		        print(f"[PEEK] Room '{target_name}' not found")
		        return self.create_packet('peek', '', "STATUS=0\nERROR=Room not found\n")
		    
		    # RECALCULATE count directly for 100% accuracy in the UI
		    actual_count = sum(1 for u in self.room_manager.active_users.values() 
		                     if u.get('room_id') == target_room_id)
		    
		    print(f"[PEEK] Found room {target_room_id}: {target_name} with {actual_count} users")
		    
		    # Build response
		    response_lines = [
		        f"I={target_room_id}",
		        f"N={target_name}",
		        f"H={target_room_data.get('desc', '')}",
		        f"T={target_room_data.get('type', 1)}", # Type is usually T or F depending on client
		        f"L={actual_count}", # FIX: Send active user count instead of a hardcoded limit
		        f"F=1",
		        f"STATUS=1"
		    ]
		    
		    # Add user list for this room
		    users_in_room = [u for u in self.room_manager.active_users.values() 
		                     if u.get('room_id') == target_room_id]
		                     
		    for i, user_data in enumerate(users_in_room):
		        persona = user_data.get('persona', '')
		        is_self = (user_data.get('conn_id') == session.connection_id)
		        f_flag = '1' if is_self else '0'
		        
		        response_lines.extend([
		            f"USER{i}_N={persona}",
		            f"USER{i}_F={f_flag}",
		            f"USER{i}_I={target_room_id}"
		        ])
		    
		    response = '\n'.join(response_lines) + '\n'
		    print("[PEEK DEBUG]", response)
		    return self.create_packet('peek', '', response)
    
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
        
        return self.create_packet('mesg', '', "STATUS=1\n")
    
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
        play_response = f"SELF=1\nHOST=1\nOPPO=0\nP1=1\nP2=0\nP3=0\nP4=0\nAUTH=1\nFROM={challenger_session.current_persona}\nSEED={int(time.time())}\nWHEN={int(time.time())}\nSTATUS=1\n"
        
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
    
    def create_272_byte_session_data(self, session1, session2=None):
        session_data = bytearray(272)
        session_data[0:4] = struct.pack(">I", 1)
        
        player1_name = session1.current_persona if hasattr(session1, 'current_persona') else 'Player1'
        session_data[4:20] = player1_name.ljust(16, '\0').encode('ascii')
        session_data[20:24] = struct.pack(">I", 1)
        
        if session2 and hasattr(session2, 'current_persona'):
            player2_name = session2.current_persona
            session_data[24:40] = player2_name.ljust(16, '\0').encode('ascii')
            session_data[40:44] = struct.pack(">I", 2)
        else:
            session_data[24:40] = 'Waiting...'.ljust(16, '\0').encode('ascii')
            session_data[40:44] = struct.pack(">I", 0)
        
        session_data[44:48] = struct.pack(">I", 10)
        session_data[48:52] = struct.pack(">I", 2)
        session_data[52:56] = struct.pack(">I", 1)
        session_data[56:60] = struct.pack(">I", 1)
        session_data[60:64] = struct.pack(">I", random.randint(1, 0xFFFFFFFF))
        session_data[64:68] = struct.pack(">I", int(time.time()))
        session_data[68:72] = struct.pack(">I", 1)
        session_data[72:76] = struct.pack(">I", 1)
        session_data[76:80] = struct.pack(">I", 0)
        session_data[80:84] = struct.pack(">I", 2)
        
        for i in range(84, 272, 4):
            session_data[i:i+4] = struct.pack(">I", 0)
        
        return bytes(session_data)
    
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