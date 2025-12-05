# challenge_system_r11.py - OPTIMIZED CHALLENGE SYSTEM
import time
import struct
import threading
import random

class ChallengeSystem:
    def __init__(self, create_packet_func, active_users, client_sessions, session_manager, room_manager, message_handlers=None):
        self.create_packet = create_packet_func
        self.active_users = active_users
        self.client_sessions = client_sessions
        self.session_manager = session_manager
        self.room_manager = room_manager
        self.message_handlers = message_handlers
        
        # Challenge states mapping
        self.states = {
            0: "INACTIVE", 1: "PENDING", 2: "DECLINED", 3: "BLOCKED",
            4: "ACCEPTED", 6: "READY", 7: "NETWORK_VERIFYING", 9: "EXPIRED"
        }

    # ===== COMMAND HANDLERS =====
    
    def handle_auxi(self, data, session):
        """Handle auxi command - challenge initiation"""
        if not hasattr(session, 'selected_target') or not session.selected_target:
            print(f"AUXI ERROR: {session.clientNAME} has no selected target")
            return self.create_packet('auxi', '', "STATUS=0\nERROR=No target selected\n")
        
        data_str = data.decode('latin1') if data else ""
        print(f"AUXI: Challenge initiation from {session.clientNAME} to {session.selected_target}")
        
        # Parse challenge token if present
        challenge_token = ""
        for line in data_str.split('\n'):
            if line.startswith('TEXT='):
                challenge_token = line[5:].strip()
                break
        
        # Generate challenge token if not provided
        if not challenge_token:
            timestamp = int(time.time())
            random_num = random.randint(1000, 9999)
            challenge_token = f"{timestamp}_{random_num}_{session.current_persona}_{session.selected_target}"
        
        print(f"AUXI: Generated token: {challenge_token}")
        
        # Store challenge state
        session.challenge_state = 1  # PENDING
        session.challenger = session.current_persona
        session.challenge_target = session.selected_target
        session.challenge_token = challenge_token
        session.challenge_timeout = time.time() + 30  # 30 second timeout
        
        # Find target session
        target_session = None
        target_conn_id = None
        
        for conn_id, user_data in self.active_users.items():
            if user_data.get('persona') == session.selected_target:
                target_conn_id = conn_id
                if conn_id in self.client_sessions:
                    target_session = self.client_sessions[conn_id]
                break
        
				# In the challenge acceptance logic where you need session data for 2 players:
        if challenger_session and target_session:
            # Create session data for both players
            session_data = self.create_272_byte_session_data(challenger_session, target_session)
            
            # Send to both players
            play_response = f"SELF=1\nHOST=1\nOPPO=0\nP1=1\nP2=0\nP3=0\nP4=0\nAUTH=1\nFROM={challenger_session.current_persona}\nSEED={int(time.time())}\nWHEN={int(time.time())}\nSTATUS=1\n"
            
            # Send to challenger
            challenger_session.connection.sendall(self.create_packet('play', '', play_response))
            time.sleep(0.5)
            challenger_session.connection.sendall(self.create_packet('+ses', '', session_data))
            
            # Send to target
            target_session.connection.sendall(self.create_packet('play', '', play_response))
            time.sleep(0.5)
            target_session.connection.sendall(self.create_packet('+ses', '', session_data))
        if target_session and hasattr(target_session, 'connection'):
            # Send challenge notification to target
            notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=3\n"
            try:
                target_session.connection.sendall(self.create_packet('+msg', '', notification))
                print(f"AUXI: Sent challenge notification to {session.selected_target}")
                
                # Set target's challenge state
                target_session.challenge_state = 1  # PENDING
                target_session.challenger = session.current_persona
                target_session.challenge_token = challenge_token
                target_session.challenge_timeout = time.time() + 30
                
            except Exception as e:
                print(f"AUXI: Error sending notification: {e}")
                return self.create_packet('auxi', '', "STATUS=0\nERROR=Could not send challenge\n")
        
        # Send confirmation to challenger
        response = f"TEXT={challenge_token}\nSTATUS=1\n"
        return self.create_packet('auxi', '', response)

    def handle_mesg(self, data, session):
		    """Handle mesg command - challenge responses AND initiations"""
		    data_str = data.decode('latin1') if data else ""
		    
		    print(f"MESG DEBUG from {session.clientNAME}:")
		    print(f"  Raw data: {data_str}")
		    
		    # First, check if this is a challenge RESPONSE (ACPT/DECL/BLOC)
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
		        # Handle challenge response
		        print(f"MESG: Challenge response from {session.clientNAME}: {response_type} to {response_target}")
		        return self.handle_challenge_response(session, response_target, response_type)
		    
		    # If not a response, check if it's a challenge INITIATION
		    is_challenge_initiation = False
		    target_user = ""
		    challenge_token = ""
		    
		    for line in data_str.split('\n'):
		        line = line.strip()
		        if line.startswith('PRIV=') or line.startswith('N='):
		            # Get target user
		            target_user = line.split('=', 1)[1].strip()
		        elif line.startswith('TEXT='):
		            # Get challenge token
		            challenge_token = line.split('=', 1)[1].strip()
		            # Check if this looks like a challenge token (not empty, not a response)
		            if challenge_token and challenge_token not in ['ACPT', 'DECL', 'BLOC']:
		                is_challenge_initiation = True
		        elif line.startswith('ATTR='):
		            # ATTR=3 often indicates a challenge
		            attr_value = line.split('=', 1)[1].strip()
		            if attr_value == '3':
		                is_challenge_initiation = True
		    
		    # If it's a challenge initiation
		    if is_challenge_initiation and target_user and challenge_token:
		        print(f"MESG: Challenge initiation from {session.clientNAME} to {target_user} with token {challenge_token}")
		        
		        # Store challenge state for initiator
		        session.challenge_state = 1  # PENDING
		        session.challenger = session.current_persona
		        session.challenge_target = target_user
		        session.challenge_token = challenge_token
		        session.challenge_timeout = time.time() + 30
		        
		        # Find target session
		        target_session = None
		        for conn_id, other_session in self.client_sessions.items():
		            if (hasattr(other_session, 'current_persona') and 
		                other_session.current_persona == target_user):
		                target_session = other_session
		                break
		        
		        if target_session and hasattr(target_session, 'connection'):
		            # Send challenge notification to target
		            notification = f"N={session.current_persona}\nT={challenge_token}\nATTR=3\n"
		            try:
		                target_session.connection.sendall(self.create_packet('+msg', '', notification))
		                print(f"MESG: Sent challenge notification to {target_user}")
		                
		                # Set target's challenge state
		                target_session.challenge_state = 1  # PENDING
		                target_session.challenger = session.current_persona
		                target_session.challenge_token = challenge_token
		                target_session.challenge_timeout = time.time() + 30
		                
		            except Exception as e:
		                print(f"MESG: Error sending notification: {e}")
		                return self.create_packet('mesg', '', "STATUS=0\nERROR=Could not send challenge\n")
		        
		        # Send confirmation to challenger
		        response = f"TEXT={challenge_token}\nSTATUS=1\n"
		        return self.create_packet('mesg', '', response)
		    
		    # Not a challenge message - delegate to message system
		    print(f"MESG: Routing to message system (non-challenge message)")
		    
		    if hasattr(self, 'message_handlers'):
		        return self.message_handlers.handle_mesg(data, session)
		    else:
		        print(f"MESG ERROR: No message_handlers available")
		        return self.create_packet('mesg', '', "STATUS=1\n")
		        
		# Add this method to ChallengeSystem class in challenge_system_r11.py
    def handle_user(self, data, session):
		    """Handle user command - target selection for challenges"""
		    data_str = data.decode('latin1') if data else ""
		    print(f"USER: Target selection: {data_str}")
		    
		    # Parse the target user/persona
		    target_persona = ""
		    for line in data_str.split('\n'):
		        if line.startswith('PERS='):
		            target_persona = line[5:].strip()
		            break
		    
		    if not target_persona:
		        # No target specified
		        return self.create_packet('user', '', "STATUS=0\nERROR=No target specified\n")
		    
		    print(f"USER: {session.clientNAME} selected target: {target_persona}")
		    
		    # Store the selected target for challenge initiation
		    session.selected_target = target_persona
		    
		    # Find the target user in active users
		    target_found = False
		    target_conn_id = None
		    
		    # Try to find by persona first
		    for conn_id, user_data in self.active_users.items():
		        if user_data.get('persona') == target_persona:
		            target_found = True
		            target_conn_id = conn_id
		            break
		    
		    # If not found by persona, try by username
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
        """Handle CHAL command - challenge state registration"""
        current_state = getattr(session, 'challenge_state', 0)
        
        if current_state == 0:
            return self.create_packet('chal', '', "STATUS=1\n")
        else:
            # Reset challenge state
            session.challenge_state = 0
            session.challenger = ''
            return self.create_packet('chal', '', "STATUS=0\n")

    def handle_peek(self, data, session):
        """Handle peek command - user selection"""
        data_str = data.decode('latin1') if data else ""
        
        # Parse the NAME field
        target_name = ""
        for line in data_str.split('\n'):
            if line.startswith('NAME='):
                target_name = line[5:].strip()
                break
        
        print(f"[PEEK] from {session.clientNAME}: NAME='{target_name}'")
        
        if not target_name:
            # No target specified - return empty response
            return self.create_packet('peek', '', "STATUS=1\n")
        
        # Find the target user in active_users
        target_session = None
        for conn_id, user_data in self.active_users.items():
            if user_data.get('persona') == target_name or user_data.get('username') == target_name:
                # Try to get the actual session
                if conn_id in self.client_sessions:
                    target_session = self.client_sessions[conn_id]
                    break
        
        if target_session:
            response = f"NAME={target_name}\nROOM={target_session.current_room}\nSTATUS=1\n"
            print(f"[PEEK] Found {target_name} in room {target_session.current_room}")
        else:
            response = f"NAME={target_name}\nSTATUS=0\nERROR=User not found\n"
            print(f"[PEEK] User {target_name} not found")
        
        return self.create_packet('peek', '', response)
    
    # ===== NOTIFICATION METHODS =====
    def send_challenge_notification(self, challenger_name, token, target_session):
        """Send challenge notification to target using optimal method"""
        
        print(f"[CHALLENGE] Sending notification to {target_session.clientNAME}")
        
        # METHOD 1: Trying test tokens
        if self.test_mesg_formats(challenger_name, token, target_session):
            print("  Using +msg notification path")
    def test_mesg_formats(self, challenger_name, token, target_session):
        """Test different MESG formats to find what triggers notification"""
        
        test_formats = [
            # Format 1: What we've been using
            (f"N={challenger_name}\nT={token}\n", "Original N=, T="),
            
            # Format 2: Using N instead of N
            (f"N={challenger_name}\nTEXT={token}\nATTR=1\n", "N, TEXT, ATTR=1"),
            
            # Format 3: Just TEXT field (no recipient)
            (f"N={challenger_name}\nTEXT={token}\nATTR=2\n", "N, TEXT, ATTR=2"),
            
            # Format 4: Different field order
            (f"N={challenger_name}\nTEXT={token}\nATTR=3\n", "N, TEXT, ATTR=3"),
            
            # Format 5: With F flag
            (f"N={challenger_name}\nTEXT={token}\nATTR=4\n", "N, TEXT, ATTR=4"),
            
            # Format 6: Simple challenge message
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x01\n", "N, TEXT, ATTR=0x01"),
            
            # Format 7: With TYPE field
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x02\n", "N, TEXT, ATTR=0x02"),

            # Format 6: Simple challenge message
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x03\n", "N, TEXT, ATTR=0x03"),
            
            # Format 7: With TYPE field
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x04\n", "N, TEXT, ATTR=0x04"),
            
            # Format 6: Simple challenge message
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x10000\n", "N, TEXT, ATTR=0x10000"),
            
            # Format 7: With TYPE field
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x20000\n", "N, TEXT, ATTR=0x20000"),

            # Format 6: Simple challenge message
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x30000\n", "N, TEXT, ATTR=0x30000"),
            
            # Format 7: With TYPE field
            (f"N={challenger_name}\nTEXT={token}\nATTR=0x40000\n", "N, TEXT, ATTR=0x40000"),
        ]
        
        for payload, description in test_formats:
            print(f"\n  Testing: {description}")
            print(f"    Payload: {payload[:50]}...")
            
            try:
                packet = self.create_packet('+msg', '', payload)
                target_session.connection.sendall(packet)
                print(f"    ✓ Sent")
                time.sleep(1)  # Wait for response
            except Exception as e:
                print(f"    ✗ Failed: {e}")    

    # ===== RESPONSE HANDLING =====
    
    def handle_challenge_response(self, session, target_user, response):
		    """Handle challenge response (ACPT/DECL/BLOC)"""
		    print(f"[CHALLENGE] {session.clientNAME} responded: {response} to {target_user}")
		    
		    # Find challenger session
		    challenger_session = None
		    if target_user:
		        challenger_session = self.find_user_session(target_user)
		    elif hasattr(session, 'challenger'):
		        challenger_session = self.find_user_session(session.challenger)
		    
		    # Update states based on response
		    state_map = {
		        'ACPT': 4,  # ACCEPTED
		        'DECL': 2,  # DECLINED
		        'BLOC': 3   # BLOCKED
		    }
		    
		    new_state = state_map.get(response, 0)
		    session.challenge_state = new_state
		    
		    if challenger_session:
		        challenger_session.challenge_state = new_state
		        
		        if response == 'ACPT':
		            # FIX: Pass both sessions to start_race_between_players
		            self.start_race_between_players(challenger_session, session)
		    
		    return self.create_packet('mesg', '', "STATUS=1\n")

    # ===== HELPER FUNCTIONS =====
    
    def find_challenge_target(self, session):
        """Find valid challenge target for session"""
        # Check if user has explicitly selected a target
        if hasattr(session, 'challenge_target') and session.challenge_target:
            target = session.challenge_target
            target_session = self.find_user_session(target)
            if target_session and self.verify_challenge_conditions(session, target_session):
                return target
        
        # Find any user in same room
        current_room = getattr(session, 'current_room_id', 0)
        for user_session in self.client_sessions.values():
            if (user_session != session and 
                self.verify_challenge_conditions(session, user_session) and
                getattr(user_session, 'current_room_id', 0) == current_room):
                return user_session.clientNAME
        
        return None

    def find_user_session(self, username):
        """Find session by username"""
        for session in self.client_sessions.values():
            if session.clientNAME == username:
                return session
        return None

    def verify_challenge_conditions(self, challenger_session, target_session):
        """Verify challenge can be initiated between sessions"""
        return (challenger_session and target_session and
                challenger_session.clientNAME != target_session.clientNAME and
                getattr(challenger_session, 'current_room_id', 0) == 
                getattr(target_session, 'current_room_id', 0))

    def start_race_between_players(self, challenger_session, target_session):
		    """Start race between two players when challenge is accepted"""
		    print(f"STARTING RACE: {challenger_session.current_persona} vs {target_session.current_persona}")
		    
		    # Set both players to READY state
		    challenger_session.challenge_state = 6  # READY
		    target_session.challenge_state = 6      # READY
		    
		    # Create session data for both players
		    session_data = self.create_272_byte_session_data(challenger_session, target_session)
		    
		    # Send play command to both players
		    play_response = f"SELF=1\nHOST=1\nOPPO=0\nP1=1\nP2=0\nP3=0\nP4=0\nAUTH=1\nFROM={challenger_session.current_persona}\nSEED={int(time.time())}\nWHEN={int(time.time())}\nSTATUS=1\n"
		    
		    # Send to challenger
		    try:
		        challenger_session.connection.sendall(self.create_packet('play', '', play_response))
		        time.sleep(0.5)
		        challenger_session.connection.sendall(self.create_packet('+ses', '', session_data))
		        print(f"RACE: Sent play command to challenger {challenger_session.current_persona}")
		    except Exception as e:
		        print(f"RACE: Error sending to challenger: {e}")
		    
		    # Send to target
		    try:
		        target_session.connection.sendall(self.create_packet('play', '', play_response))
		        time.sleep(0.5)
		        target_session.connection.sendall(self.create_packet('+ses', '', session_data))
		        print(f"RACE: Sent play command to target {target_session.current_persona}")
		    except Exception as e:
		        print(f"RACE: Error sending to target: {e}")

    def create_272_byte_session_data(self, session1, session2=None):
		    """Create 272-byte race session data - handles both single and dual sessions"""
		    import random  # Make sure random is imported
		    
		    session_data = bytearray(272)
		    
		    # Header (4 bytes)
		    session_data[0:4] = struct.pack(">I", 1)  # Version/magic
		    
		    # Player 1 data (always session1)
		    player1_name = session1.current_persona if hasattr(session1, 'current_persona') else 'Player1'
		    session_data[4:20] = player1_name.ljust(16, '\0').encode('ascii')
		    session_data[20:24] = struct.pack(">I", 1)  # Player 1 ID
		    
		    # Player 2 data (session2 if provided, otherwise empty)
		    if session2 and hasattr(session2, 'current_persona'):
		        player2_name = session2.current_persona
		        session_data[24:40] = player2_name.ljust(16, '\0').encode('ascii')
		        session_data[40:44] = struct.pack(">I", 2)  # Player 2 ID
		    else:
		        # Single player mode or waiting for opponent
		        session_data[24:40] = 'Waiting...'.ljust(16, '\0').encode('ascii')
		        session_data[40:44] = struct.pack(">I", 0)  # Player 2 not present
		    
		    # Race configuration defaults
		    session_data[44:48] = struct.pack(">I", 10)  # Laps (default 10)
		    session_data[48:52] = struct.pack(">I", 2)   # Difficulty (medium)
		    session_data[52:56] = struct.pack(">I", 1)   # Damage enabled (1)
		    
		    # Track selection (default: Daytona)
		    track_id = 1  # Daytona
		    session_data[56:60] = struct.pack(">I", track_id)
		    
		    # Random seed
		    seed = random.randint(1, 0xFFFFFFFF)
		    session_data[60:64] = struct.pack(">I", seed)
		    
		    # Timestamp
		    timestamp = int(time.time())
		    session_data[64:68] = struct.pack(">I", timestamp)
		    
		    # Host flag (first player is host)
		    session_data[68:72] = struct.pack(">I", 1)  # session1 is host
		    
		    # Game mode flags
		    session_data[72:76] = struct.pack(">I", 1)  # Multiplayer enabled
		    session_data[76:80] = struct.pack(">I", 0)  # AI players count
		    
		    # AI difficulty if applicable
		    session_data[80:84] = struct.pack(">I", 2)  # AI difficulty
		    
		    # Remaining bytes (game-specific settings)
		    for i in range(84, 272, 4):
		        session_data[i:i+4] = struct.pack(">I", 0)
		    
		    return bytes(session_data)
    
    # ===== STATE MANAGEMENT =====
    def ChallengeCallback_Cleanup(self, session):
        """Cleanup challenge state on disconnect (called by session manager)"""
        if hasattr(session, 'challenge_state') and session.challenge_state != 0:
            print(f"[CHALLENGE] Cleaning up {session.connection_id}")
            session.challenge_state = 0
            session.challenger = ''
            session.challenge_target = None

    def update_challenge_state(self, session):
      """Update challenge state and handle timeouts"""
      current_time = time.time()
      
      if hasattr(session, 'challenge_state') and session.challenge_state == 1:  # PENDING
          if hasattr(session, 'challenge_timeout') and current_time > session.challenge_timeout:
              print(f"CHALLENGE: Timeout for {session.current_persona}")
              session.challenge_state = 9  # EXPIRED
              
              # Notify challenger if this is the target
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
        """Get current challenge state"""
        return getattr(session, 'challenge_state', 0)