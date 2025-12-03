# challenge_system_r11.py - OPTIMIZED CHALLENGE SYSTEM
import time
import struct
import threading

class ChallengeSystem:
    def __init__(self, create_packet_func, active_users, client_sessions, session_manager, room_manager):
        self.create_packet = create_packet_func
        self.active_users = active_users
        self.client_sessions = client_sessions
        self.session_manager = session_manager
        self.room_manager = room_manager
        
        # Challenge states mapping
        self.states = {
            0: "INACTIVE", 1: "PENDING", 2: "DECLINED", 3: "BLOCKED",
            4: "ACCEPTED", 6: "READY", 7: "NETWORK_VERIFYING", 9: "EXPIRED"
        }

    # ===== COMMAND HANDLERS =====
    
    def handle_auxi(self, data, session):
        """Handle AUXI command - challenge initiation with processed token"""
        challenger_name = session.clientNAME
        token = data.decode('latin1').strip() if data else ""
        
        print(f"[CHALLENGE] AUXI from {challenger_name}: {token[:20]}...")
        
        # Extract just the token value (remove "TEXT=" prefix if present)
        if token.startswith("TEXT="):
            token = token[5:-2]
        
        # Find target player
        target_user = self.find_challenge_target(session)
        target_session = self.find_user_session(target_user)
        
        if not target_session:
            print(f"[CHALLENGE] No target found for {challenger_name}")
            return self.create_packet('auxi', '', "STATUS=1\n")
        
        print(f"[CHALLENGE] Target found: {target_user}")
        
        # Send challenge notification to target
        self.send_challenge_notification(challenger_name, token, target_session)
        
        # Update challenge states
        session.challenge_state = 1
        target_session.challenge_state = 1
        target_session.challenger = challenger_name
        
        return self.create_packet('auxi', '', "STATUS=1\n")

    def handle_mesg(self, data, session):
        """Handle MESG command - challenge responses and messages"""
        if not data:
            return self.create_packet('mesg', '', "STATUS=1\n")
        
        data_str = data.decode('latin1')
        target_user = None
        message_text = ""
        
        # Parse MESG fields
        for line in data_str.split('\n'):
            if line.startswith('N='):
                target_user = line[2:]
            elif line.startswith('T='):
                message_text = line[2:]
        
        # Handle challenge responses
        if message_text in ['BLOC', 'DECL', 'ACPT']:
            return self.handle_challenge_response(session, target_user, message_text)
        
        return self.create_packet('mesg', '', "STATUS=1\n")

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
		    data_str = data.decode('latin1') if data else ""
		    print(f"[PEEK] from {session.clientNAME}: {data_str}")
		    
		    selected_name = None
		    for line in data_str.split('\n'):
		        if line.startswith('NAME='):
		            selected_name = line[5:]
		            break
		    
		    if selected_name:
		        # Store selection
		        if selected_name in ['East', 'West', 'Beginner', 'Lobby']:
		            session.selected_room = selected_name
		            print(f"[PEEK] Room selection: {selected_name}")
		            
		            # Send user updates for this room
		            def send_room_users():
		                time.sleep(0.1)
		                room_id = {'East': 1, 'West': 2, 'Beginner': 3, 'Lobby': 0}.get(selected_name, 0)
		                
		                # Send +usr updates for users in this room
		                for user_data in self.active_users.values():
		                    if user_data.get('room_id') == room_id:
		                        usr_payload = f"I={room_id}\nN={user_data['persona']}\nF=0\nA=192.168.2.123\n"
		                        usr_packet = self.create_packet('+usr', '', usr_payload)
		                        if session.connection:
		                            session.connection.sendall(usr_packet)
		                            print(f"  Sent +usr for {user_data['persona']} in {selected_name}")
		            
		            threading.Thread(target=send_room_users, daemon=True).start()
		        else:
		            # User selection for challenge
		            session.selected_user = selected_name
		            session.challenge_target = selected_name
		            print(f"[PEEK] User selection for challenge: {selected_name}")
		    
		    # Simple response as binary suggests
		    return self.create_packet('peek', '', "STATUS=1\n")
    # ===== NOTIFICATION METHODS =====
    def send_challenge_notification(self, challenger_name, token, target_session):
        """Send challenge notification to target using optimal method"""
        
        print(f"[CHALLENGE] Sending notification to {target_session.clientNAME}")
        
        # METHOD 1: Trying test tokens
        if self.test_mesg_formats(challenger_name, token, target_session):
            print("  Using MESG notification path")
    def test_mesg_formats(self, challenger_name, token, target_session):
		    """Test different MESG formats to find what triggers notification"""
		    
		    test_formats = [
		        # Format 1: What we've been using
		        (f"N={challenger_name}\nT={token}\n", "Original N=, T="),
		        
		        # Format 2: Using PRIV instead of N
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=1\n", "PRIV, TEXT, ATTR=1"),
		        
		        # Format 3: Just TEXT field (no recipient)
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=2\n", "PRIV, TEXT, ATTR=2"),
		        
		        # Format 4: Different field order
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=3\n", "PRIV, TEXT, ATTR=3"),
		        
		        # Format 5: With F flag
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=4\n", "PRIV, TEXT, ATTR=4"),
		        
		        # Format 6: Simple challenge message
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x01\n", "PRIV, TEXT, ATTR=0x01"),
		        
		        # Format 7: With TYPE field
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x02\n", "PRIV, TEXT, ATTR=0x02"),

		        # Format 6: Simple challenge message
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x03\n", "PRIV, TEXT, ATTR=0x03"),
		        
		        # Format 7: With TYPE field
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x04\n", "PRIV, TEXT, ATTR=0x04"),
		        
		        # Format 6: Simple challenge message
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x10000\n", "PRIV, TEXT, ATTR=0x10000"),
		        
		        # Format 7: With TYPE field
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x20000\n", "PRIV, TEXT, ATTR=0x20000"),

		        # Format 6: Simple challenge message
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x30000\n", "PRIV, TEXT, ATTR=0x30000"),
		        
		        # Format 7: With TYPE field
		        (f"PRIV={challenger_name}\nTEXT={token}\nATTR=0x40000\n", "PRIV, TEXT, ATTR=0x40000"),
		    ]
		    
		    for payload, description in test_formats:
		        print(f"\n  Testing: {description}")
		        print(f"    Payload: {payload[:50]}...")
		        
		        try:
		            packet = self.create_packet('mesg', '', payload)
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
                self.start_race_with_opponents(challenger_session)
        
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

    def start_race_with_opponents(self, session):
        """Start race when challenge is accepted"""
        print(f"[RACE] Starting race for {session.clientNAME}")
        # This would trigger race setup in the race system module

    # ===== STATE MANAGEMENT =====
    
    def ChallengeState_Get(self, session):
        """Get current challenge state (for external modules)"""
        return getattr(session, 'challenge_state', 0)

    def ChallengeCallback_Cleanup(self, session):
        """Cleanup challenge state on disconnect (called by session manager)"""
        if hasattr(session, 'challenge_state') and session.challenge_state != 0:
            print(f"[CHALLENGE] Cleaning up {session.connection_id}")
            session.challenge_state = 0
            session.challenger = ''
            session.challenge_target = None

    def update_challenge_state(self, session):
        """Update challenge state machine (placeholder for future state machine)"""
        # Could be expanded for automatic state transitions
        pass