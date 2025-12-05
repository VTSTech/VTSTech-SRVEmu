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
		    """Handle MESG command - challenge messages only"""
		    if not data:
		        return self.create_packet('mesg', '', "STATUS=1\n")
		    
		    # Handle both bytes and string input
		    if isinstance(data, bytes):
		        data_str = data.decode('latin1')
		    else:
		        data_str = str(data)
		    
		    print(f"[CHALLENGE MESG] from {session.clientNAME}: {data_str}")
		    
		    target_user = None
		    message_text = ""
		    attr_value = 0
		    
		    # Parse MESG fields
		    for line in data_str.split('\n'):
		        if line.startswith('PRIV=') or line.startswith('N='):
		            target_user = line.split('=', 1)[1]
		        elif line.startswith('TEXT=') or line.startswith('T='):
		            message_text = line.split('=', 1)[1]
		        elif line.startswith('ATTR=') or line.startswith('F='):
		            try:
		                attr_value = int(line.split('=', 1)[1])
		            except:
		                pass
		    
		    # Check if this is a challenge message
		    # Challenge messages have ATTR=3 and token-like TEXT
		    is_challenge = (attr_value == 3 and message_text and 
		                   '_' in message_text)  # Token usually has underscores
		    
		    # Also check for challenge responses
		    is_response = (message_text in ['BLOC', 'DECL', 'ACPT'])
		    
		    if not (is_challenge or is_response):
		        print(f"[CHALLENGE MESG] Not a challenge message, forwarding to message system")
		        return None  # Return None to indicate this should go to message system
		    
		    # Handle challenge responses
		    if is_response:
		        print(f"[CHALLENGE] {session.clientNAME} responded: {message_text} to {target_user}")
		        return self.handle_challenge_response(session, target_user, message_text)
		    
		    # Handle challenge initiation
		    if is_challenge and target_user:
		        print(f"[CHALLENGE] Challenge from {session.clientNAME} to {target_user}: {message_text}")
		        
		        # Find target session
		        target_session = self.find_user_session(target_user)
		        if target_session:
		            # Update challenge states
		            session.challenge_state = 1
		            session.challenger = session.clientNAME  # Challenger is self
		            target_session.challenge_state = 1
		            target_session.challenger = session.clientNAME
		            
		            # Send challenge notification to target
		            self.send_challenge_notification(session.clientNAME, message_text, target_session)
		        else:
		            print(f"[CHALLENGE] Target {target_user} not found")
		    
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