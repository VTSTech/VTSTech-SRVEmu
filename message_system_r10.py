# message_system_r08.py - COMPLETE MESSAGE SYSTEM
import time

class MessageHandlers:
    def __init__(self, create_packet_func, active_users_dict, challenge_system_ref=None):
        self.create_packet = create_packet_func
        self.active_users = active_users_dict
        self.challenge_system = challenge_system_ref
        print(f"MESSAGE: Handler initialized with challenge system: {challenge_system_ref is not None}")
    
    def handle_mesg(self, data, session):
		    data_str = data.decode('latin1') if data else ""
		    print(f"MESG: Message data: {data_str}")
		    
		    target_user = None
		    message_text = ""
		    message_flags = 0
		    
		    for line in data_str.split('\n'):
		        if line.startswith('N='):
		            target_user = line[2:]
		        elif line.startswith('T='):
		            message_text = line[2:]
		        elif line.startswith('F='):
		            try:
		                message_flags = int(line[2:])
		            except:
		                pass
		    
		    # SPECIAL CASE: If this is a challenge response (ACPT/DECL/BLOC) without target,
		    # assume it's for the current challenger
		    if message_text in ['BLOC', 'DECL', 'ACPT'] and not target_user:
		        if hasattr(session, 'challenger') and session.challenger:
		            target_user = session.challenger
		            print(f"CHALLENGE MESG: Auto-targeting challenger {target_user} for response '{message_text}'")
		    
		    # Check for challenge responses
		    if message_text in ['BLOC', 'DECL', 'ACPT'] and target_user:
		        print(f"CHALLENGE MESG: Challenge response '{message_text}' from {session.clientNAME} to {target_user}")
		        return self.handle_challenge_response(session, target_user, message_text)
		    
		    # Handle regular messages
		    if target_user and message_text:
		        print(f"MESG: {session.clientNAME} -> {target_user}: '{message_text}'")
		        return self.send_private_message(session, target_user, message_text, message_flags)
		    else:
		        print(f"MESG: Invalid message format - target: {target_user}, text: {message_text}")
		        response = "STATUS=0\nERROR=Invalid message format\n"
		    
		    return self.create_packet('mesg', '', response)

    def handle_challenge_response(self, session, target_user, message_text):
		    """Handle challenge responses - update both clients"""
		    print(f"CHALLENGE RESPONSE: {session.clientNAME} responded '{message_text}' to {target_user}")
		    
		    if not self.challenge_system:
		        return self.create_packet('mesg', '', "STATUS=1\n")
		    
		    # Find the challenger session
		    challenger_session = self.challenge_system.find_user_session(target_user)
		    
		    if message_text == 'ACPT':
		        session.challenge_state = 4  # ACCEPTED
		        if challenger_session:
		            challenger_session.challenge_state = 4  # Also set challenger to ACCEPTED
		            # Notify challenger that challenge was accepted
		            notify_packet = self.create_packet('+msg', '', 
		                                              f"FROM=System\nTEXT=Challenge accepted by {session.clientNAME}\n")
		            challenger_session.connection.sendall(notify_packet)
		            print(f"CHALLENGE: {session.clientNAME} accepted challenge from {target_user}")
		            
		            # IMMEDIATELY progress both to READY and start race
		            session.challenge_state = 6  # READY
		            challenger_session.challenge_state = 6  # READY
		            print(f"CHALLENGE: Both clients ready, starting race immediately")
		            self.challenge_system.start_race_with_opponents(challenger_session)
		        
		    elif message_text == 'DECL':
		        session.challenge_state = 2  # DECLINED
		        if challenger_session:
		            challenger_session.challenge_state = 2  # Also decline challenger
		            notify_packet = self.create_packet('+msg', '', 
		                                              f"FROM=System\nTEXT=Challenge declined by {session.clientNAME}\n")
		            challenger_session.connection.sendall(notify_packet)
		        print(f"CHALLENGE: {session.clientNAME} declined challenge from {target_user}")
		        
		    elif message_text == 'BLOC':
		        session.challenge_state = 3  # BLOCKED
		        if challenger_session:
		            challenger_session.challenge_state = 3  # Also block challenger
		        print(f"CHALLENGE: {session.clientNAME} blocked {target_user}")
		    
		    return self.create_packet('mesg', '', "STATUS=1\n")
    def handle_simple_challenge_command(self, session, target_user, command, message_type):
        print(f"SIMPLE CHALLENGE: {session.clientNAME} sent {command} to {target_user}")
        
        if not self.challenge_system:
            print("CHALLENGE WARNING: No challenge system available")
            return self.create_packet('mesg', '', "STATUS=1\n")
        
        response = f"STATUS=1\nTYPE={command}\n"
        return self.create_packet('mesg', '', response)
    
    def send_private_message(self, session, target_user, message_text, flags):
        target_session = self.find_user_session(target_user)
        
        if target_session and target_session.connection:
            try:
                private_packet = self.create_packet('+msg', '', 
                    f"FROM={session.clientNAME}\nTEXT={message_text}\nF={flags}\n")
                target_session.connection.sendall(private_packet)
                
                response = f"FROM={session.clientNAME}\nTEXT={message_text}\nSTATUS=1\nTYPE=PRIVATE\n"
                print(f"MESG: Private message delivered to {target_user}")
            except Exception as e:
                response = "STATUS=0\nERROR=Delivery failed\n"
                print(f"MESG: Private message delivery failed: {e}")
        else:
            response = "STATUS=0\nERROR=User not found or offline\n"
        
        return self.create_packet('mesg', '', response)
    
    def send_chat_message(self, session, target_user, message_text, flags):
        response = f"FROM={session.clientNAME}\nTEXT={message_text}\nSTATUS=1\nTYPE=CHAT\n"
        print(f"MESG: Chat message from {session.clientNAME}")
        return self.create_packet('mesg', '', response)
    
    def send_system_message(self, session, message_text, flags):
        response = f"FROM={session.clientNAME}\nTEXT={message_text}\nSTATUS=1\nTYPE=SYSTEM\n"
        print(f"MESG: System message from {session.clientNAME}")
        return self.create_packet('mesg', '', response)
    
    def find_user_session(self, username):
        print(f"MESSAGE: Session lookup for {username} - handled by main server")
        return None