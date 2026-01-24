# message_system_r11.py - COMPLETE MESSAGE SYSTEM
import time

class MessageHandlers:
    def __init__(self, create_packet_func, active_users_dict, room_manager_ref=None, challenge_system_ref=None):
        self.create_packet = create_packet_func
        self.active_users = active_users_dict
        self.room_manager = room_manager_ref
        self.challenge_system = challenge_system_ref
        print(f"MESSAGE: Handler initialized")

    def handle_mesg(self, data, session):
        """Handle regular (non-challenge) MESG commands"""
        if isinstance(data, bytes):
            data_str = data.decode('latin1')
        else:
            data_str = str(data)
        
        target_user = None
        message_text = ""
        message_flags = 0
        is_private = False

        for line in data_str.split('\n'):
            if line.startswith('PRIV='):
                target_user = line.split('=', 1)[1]
                is_private = True
            elif line.startswith('N='): # Some games use N for room chat target
                target_user = line.split('=', 1)[1]
            elif line.startswith('TEXT=') or line.startswith('T='):
                message_text = line.split('=', 1)[1]
            elif line.startswith('ATTR=') or line.startswith('F='):
                try:
                    message_flags = int(line.split('=', 1)[1])
                except:
                    pass

        if is_private and target_user:
            return self.send_private_message(session, target_user, message_text, message_flags)
        else:
            # If no PRIV flag, it's a Room Chat broadcast
            return self.broadcast_room_chat(session, message_text, message_flags)
            
    def broadcast_room_chat(self, session, message_text, flags):
		        # 1. Define variables at the start (avoid UnboundLocalError)
		        sender_room_id = getattr(session, 'room_id', 0)
		        sender_name = getattr(session, 'persona', 
                      getattr(session, 'current_persona', 
                      getattr(session, 'authenticated_username', 
                      getattr(session, 'clientNAME', "Unknown"))))
		        count = 0

		        print(f"CHAT: {sender_name} in Room {sender_room_id}: {message_text}")

		        # 2. Prepare the packet once
		        chat_packet = self.create_packet('+msg', '', 
		            f"FROM={sender_name}\nTEXT={message_text}\nF={flags}\nRI={sender_room_id}\n")

		        # 3. Use one consistent session list
		        # Using session_manager reference (passed as room_manager_ref in init)
		        if self.room_manager and hasattr(self.room_manager, 'client_sessions'):
		            target_sessions = self.room_manager.client_sessions.values()
		            
		            for user_session in target_sessions:
		                # Check room match and ensure we don't send the broadcast to the sender
		                if getattr(user_session, 'room_id', None) == sender_room_id and user_session != session:
		                    try:
		                        if user_session.connection:
		                            user_session.connection.sendall(chat_packet)
		                            count += 1
		                    except Exception as e:
		                        print(f"CHAT: Failed to send to {getattr(user_session, 'persona', 'Unknown')}: {e}")

		        # 4. Return response (sender_name is now guaranteed to exist)
		        response = f"FROM={sender_name}\nTEXT={message_text}\nS=0\nSTATUS=0\nTYPE=CHAT\n"
		        return self.create_packet('mesg', '', response)
            
    def handle_challenge_response(self, session, target_user, message_text):
        """Handle challenge responses - update both clients"""
        print(f"CHALLENGE RESPONSE: {session.clientNAME} responded '{message_text}' to {target_user}")
        
        if not self.challenge_system:
            return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")
        
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
        
        return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")
        
    def handle_simple_challenge_command(self, session, target_user, command, message_type):
        print(f"SIMPLE CHALLENGE: {session.clientNAME} sent {command} to {target_user}")
        
        if not self.challenge_system:
            print("CHALLENGE WARNING: No challenge system available")
            return self.create_packet('mesg', '', "S=0\nSTATUS=0\n")
        
        response = f"S=0\nSTATUS=0\nTYPE={command}\n"
        return self.create_packet('mesg', '', response)
    
    def send_private_message(self, session, target_username, message_text, flags):
            """Send a PM to a specific user by name"""
            target_session = None
            
            # Look up the target session
            if self.room_manager and hasattr(self.room_manager, 'sessions'):
                for s in self.room_manager.sessions.values():
                    if s.persona == target_username or s.clientNAME == target_username:
                        target_session = s
                        break

            if target_session and target_session.connection:
                try:
                    private_packet = self.create_packet('+msg', '', 
                        f"FROM={session.persona}\nTEXT={message_text}\nF={flags}\nPRIV=1\n")
                    target_session.connection.sendall(private_packet)
                    
                    print(f"MESG: Private message {session.persona} -> {target_username}")
                    response = f"FROM={session.persona}\nTEXT={message_text}\nS=0\nSTATUS=0\nTYPE=PRIVATE\n"
                except Exception as e:
                    response = "S=0\nSTATUS=0\nERROR=Delivery failed\n"
            else:
                response = "S=0\nSTATUS=0\nERROR=User not found\n"
                print(f"MESG: Target {target_username} not found for PM")

            return self.create_packet('mesg', '', response)
    
    def send_chat_message(self, session, target_user, message_text, flags):
        response = f"FROM={session.clientNAME}\nTEXT={message_text}\nS=0\nSTATUS=0\nTYPE=CHAT\n"
        print(f"MESG: Chat message from {session.clientNAME}")
        return self.create_packet('mesg', '', response)
    
    def send_system_message(self, session, message_text, flags):
        response = f"FROM={session.clientNAME}\nTEXT={message_text}\nS=0\nSTATUS=0\nTYPE=SYSTEM\n"
        print(f"MESG: System message from {session.clientNAME}")
        return self.create_packet('mesg', '', response)
    
    def find_user_session(self, username):
        print(f"MESSAGE: Session lookup for {username} - handled by main server")
        return None