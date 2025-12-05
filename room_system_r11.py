# room_system_r07.py
import time
import threading

class RoomManager:
    """Manages rooms and user presence"""
    
    def __init__(self, create_packet_func, server_ip):
        self.create_packet = create_packet_func
        self.server_ip = server_ip
        
        # Enhanced room storage mimicking binary hash tables
        self.room_hash_table = {}  # piVar24[0xc4] equivalent
        self.user_hash_table = {}  # piVar24[0xc9] equivalent
        self.rank_hash_table = {}  # piVar24[0xce] equivalent
        self.active_rooms = {
				    0: {'name': 'Lobby', 'desc': 'Main Lobby Hub', 'usercount': 0, 'maxusers': 100, 'room_id': 0, 'flags': '0', 'type': 0},  # Add this
				    1: {'name': 'East', 'desc': 'East Coast Racers', 'usercount': 0, 'maxusers': 50, 'room_id': 1, 'flags': '0', 'type': 1},
				    2: {'name': 'West', 'desc': 'West Coast Racers', 'usercount': 0, 'maxusers': 50, 'room_id': 2, 'flags': '0', 'type': 1},
				    3: {'name': 'Beginner', 'desc': 'New Drivers Welcome', 'usercount': 0, 'maxusers': 50, 'room_id': 3, 'flags': '0', 'type': 1}
				}
        self.active_users = {}
        self.user_presence_lock = threading.Lock()
    
    def update_user_presence(self, connection_id, username, persona, room, room_id, connected=True, is_self=False):
		    """Enhanced user presence tracking based on real traffic"""
		    if not username or username == 'Lobby':
		        username = 'Unknown'
		    if not persona or persona == 'Lobby':
		        persona = username
		    
		    # Ensure room_id is integer and Lobby is 0
		    try:
		        room_id = int(room_id)
		    except:
		        room_id = 0
		    
		    # If room name is Lobby, ensure room_id is 0
		    if room == 'Lobby' or room == 'Main Lobby':
		        room_id = 0
		    
		    print(f"PRESENCE: conn={connection_id}, user='{username}', persona='{persona}', room='{room}', room_id={room_id}, is_self={is_self}")
		    
		    with self.user_presence_lock:
		        # If user already exists, update their data
		        if connection_id in self.active_users:
		            old_data = self.active_users[connection_id]
		            old_room_id = old_data['room_id']
		            
		            # Update room counts if room changed
		            if old_room_id != room_id:
		                if old_room_id >= 0 and old_room_id in self.active_rooms:
		                    self.active_rooms[old_room_id]['usercount'] = max(0, self.active_rooms[old_room_id]['usercount'] - 1)
		                    print(f"ROOM POP: {username} left room {old_room_id}, now {self.active_rooms[old_room_id]['usercount']} users")
		                
		                if room_id >= 0 and room_id in self.active_rooms:
		                    self.active_rooms[room_id]['usercount'] += 1
		                    print(f"ROOM POP: {username} joined room {room_id}, now {self.active_rooms[room_id]['usercount']} users")
		            
		            # Update user data
		            self.active_users[connection_id].update({
		                'username': username,
		                'persona': persona,
		                'room': room,
		                'room_id': room_id,
		                'flags': '1' if is_self else '0',
		                'is_self': is_self
		            })
		            
		        elif connected:
		            # Add new user
		            self.active_users[connection_id] = {
		                'username': username,
		                'persona': persona,
		                'room': room,
		                'room_id': room_id,
		                'login_time': time.time(),
		                'flags': '1' if is_self else '0',
		                'conn_id': connection_id,
		                'is_self': is_self
		            }
		            
		            # Update room count
		            if room_id >= 0 and room_id in self.active_rooms:
		                self.active_rooms[room_id]['usercount'] += 1
		                print(f"ROOM POP: {username} joined room {room_id}, now {self.active_rooms[room_id]['usercount']} users")
		                
		        elif connection_id in self.active_users:
		            # User disconnected
		            user_data = self.active_users[connection_id]
		            room_id = user_data['room_id']
		            if room_id >= 0 and room_id in self.active_rooms:
		                self.active_rooms[room_id]['usercount'] = max(0, self.active_rooms[room_id]['usercount'] - 1)
		                print(f"ROOM POP: {username} disconnected from room {room_id}, now {self.active_rooms[room_id]['usercount']} users")
		            del self.active_users[connection_id]
		        
		        # Debug: Show current active users
		        print(f"ACTIVE USERS COUNT: {len(self.active_users)}")
		        for conn_id, user_data in self.active_users.items():
		            print(f"  - {user_data['persona']} in room {user_data['room_id']}")
                
    def create_room_update_packet(self, room_data):
        """Create room update packet"""
        fields = [
            f"I={room_data['room_id']}", 
            f"N={room_data['name']}", 
            f"H={room_data['desc']}",
            f"A={self.server_ip}", 
            f"T={room_data['type']}", 
            f"L={room_data['maxusers']}", 
            f"F=0"  # FIXED: Always send F=0
        ]
        return self.create_packet('+rom', '', '\n'.join(fields) + '\n')    
        
    def create_user_update_packet(self, user_data):
		    """Create user update packet"""
		    if not user_data.get('username') or user_data.get('username') == 'Lobby':
		        return self.create_packet('+usr', '', "I=0\nN=Invalid\nF=0\n")
		        
		    display_name = user_data.get('persona', user_data.get('username', 'Unknown'))
		    room_id = user_data.get('room_id', 0)
		    
		    # Ensure room_id is properly set (allow 0 for Lobby)
		    if room_id is None or room_id == '':
		        room_id = 0
		    
		    if 'unique_id' in user_data:
		        user_id = user_data['unique_id']
		    else:
		        if user_data.get('is_dummy', False):
		            user_id = -abs(hash(user_data['username'])) % 1000000
		        else:
		            user_id = abs(hash(user_data.get('conn_id', display_name))) % 1000000    
		            
		    # Allow room_id 0 (Lobby)
		    if room_id < 0:
		        return self.create_packet('+usr', '', "I=0\nN=Invalid\nF=0\n")
		        
		    # Determine correct flag value
		    # Self user should be F=1, others F=0
		    user_flags = user_data.get('flags', '0')
		    
		    # Check if this is a self-referencing packet
		    is_self = user_data.get('is_self', False)
		    if is_self:
		        user_flags = '1'
		    
		    fields = [
		        f"I={user_id}", 
		        f"N={display_name}", 
		        f"F={user_flags}",  # Use dynamic flag value
		        f"A={self.server_ip}"  # Add IP address
		    ]
		    return self.create_packet('+usr', '', '\n'.join(fields) + '\n')
        
    def hash_table_insert(self, hash_table, key, user_data):
        """Mimic binary hash table insertion"""
        hash_table[key] = {
            'data': user_data,
            'timestamp': time.time(),
            'flags': 0
        }
        
    def hash_table_lookup(self, hash_table, key):
        """Mimic binary hash table lookup"""
        return hash_table.get(key)
        
    def create_population_packet(self):
        """Create population packet"""
        pop_data = [f"{room_id}:{room_data['usercount']}" for room_id, room_data in self.active_rooms.items()]
        population_data = f"Z={' '.join(pop_data)}\n"
        print(f"POPULATION: Room counts - {population_data.strip()}")
        return self.create_packet('+pop', '', population_data)
    
    def broadcast_room_updates(self, client_sessions):
        """Broadcast room updates to all clients"""
        print(f"BROADCAST: Sending room updates to {len(client_sessions)} clients")
        
        valid_count = 0
        for connection_id, session in list(client_sessions.items()):
            if hasattr(session, 'connection') and session.connection:
                try:
                    session.connection.getpeername()
                    
                    pop_packet = self.create_population_packet()
                    if pop_packet:
                        session.connection.sendall(pop_packet)
                    
                    users_sent = 0
                    for user_data in self.active_users.values():
                        if user_data['room_id'] > 0:
                            user_packet = self.create_user_update_packet(user_data)
                            if user_packet:
                                session.connection.sendall(user_packet)
                                users_sent += 1
                                time.sleep(0.05)
                    
                    valid_count += 1
                    print(f"BROADCAST: Sent {users_sent} user updates to {connection_id}")
                    
                except Exception as e: 
                    print(f"BROADCAST: Error sending to {connection_id}: {e}")
        
        print(f"BROADCAST: Sent updates to {valid_count} valid clients")

class RoomHandlers:
    """Handles room-related commands"""
    
    def __init__(self, create_packet_func, room_manager, update_user_presence_func, get_client_sessions_func):
        self.create_packet = create_packet_func
        self.room_manager = room_manager
        self.update_user_presence = update_user_presence_func
        self.get_client_sessions = get_client_sessions_func  # Function to get client sessions
    
    def handle_sele(self, data, session):
        """Handle sele command - lobby data request"""
        data_str = data.decode('latin1') if data else ""
        print(f"SELE: Client requesting: {data_str.strip()}")
        
        response_lines = []
        
        def send_lobby_updates():
            time.sleep(0.5)
            if session.connection:
                try:
                    session.connection.getpeername()
                    print("SELE: Sending real-time room/user updates")
                    
                    # Send room updates for ALL rooms including Lobby (room_id: 0)
                    for room_data in self.room_manager.active_rooms.values():
                        room_packet = self.room_manager.create_room_update_packet(room_data)
                        session.connection.sendall(room_packet)
                        time.sleep(0.05)
                    
                    # Send user updates for ALL users including those in Lobby
                    users_sent = 0
                    for conn_id, user_data in self.room_manager.active_users.items():
                        # Allow all users regardless of room
                        user_packet = self.room_manager.create_user_update_packet(user_data)
                        if user_packet:
                            session.connection.sendall(user_packet)
                            users_sent += 1
                            time.sleep(0.02)
                    
                    # Send population update
                    pop_packet = self.room_manager.create_population_packet()
                    session.connection.sendall(pop_packet)
                    
                    print(f"SELE: Sent {len(self.room_manager.active_rooms)} rooms, {users_sent} users")
                    
                except Exception as e:
                    print(f"SELE: Error sending updates: {e}")
        
        threading.Timer(0.1, send_lobby_updates).start()
        
        if "ROOMS=1" in data_str:
            response_lines.extend(["ROOMS=1", f"COUNT={len(self.room_manager.active_rooms)}"])
            for i, room_data in enumerate(self.room_manager.active_rooms.values()):
                response_lines.extend([
                    f"ROOM{i}={room_data['name']}", 
                    f"ROOM{i}_DESC={room_data['desc']}",
                    f"ROOM{i}_COUNT={room_data['usercount']}", 
                    f"ROOM{i}_MAX={room_data['maxusers']}"
                ])
            print(f"SELE: Including {len(self.room_manager.active_rooms)} rooms")
        
        if "USERS=1" in data_str:
            # Include ALL active users
            all_active_users = list(self.room_manager.active_users.values())
            
            response_lines.extend(["USERS=1", f"COUNT={len(all_active_users)}"])
            for i, user_data in enumerate(all_active_users):
                response_lines.extend([
                    f"USER{i}={user_data['username']}", 
                    f"USER{i}_PERS={user_data['persona']}", 
                    f"USER{i}_ROOM={user_data['room']}"
                ])
            print(f"SELE: Including {len(all_active_users)} total active users")
        
        # Handle RANKS request
        if "RANKS=" in data_str:
            rank_num = 50
            for line in data_str.split('\n'):
                if line.startswith('RANKS='):
                    try:
                        rank_num = int(line[6:])
                    except:
                        pass
                    break
            
            print(f"SELE: Sending ranking data for rank {rank_num}")
            response_lines = [
                f"RANK={rank_num}",
                f"USER={session.clientNAME}",
                "RATING=1500",
                "WINS=0",
                "LOSS=0",
                "STATUS=1"
            ]
            return self.create_packet('sele', '', '\n'.join(response_lines) + '\n')

        if "MESGS=1" in data_str:
            print(f"SELE: Sending message data")
            response_lines = [
                "MESGS=1",
                "COUNT=0",  # No messages
                "STATUS=1"
            ]
            return self.create_packet('sele', '', '\n'.join(response_lines) + '\n')
        
        if not response_lines: 
            response_lines = ["ROOMS=1", "USERS=1", "RANKS=1", "MESGS=1"]
            
        response_lines.append("STATUS=1")
        
        return self.create_packet('sele', '', '\n'.join(response_lines) + '\n')
    
    def handle_room(self, data, session):
        """Handle room creation"""
        new_room_id = 1001 + len([r for r in self.room_manager.active_rooms.keys() if r >= 1000])
        
        display_name = session.roomNAME
        room_desc = session.roomDESC if session.roomDESC and session.roomDESC != "None" else "Race Room"
        max_users = min(int(session.roomMAX) if session.roomMAX and session.roomMAX.isdigit() else 50, 50)
        
        print(f"ROOM: '{display_name}' created with MAX={max_users}, DESC='{room_desc}'")
        
        self.room_manager.active_rooms[new_room_id] = {
            'name': display_name,
            'desc': room_desc, 
            'usercount': 1,
            'maxusers': max_users,
            'room_id': new_room_id,
            'flags': '0',
            'type': 3 if session.roomPASS else 1
        }
        
        session.current_room_id = new_room_id
        session.current_room = display_name
        
        username = getattr(session, 'authenticated_username', session.clientNAME)
        persona = getattr(session, 'current_persona', username)
        
        print(f"ROOM DEBUG: Using username '{username}' from auth, persona '{persona}'")
        
        self.update_user_presence(session.connection_id, username, persona, display_name, new_room_id, True, is_self=True)
        
        response_lines = [
            f"I={new_room_id}", 
            f"L={max_users}", 
            "T=1", 
            "F=0", 
            f"H={room_desc}", 
            f"A={self.room_manager.server_ip}", 
            "STATUS=1"
        ]
        print(f"ROOM: Created room ID {new_room_id} for {username}")
        return self.create_packet('room', '', '\n'.join(response_lines) + '\n')
    
    def handle_move(self, data, session):
        """Handle room movement"""
        room_name = session.moveNAME if session.moveNAME and session.moveNAME.strip() else 'Lobby'
        print(f"MOVE: Request to room: '{room_name}'")
        
        target_room_id = 0
        room_mapping = {'East': 1, 'West': 2, 'Beginner': 3, 'Lobby': 0}
        
        if room_name in room_mapping:
            target_room_id = room_mapping[room_name]
        elif any(room_data['name'] == room_name for room_data in self.room_manager.active_rooms.values()):
            for room_id, room_data in self.room_manager.active_rooms.items():
                if room_data['name'] == room_name:
                    target_room_id = room_id
                    break
        else:
            print(f"MOVE WARNING: Room '{room_name}' not found, staying in current room")
            target_room_id = getattr(session, 'current_room_id', 0)
        
        old_room_id = getattr(session, 'current_room_id', 0)
        session.current_room_id = target_room_id
        session.current_room = room_name
        
        username = getattr(session, 'authenticated_username', session.clientNAME)
        persona = getattr(session, 'current_persona', username)
        
        print(f"MOVE DEBUG: User '{username}' moving from room {old_room_id} to {target_room_id}")
        
        self.update_user_presence(
            session.connection_id,
            username,  
            persona,
            room_name,
            target_room_id,
            True,
            is_self=True
        )
        
        response_lines = [f"I={target_room_id}", f"N={room_name}", "T=1", "F=0"]
        response = '\n'.join(response_lines) + '\n'
        print(f"MOVE: {username} moved from room {old_room_id} to room {target_room_id} ({room_name})")
        
        move_packet = self.create_packet('move', '', response)
        
        def send_automatic_updates():
            time.sleep(0.3)
            if session.connection and hasattr(session.connection, 'sendall'):
                try:
                    print("SENDING AUTOMATIC UPDATES AFTER MOVE")
                    for packet_func in [self.reply_pop, self.reply_usr, self.reply_who]:
                        packet = packet_func(session)
                        try:
                            session.connection.getpeername()
                            session.connection.sendall(packet)
                            print(f"Sent {packet_func.__name__} update")
                        except:
                            print(f"Connection invalid, skipping {packet_func.__name__}")
                        time.sleep(0.2)
                    print("BROADCASTING updates to all clients")
                    # Use the function to get client sessions
                    client_sessions = self.get_client_sessions()
                    self.room_manager.broadcast_room_updates(client_sessions)
                    print("AUTOMATIC UPDATES COMPLETED")
                except Exception as e: 
                    print(f"MOVE: Error sending automatic updates: {e}")
        
        threading.Timer(0.1, send_automatic_updates).start()
        return move_packet
        
    def reply_who(self, session):
        """+who command handler"""
        username = getattr(session, 'authenticated_username', session.clientNAME)
        persona = getattr(session, 'current_persona', username)
        current_room_id = getattr(session, 'current_room_id', 0)
        fields = ["F=U", f"N={persona}", f"RI={current_room_id}", "RT=1", "R=0", "RF=1"]
        print(f"+WHO: User list includes {persona} (user: {username})")
        return self.create_packet('+who', '', '\n'.join(fields) + '\n')
    
    def reply_pop(self, session):
        """+pop command handler"""
        current_room_id = getattr(session, 'current_room_id', 0)
        room_population = "0/50"
        for room_data in self.room_manager.active_rooms.values():
            if room_data['room_id'] == current_room_id:
                room_population = f"{room_data['usercount']}:{room_data['maxusers']}"
                break
        print(f"+POP: Room {current_room_id} population {room_population}")
        return self.create_packet('+pop', '', f"Z={room_population}\n")
    
    def reply_usr(self, session):
        response_lines = []
        
        # Get active users from room manager
        active_users = self.room_manager.active_users
        
        print(f"+USR: Building user list for {session.clientNAME}")
        
        # Get the current user's connection IP if available
        client_ip = self.room_manager.server_ip
        if hasattr(session, 'connection') and session.connection:
            try:
                client_ip = session.connection.getpeername()[0]
            except:
                pass
        
        # Always include the requesting client in the list
        if hasattr(session, 'clientNAME') and session.clientNAME:
            current_room_id = getattr(session, 'current_room_id', 0)
            persona = getattr(session, 'current_persona', session.clientNAME)
            
            # Self user should use F=1
            user_entry = f"I={current_room_id}\nN={persona}\nF=1\nA={client_ip}"
            response_lines.append(user_entry)
            print(f"+USR Self: {persona} with F=1 (room:{current_room_id})")
        
        # Add other users - use F=0 for others
        for conn_id, user_data in active_users.items():
            # Skip self
            if conn_id == session.connection_id:
                continue
                
            if user_data.get('persona'):
                room_id = user_data.get('room_id', 0)
                
                # Get other user's IP if available
                other_ip = client_ip
                
                # Try to get the actual session for this user
                try:
                    import __main__
                    if conn_id in __main__.session_manager.client_sessions:
                        other_session = __main__.session_manager.client_sessions[conn_id]
                        if hasattr(other_session, 'connection') and other_session.connection:
                            try:
                                other_ip = other_session.connection.getpeername()[0]
                            except:
                                pass
                except:
                    pass
                
                # Other users should use F=0
                user_entry = f"I={room_id}\nN={user_data['persona']}\nF=0\nA={other_ip}"
                response_lines.append(user_entry)
                print(f"+USR Other: {user_data['persona']} with F=0 (room:{room_id})")
        
        if response_lines:
            print(f"+USR: Sending {len(response_lines)} user entries to {session.clientNAME}")
        
        # Create the packet with all user entries
        full_response = '\n'.join(response_lines) + '\n'
        return self.create_packet('+usr', '', full_response)