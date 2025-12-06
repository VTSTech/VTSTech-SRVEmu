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
		    """FIXED population counting"""
		    if not username or username == 'Lobby':
		        username = 'Unknown'
		    if not persona or persona == 'Lobby':
		        persona = username
		    
		    try:
		        room_id = int(room_id)
		    except:
		        room_id = 0
		    
		    print(f"PRESENCE: conn={connection_id}, user='{username}', persona='{persona}', room='{room}', room_id={room_id}, is_self={is_self}")
		    
		    with self.user_presence_lock:
		        # Track old room for cleanup
		        old_room_id = None
		        if connection_id in self.active_users:
		            old_room_id = self.active_users[connection_id]['room_id']
		        
		        if connected:
		            # Update user data
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
		            
		            # Update room counts - ALWAYS recalculate
		            if old_room_id is not None and old_room_id in self.active_rooms:
		                # Recalculate old room count
		                old_count = sum(1 for u in self.active_users.values() 
		                              if u.get('room_id') == old_room_id)
		                self.active_rooms[old_room_id]['usercount'] = old_count
		                print(f"ROOM POP: {persona} left room {old_room_id}, now {old_count} users")
		            
		            if room_id in self.active_rooms:
		                # Recalculate new room count
		                new_count = sum(1 for u in self.active_users.values() 
		                              if u.get('room_id') == room_id)
		                self.active_rooms[room_id]['usercount'] = new_count
		                print(f"ROOM POP: {persona} joined room {room_id}, now {new_count} users")
		            elif room_id not in self.active_rooms:
		                # This shouldn't happen, but just in case
		                print(f"WARNING: Room {room_id} not in active_rooms!")
		        
		        elif connection_id in self.active_users:
		            # User disconnected
		            old_room_id = self.active_users[connection_id]['room_id']
		            del self.active_users[connection_id]
		            
		            if old_room_id in self.active_rooms:
		                remaining_count = sum(1 for u in self.active_users.values() 
		                                    if u.get('room_id') == old_room_id)
		                self.active_rooms[old_room_id]['usercount'] = remaining_count
		                print(f"ROOM POP: {persona} disconnected, room {old_room_id} now {remaining_count} users")
		        
		        # Always verify counts
		        print(f"ACTIVE USERS COUNT: {len(self.active_users)}")
		        for conn_id, user_data in self.active_users.items():
		            print(f"  - {user_data['persona']} in room {user_data['room_id']}")
                
    def create_room_update_packet(self, room_data):
		    """Create room update packet with correct field order"""
		    room_id = room_data.get('room_id', 0)
		    room_name = room_data.get('name', '')
		    desc = room_data.get('desc', '')
		    players = room_data.get('usercount', 0)
		    max_players = room_data.get('maxusers', 50)
		    room_type = room_data.get('type', 1)
		    host = room_data.get('host', self.server_ip)
		    
		    # Binary field order from documentation
		    fields = [
		        f"I={room_id}",           # Room ID (0x003e30d8)
		        f"H={desc}",              # Description (0x003e30e0)
		        f"A={host}",              # Host (0x003e30e8)
		        f"T={players}",           # Player count (0x003e30f0)
		        f"L={max_players}",       # Max players (0x003e30f8)
		        f"F=0"                    # Flags
		    ]
		    
		    # Room name might be in N field
		    if room_name:
		        fields.append(f"N={room_name}")
		    
		    # Password if exists
		    if room_data.get('password'):
		        fields.append(f"P={room_data['password']}")
		    
		    packet_data = '\n'.join(fields) + '\n'
		    print(f"DEBUG +rom packet for room {room_id}:")
		    print(packet_data)
		    return self.create_packet('+rom', '', packet_data)   
        
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
		                
		                # IMPORTANT: Send +rom commands for ALL rooms including Lobby (room_id: 0)
		                if "ROOMS=1" in data_str:
		                    # CALL reply_rom and iterate over it
		                    for room_packet in self.reply_rom(session):
		                        if room_packet:
		                            session.connection.sendall(room_packet)
		                            time.sleep(0.05)
		                    print(f"SELE: Sent {len(self.room_manager.active_rooms)} rooms as +rom commands")
		                
		                # Send user updates for ALL users including those in Lobby
		                if "USERS=1" in data_str:
		                    usr_packet = self.reply_usr(session)
		                    if usr_packet:
		                        session.connection.sendall(usr_packet)
		                    users_sent = len(self.room_manager.active_users)
		                    print(f"SELE: Sent {users_sent} users as +usr command")
		                
		                # Send population update
		                if "ROOMS=1" in data_str or "USERS=1" in data_str:
		                    pop_packet = self.reply_pop(session)
		                    if pop_packet:
		                        session.connection.sendall(pop_packet)
		                    print(f"SELE: Sent +pop update")
		                
		            except Exception as e:
		                print(f"SELE: Error sending updates: {e}")
		    
        # Start sending updates in background
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
		    """Handle room creation - FIXED to send +rom updates"""
		    new_room_id = 1001 + len([r for r in self.room_manager.active_rooms.keys() if r >= 1000])
		    
		    display_name = session.roomNAME
		    room_desc = session.roomDESC if session.roomDESC and session.roomDESC != "None" else "Race Room"
		    max_users = min(int(session.roomMAX) if session.roomMAX and session.roomMAX.isdigit() else 50, 50)
		    
		    print(f"ROOM: '{display_name}' created with MAX={max_users}, DESC='{room_desc}'")
		    
		    # Create room with correct flags (F=1 for public)
		    self.room_manager.active_rooms[new_room_id] = {
		        'name': display_name,
		        'desc': room_desc, 
		        'usercount': 0,  # Start with 0, will be updated by presence
		        'maxusers': max_users,
		        'room_id': new_room_id,
		        'flags': '0',
		        'type': 3 if session.roomPASS else 1,
		        'host': self.room_manager.server_ip  # Add host
		    }
		    
		    session.current_room_id = new_room_id
		    session.current_room = display_name
		    
		    username = getattr(session, 'authenticated_username', session.clientNAME)
		    persona = getattr(session, 'current_persona', username)
		    
		    print(f"ROOM DEBUG: Using username '{username}' from auth, persona '{persona}'")
		    
		    # Update presence (this will set correct population)
		    self.update_user_presence(session.connection_id, username, persona, display_name, new_room_id, True, is_self=True)
		    
		    # Send room creation response
		    response_lines = [
		        f"I={new_room_id}", 
		        f"L={max_users}", 
		        "T=1",  # Start with creator
		        "F=1",  # Public room (F=1 like default rooms)
		        f"H={room_desc}", 
		        f"A={self.room_manager.server_ip}", 
		        f"N={display_name}",  # Add room name
		        "STATUS=1"
		    ]
		    print(f"ROOM: Created room ID {new_room_id} for {username}")
		    
		    room_response = self.create_packet('room', '', '\n'.join(response_lines) + '\n')
		    
		    # Send +rom update for the new room
		    def send_room_updates():
		        time.sleep(0.3)
		        if session.connection and hasattr(session.connection, 'sendall'):
		            try:
		                # Send +rom for the new room
		                room_data = self.room_manager.active_rooms[new_room_id]
		                rom_packet = self.room_manager.create_room_update_packet(room_data)
		                session.connection.sendall(rom_packet)
		                print(f"ROOM: Sent +rom update for room {new_room_id}")
		                
		                # Also send updated +pop
		                pop_packet = self.reply_pop(session)
		                session.connection.sendall(pop_packet)
		                
		            except Exception as e:
		                print(f"ROOM: Error sending updates: {e}")
		    def broadcast_new_room(room_id, room_data):
				    """Broadcast new room to all connected clients"""
				    client_sessions = self.get_client_sessions()  # You need to implement this
				    for conn_id, other_session in client_sessions.items():
				        if other_session.connection and hasattr(other_session.connection, 'sendall'):
				            try:
				                rom_packet = self.room_manager.create_room_update_packet(room_data)
				                other_session.connection.sendall(rom_packet)
				                print(f"BROADCAST: Sent room {room_id} to {other_session.clientNAME}")
				            except Exception as e:
				                print(f"BROADCAST: Error sending to {conn_id}: {e}")		    
		    threading.Timer(0.1, send_room_updates).start()
		    threading.Timer(0.5, broadcast_new_room, args=(new_room_id, self.room_manager.active_rooms[new_room_id])).start()  
		    return room_response
		                	    
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
        print(f"+who: User list includes {persona} (user: {username})")
        return self.create_packet('+who', '', '\n'.join(fields) + '\n')
    
    def reply_pop(self, session):
		    """+pop command handler"""
		    current_room_id = getattr(session, 'current_room_id', 0)
		    room_population = "0/50"
		    for room_data in self.room_manager.active_rooms.values():
		        if room_data['room_id'] == current_room_id:
		            room_population = f"{room_data['usercount']}:{room_data['maxusers']}"
		            break
		    print(f"+pop: Room {current_room_id} population {room_population}")
		    return self.create_packet('+pop', '', f"Z={room_population}\n")

    def reply_rom(self, session):
		    """Send room list as +rom commands - INCLUDE ALL ROOMS"""
		    room_packets = []
		    
		    print(f"+rom: Building room list for {session.clientNAME}")
		    print(f"+rom: Total rooms: {len(self.room_manager.active_rooms)}")
		    
		    for room_id, room_data in self.room_manager.active_rooms.items():
		        room_name = room_data.get('name', f'Room{room_id}')
		        desc = room_data.get('desc', room_name)
		        host = room_data.get('host', self.room_manager.server_ip)
		        players = room_data.get('usercount', 0)
		        max_players = room_data.get('maxusers', 50)
		        room_type = room_data.get('type', 1)
		        
		        # Ensure F flag is consistent (1 for public rooms)
		        room_flags = '1' if room_type == 1 else '0'
		        
		        room_entry = f"I={room_id}\nN={room_name}\nH={desc}\nA={host}\nT={players}\nL={max_players}\nF={room_flags}\n"
		        
		        print(f"+rom: Room {room_id}: {room_name} ({players}/{max_players}) F={room_flags}")
		        room_packets.append(self.create_packet('+rom', '', room_entry))
		    
		    return room_packets
            
    def reply_usr(self, session):
		    """+usr command handler - send users in CURRENT ROOM, not all users"""
		    response_lines = []
		    
		    current_room_id = getattr(session, 'current_room_id', 0)
		    print(f"+usr: Building user list for room {current_room_id}")
		    
		    # Get users in the SAME room as the client
		    users_in_room = []
		    for conn_id, user_data in self.room_manager.active_users.items():
		        if user_data.get('room_id') == current_room_id:
		            users_in_room.append(user_data)
		    
		    print(f"+usr: Room {current_room_id} has {len(users_in_room)} users")
		    
		    for i, user_data in enumerate(users_in_room):
		        persona = user_data.get('persona', '')
		        is_self = (user_data.get('conn_id') == session.connection_id)
		        f_flag = '1' if is_self else '0'
		        
		        # Format: I=room_id N=name F=flag A=ip
		        ip_addr = self.room_manager.server_ip
		        if 'ip' in user_data:
		            ip_addr = user_data['ip']
		        
		        user_entry = f"I={current_room_id}\nN={persona}\nF={f_flag}\nA={ip_addr}"
		        response_lines.append(user_entry)
		        
		        print(f"+usr {'Self' if is_self else 'Other'}: {persona} F={f_flag}")
		    
		    if response_lines:
		        print(f"+usr: Sending {len(response_lines)} user entries for room {current_room_id}")
		    
		    full_response = '\n'.join(response_lines)
		    if full_response:
		        full_response += '\n'
		    
		    return self.create_packet('+usr', '', full_response)