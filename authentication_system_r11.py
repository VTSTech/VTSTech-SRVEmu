# authentication_system_r11.py - CLEANED & OPTIMIZED
import time, random, hashlib

class AuthenticationSlot:
    def __init__(self, slot_id):
        self.slot_id = slot_id
        self.data1 = (slot_id * 17 + 123) & 0xFF
        self.data2 = (slot_id * 23 + 45) & 0xFF
        self.data4 = (slot_id * 11 + 67) & 0xFFFF
        self.data5 = (slot_id * 29 + 89) & 0xFFFF
        self.active = (slot_id % 3 != 0)
        self.timestamp = int(time.time())
        self.processed_data = int(((slot_id * 7 + 13) / 100.0) * 1000 + 0.5)
        self.validation_data1 = random.randint(1, 0x2c)
        self.validation_data2 = random.randint(1, 0x2c)
        self.validation_data3 = random.randint(1, 0x1f5)

class AuthenticationStateMachine:
    def __init__(self):
        self.states = {0: "INITIAL", 1: "PROCESSING", 2: "VALIDATING", 3: "COMPLETE"}
        self.current_state = 0
        self.auth_start_time = int(time.time() * 1000)
        self.timeout_ms = 15000
        self.max_slots = 45
        
    def initialize(self, session):
        self.current_state = 0
        self.auth_start_time = int(time.time() * 1000)
        session.auth_slots = [AuthenticationSlot(i) if i % 3 != 0 else None for i in range(self.max_slots)]
        self.process_authentication(session)
        
    def process_authentication(self, session):
        states = [
            (0, f"Initializing {self.max_slots} authentication slots"),
            (1, "Processing authentication data"),
            (2, "Validating credentials"),
            (3, "Authentication complete")
        ]
        
        for state_num, msg in states:
            session.auth_state = state_num
            print(f"AUTH: State {state_num} - {msg}")
            
            if state_num == 1:
                session.auth_timestamp = int(time.time())
            elif state_num == 2:
                session.validation_code1, session.validation_code2 = 0x3039, 0x4d2
            elif state_num == 3:
                session.auth_complete = True
                session.client_flags |= 4

class AccountManager:
    @staticmethod
    def create_account(session, create_packet_func):
        required_fields = ['NAME', 'USER', 'PASS', 'BORN', 'MAIL']
        for field in required_fields:
            if not getattr(session, f'client{field}', ''):
                return create_packet_func('acct', '', f"STATUS=0\nERROR=Missing required fields\n")
        
        md5_hash = hashlib.md5(session.clientPASS.encode('ascii')).hexdigest()
        timestamp = time.strftime('%Y.%m.%d %I:%M:%S')
        default_personas = [session.clientNAME]
        
        try:
            with open("acct.db", "a") as db:
                db.write(f"{session.clientNAME}#{session.clientBORN}#{session.clientMAIL}#{md5_hash}#{session.clientPERS}#{session.clientLAST}#{','.join(default_personas)}\n")
            print(f"ACCT: Successfully created account for {session.clientNAME}")
        except Exception as e:
            print(f"ACCT: Error saving account: {e}")
            return create_packet_func('acct', '', "STATUS=0\nERROR=Account creation failed\n")
        
        response_lines = [
            "TOS=1", f"NAME={session.clientNAME.lower()}", f"USER={session.clientUSER}",
            "AGE=21", f"PERSONAS={','.join(default_personas)}", f"SINCE={timestamp}",
            f"LAST={timestamp}", f"PRIV={getattr(session, 'clientPRIV', '1')}", "SPAM=NN", "STATUS=1"
        ]
        
        return create_packet_func('acct', '', '\n'.join(response_lines) + '\n')
    
    @staticmethod
    def update_account_personas(username, personas):
        try:
            with open("acct.db", "r") as db: 
                lines = db.readlines()
            updated = False
            with open("acct.db", "w") as db:
                for line in lines:
                    parts = line.strip().split('#')
                    if parts[0] == username:
                        if len(parts) < 7: 
                            parts.append(','.join(personas))
                        else: 
                            parts[6] = ','.join(personas)
                        line = '#'.join(parts) + '\n'
                        updated = True
                    db.write(line)
            return updated
        except Exception as e: 
            print(f"Error updating account personas: {e}")
            return False
    
    @staticmethod
    def load_account_personas(username):
        try:
            with open("acct.db", "r") as db:
                for line in db:
                    parts = line.strip().split('#')
                    if len(parts) >= 7 and parts[0] == username and parts[6]:
                        return parts[6].split(',')
        except FileNotFoundError: 
            pass
        return [username]

class PersonaManager:
    @staticmethod
    def create_persona(session, create_packet_func):
        new_persona = getattr(session, 'clientPERS', '') or f"{session.clientNAME}_ALT{len(session.available_personas)}"
        
        if len(session.available_personas) < 4:
            session.available_personas.append(new_persona)
            session.persona_count = len(session.available_personas)
            if AccountManager.update_account_personas(session.clientNAME, session.available_personas):
                print(f"CPER: Created persona '{new_persona}'")
                response = f"PERS={new_persona}\nALTS={session.persona_count}\nSTATUS=1\n"
            else:
                session.available_personas.remove(new_persona)
                response = f"PERS={new_persona}\nALTS={session.persona_count}\nSTATUS=0\n"
        else:
            response = f"PERS={new_persona}\nALTS=4\nSTATUS=0\n"
        
        return create_packet_func('cper', '', response)
    
    @staticmethod
    def delete_persona(session, create_packet_func):
        target_persona = getattr(session, 'clientPERS', '')
        if target_persona in session.available_personas:
            session.available_personas.remove(target_persona)
            session.persona_count = len(session.available_personas)
            if AccountManager.update_account_personas(session.clientNAME, session.available_personas):
                print(f"DPER: Deleted persona '{target_persona}'")
                status = 1
            else:
                session.available_personas.append(target_persona)
                status = 0
        else: 
            status = 0
        
        return create_packet_func('dper', '', f"PERS={target_persona}\nALTS={session.persona_count}\nSTATUS={status}\n")
    
    @staticmethod
    def switch_persona(session, create_packet_func):
        selected_persona = getattr(session, 'clientPERS', '')
        session.current_persona = selected_persona if selected_persona and selected_persona in session.available_personas else (session.available_personas[0] if session.available_personas else session.clientNAME)
        
        print(f"PERS: Switched to persona '{session.current_persona}'")
        
        try:
            import __main__
            if hasattr(__main__, 'room_manager'):
                current_room = getattr(session, 'current_room', 'Lobby')
                current_room_id = getattr(session, 'current_room_id', 0)
                
                __main__.room_manager.update_user_presence(
                    session.connection_id,
                    session.authenticated_username,
                    session.current_persona,
                    current_room,
                    current_room_id,
                    True,
                    True
                )
                print(f"PERS: Updated presence for {session.authenticated_username} as '{session.current_persona}'")
        except Exception as e:
            print(f"PERS: Error updating presence: {e}")
        
        return create_packet_func('pers', '', f"PERS={session.current_persona}\nLKEY=$0\nSTATUS=0\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n")

class AuthenticationHandlers:
    def __init__(self, create_packet_func, active_users=None, client_sessions=None):
        self.create_packet = create_packet_func
        self.active_users = active_users or {}
        self.client_sessions = client_sessions or {}
        self.auth_machine = AuthenticationStateMachine()
    
    def handle_auth(self, data, session):
        session.authsent = 1
        session.update_client_state(0x61757468)
        
        authenticated_username = getattr(session, 'clientNAME', '') or getattr(session, 'clientUSER', 'UnknownUser')
        print(f"AUTH: Starting authentication for '{authenticated_username}'")
        
        self.auth_machine.initialize(session)
        
        if not hasattr(session, 'clientSESS') or not session.clientSESS:
            session.clientSESS = f"{int(time.time()) % 1000000}{random.randint(100000, 999999)}"
            print(f"AUTH: Generated SESS = {session.clientSESS}")
        
        account_personas = AccountManager.load_account_personas(authenticated_username)
        session.available_personas = account_personas
        session.current_persona = account_personas[0]
        session.persona_count = len(account_personas)
        session.authenticated_username = authenticated_username
        
        try:
            import __main__
            if hasattr(__main__, 'room_manager'):
                __main__.room_manager.update_user_presence(
                    session.connection_id,
                    authenticated_username,
                    session.current_persona,
                    'Lobby',
                    0,
                    True,
                    True
                )
                print(f"AUTH: Added {authenticated_username} to active users")
        except Exception as e:
            print(f"AUTH: Error updating user presence: {e}")
        
        response_lines = [
            "TOS=1", 
            f"NAME={authenticated_username}", 
            f"USER={getattr(session, 'clientUSER', authenticated_username)}",
            f"PERSONAS={','.join(account_personas)}", 
            f"PRIV={getattr(session, 'clientPRIV', '1')}",
            f"LAST={getattr(session, 'clientLAST', time.strftime('%Y.%m.%d-%H:%M:%S'))}", 
            f"SESS={session.clientSESS}",
            "S=0",
            "STATUS=0"
        ]
        
        session.client_flags |= 0x2
        session.auth_complete = True
        session.client_state = 0x69646c65
        session.protocol_timeout = int(time.time() * 1000) + 300000
        
        print(f"PROTOCOL: {session.connection_id} -> STATE_IDLE, flags = {session.client_flags:08x}")
        
        try:
            import __main__
            if hasattr(__main__, 'buddy_handlers'):
                __main__.buddy_handlers.update_buddy_status(authenticated_username, True)
                print(f"BUDDY: Updated online status for {authenticated_username}")
        except Exception as e:
            print(f"BUDDY: Could not update status for {authenticated_username}: {e}")
        
        return self.create_packet('auth', '', '\n'.join(response_lines) + '\n')
    
    def handle_acct(self, data, session):
        return AccountManager.create_account(session, self.create_packet)
    
    def handle_cper(self, data, session):
        return PersonaManager.create_persona(session, self.create_packet)
    
    def handle_dper(self, data, session):
        return PersonaManager.delete_persona(session, self.create_packet)
    
    def handle_pers(self, data, session):
        return PersonaManager.switch_persona(session, self.create_packet)
    
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
            if user_data.get('persona') == target_persona or user_data.get('username') == target_persona:
                target_found = True
                target_conn_id = conn_id
                break
        
        if target_found and target_conn_id in self.client_sessions:
            target_session = self.client_sessions[target_conn_id]
            response = f"PERS={target_persona}\nTITLE=1\nSTATUS=0\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n"
            print(f"USER: Found target {target_persona} in room {target_session.current_room}")
        else:
            response = f"PERS={target_persona}\nTITLE=0\nSTATUS=0\nERROR=User not found\n"
            print(f"USER: Target {target_persona} not found")
        
        return self.create_packet('user', '', response)
    
    def handle_edit(self, data, session):
        data_str = data.decode('latin1') if data else ""
        print(f"EDIT: Profile edit: {data_str}")
        
        editable_fields = ['MAIL', 'BORN', 'GEND', 'CHNG']
        updated_fields = {}
        
        for line in data_str.split('\n'):
            for field in editable_fields:
                if line.startswith(field + '='):
                    updated_fields[field] = line[len(field)+1:]
        
        if updated_fields:
            print(f"EDIT: Updated fields: {updated_fields}")
            response = "STATUS=0\n" + '\n'.join([f"{k}={v}" for k, v in updated_fields.items()]) + '\n'
        else:
            response = "STATUS=0\nERROR=No valid fields\n"
        
        return self.create_packet('edit', '', response)