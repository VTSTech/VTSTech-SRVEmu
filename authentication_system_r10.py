# authentication_system_r08.py - CLEANED & OPTIMIZED
import time
import random
import hashlib

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
        """Process authentication through all states"""
        session.auth_state = 0
        print(f"AUTH: State 0 - Initializing {self.max_slots} authentication slots")
        
        session.auth_state = 1
        print("AUTH: State 1 - Processing authentication data")
        
        session.auth_timestamp = int(time.time())
        session.auth_state = 2
        print("AUTH: State 2 - Validating credentials")
        
        session.validation_code1 = 0x3039
        session.validation_code2 = 0x4d2
        session.auth_state = 3
        session.auth_complete = True
        session.client_flags |= 4
        print("AUTH: State 3 - Authentication complete")

class AccountManager:
    @staticmethod
    def create_account(session, create_packet_func):
        required_fields = ['NAME', 'USER', 'PASS', 'BORN', 'MAIL']
        for field in required_fields:
            if not getattr(session, f'client{field}', ''):
                return create_packet_func('acct', '', "STATUS=0\nERROR=Missing required fields\n")
        
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
            f"LAST={timestamp}", f"PRIV={getattr(session, 'clientPRIV', '1')}", "STATUS=1"
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
        return [username]  # Default persona

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
        if selected_persona and selected_persona in session.available_personas:
            session.current_persona = selected_persona
            print(f"PERS: Switched to persona '{selected_persona}'")
        else: 
            session.current_persona = session.available_personas[0] if session.available_personas else session.clientNAME
        
        return create_packet_func('pers', '', f"PERS={session.current_persona}\nSTATUS=1\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n")

class AuthenticationHandlers:
    def __init__(self, create_packet_func):
        self.create_packet = create_packet_func
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
        
        response_lines = [
				    "TOS=1", 
				    f"NAME={authenticated_username}", 
				    f"USER={getattr(session, 'clientUSER', authenticated_username)}",
				    f"PERSONAS={','.join(account_personas)}", 
				    f"PRIV={getattr(session, 'clientPRIV', '1')}",
				    f"LAST={getattr(session, 'clientLAST', time.strftime('%Y.%m.%d-%H:%M:%S'))}", 
				    f"SESS={session.clientSESS}",
				    "AUTH=1",
				    "STATUS=1"  # Keep this, might be important
				]
        
        session.client_flags |= 0x2
        session.auth_complete = True
        session.client_state = 0x69646c65
        session.protocol_timeout = int(time.time() * 1000) + 300000
        
        print(f"PROTOCOL: {session.connection_id} -> STATE_IDLE, flags = {session.client_flags:08x}")
        
        # FIXED: Access buddy_handlers through global scope
        try:
            # Try to update buddy status if buddy system is available
            import __main__
            if hasattr(__main__, 'buddy_handlers'):
                __main__.buddy_handlers.update_buddy_status(authenticated_username, True)
                print(f"BUDDY: Updated online status for {authenticated_username}")
        except Exception as e:
            print(f"BUDDY: Could not update status for {authenticated_username}: {e}")
        
        #session_data = self.generate_272_byte_session_data(session)
        #self.send_session_data(session, session_data)
		    
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
        print(f"USER: Validated user {session.clientNAME}")
        response = f"PERS={session.clientPERS}\nTITLE=1\nSTATUS=1\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n"
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
            response = "STATUS=1\n" + '\n'.join([f"{k}={v}" for k, v in updated_fields.items()]) + '\n'
        else:
            response = "STATUS=0\nERROR=No valid fields\n"
        
        return self.create_packet('edit', '', response)