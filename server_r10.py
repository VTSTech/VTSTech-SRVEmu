# server_r10.py - CLEANED & OPTIMIZED
import sys
import socket
import struct
import time
import threading
import random
import uuid
from _thread import *

# Import modular systems
from challenge_system_r10 import ChallengeSystem
from authentication_system_r10 import AuthenticationHandlers
from session_system_r10 import SessionManager, NetworkHandlers, PingManager, DataServerManager
from room_system_r10 import RoomManager, RoomHandlers
from message_system_r10 import MessageHandlers
from buddy_system_r10 import BuddyHandlers

from state_trigger import StateTrigger
# Import game modules
try:
    from nascar_module import NascarHandlers
    HAS_NASCAR = True
except ImportError:
    HAS_NASCAR = False
    print("WARNING: NASCAR module not available")

try:
    from nbav3_module import NBAv3Handlers
    HAS_NBAV3 = True
except ImportError:
    HAS_NBAV3 = False
    print("WARNING: NBA Street v3 module not available")

# Configuration
BUILD = "0.10-Modular"
PORT_NFSU_PS2 = 10900   # ps2nfs04.ea.com:10900
PORT_NFSU2_PS2 = 20900  # ps2nfs05.ea.com:10900
PORT_BO3U_PS2 = 21800   # ps2burnout05.ea.com:21800
PORT_BO3R_PS2 = 21840   # ps2lobby02.beta.ea.com:21840
PORT_NFL05_PS2 = 20000  # ps2madden05.ea.com:20000
PORT_BOP_PS3 = 21870    # ps3burnout08.ea.com:21870
PORT_BOP_PC = 21840     # pcburnout08.ea.com:21871
PORT_SSX3_PS2 = 11000   # ps2ssx04.ea.com:11000
PORT_NC04_PS2 = 10600   # ps2nascar04.ea.com:10600
PORT_NBAV3_PS2 = 21000  # ps2nbastreet05.ea.com:21000

# Update the PORTS dictionary
PORTS = {
    'nc04': PORT_NC04_PS2,
    'listener': PORT_NFSU_PS2,  # Using NFSU port as default listener
    'buddy': 10899,
    'data_start': 11000,
    'nbav3': PORT_NBAV3_PS2,
    'nfsu': PORT_NFSU_PS2,
    'nfsu2': PORT_NFSU2_PS2,
    'bo3u': PORT_BO3U_PS2,
    'bo3r': PORT_BO3R_PS2,
    'nfl05': PORT_NFL05_PS2,
    'bop_ps3': PORT_BOP_PS3,
    'bop_pc': PORT_BOP_PC,
    'ssx3': PORT_SSX3_PS2
}

# Update GAME_MODES dictionary (around line 35)
GAME_MODES = {
    'nascar': {
        'port': PORT_NC04_PS2,
        'name': 'NASCAR Thunder 2004',
        'module': None,
        'handlers': None
    },
    'nbav3': {
        'port': PORT_NBAV3_PS2,
        'name': 'NBA Street v3',
        'module': None,
        'handlers': None
    },
    'nfsu': {
        'port': PORT_NFSU_PS2,
        'name': 'Need for Speed Underground',
        'module': None,
        'handlers': None
    },
    'nfsu2': {
        'port': PORT_NFSU2_PS2,
        'name': 'Need for Speed Underground 2',
        'module': None,
        'handlers': None
    },
    'bo3u': {
        'port': PORT_BO3U_PS2,
        'name': 'Burnout 3: Takedown (Update)',
        'module': None,
        'handlers': None
    },
    'bo3r': {
        'port': PORT_BO3R_PS2,
        'name': 'Burnout 3: Takedown (Release)',
        'module': None,
        'handlers': None
    },
    'nfl05': {
        'port': PORT_NFL05_PS2,
        'name': 'Madden NFL 2005',
        'module': None,
        'handlers': None
    },
    'bop_ps3': {
        'port': PORT_BOP_PS3,
        'name': 'Burnout Paradise (PS3)',
        'module': None,
        'handlers': None
    },
    'bop_pc': {
        'port': PORT_BOP_PC,
        'name': 'Burnout Paradise (PC)',
        'module': None,
        'handlers': None
    },
    'ssx3': {
        'port': PORT_SSX3_PS2,
        'name': 'SSX 3',
        'module': None,
        'handlers': None
    }
}
SERVER_IP = None
PORTS = {
    'listener': 10901, 
    'buddy': 10899, 
    'data_start': 11000, 
}

# Game modes
GAME_MODES = {
    'nascar': {
        'port': PORT_NC04_PS2,
        'name': 'NASCAR Thunder 2004',
        'module': None,
        'handlers': None
    },
    'nbav3': {
        'port': PORT_NBAV3_PS2,
        'name': 'NBA Street v3',
        'module': None,
        'handlers': None
    }
}
# Global state
current_data_port = PORTS['data_start']
locks = {'data': threading.Lock()}
sockets = {'game': socket.socket(), 'buddy': socket.socket(), 'listener': socket.socket()}
current_game_mode = None  # Will be set during bind_server()

# Protocol states
PROTOCOL_STATES = {
    0x72646972: "STATE_DIRECTORY",
    0x636f6e6e: "STATE_CONNECTED", 
    0x736b6579: "STATE_KEY_EXCHANGE",
    0x69646c65: "STATE_IDLE",
    0x61757468: "STATE_AUTH",
    0x61636374: "STATE_ACCOUNT",
    0x74696d65: "STATE_TIMEOUT",
    0x7465726d: "STATE_TERMINATED",
    0x6f66666c: "STATE_OFFLINE",
    0xfefefefe: "STATE_ERROR"
}

class ClientSession:
    def __init__(self, connection_id, game_mode=None):
        self.connection_id = connection_id
        self.game_mode = game_mode  # Store which game mode this session is for
        self.connection = self.ping_timer = None
        self.data_port = 0
        self.msgType = b''; self.msgSize = 0
        self.authsent = self.SKEYSENT = self.NO_DATA = 0
        self.news_cnt = self.ping_cnt = 0
        self.last_activity = self.ping_start = time.time()
        self.last_ping_time = 0; self.ping_interval = 5.0
        self.ping_initiated = False
        
        # User identity
        self.clientNAME = 'Unknown'
        self.clientUSER = 'Unknown'
        self.current_persona = 'Unknown'
        self.authenticated_username = 'Unknown'
        
        self.available_personas = []; self.persona_count = 0
        self.current_room = "Lobby"; self.current_room_id = 0
        
        # Authentication
        self.auth_state = 0
        self.auth_complete = False
        self.auth_slots = []
        self.validation_code1 = 0
        self.validation_code2 = 0
        self.validation_code3 = 0
        self.auth_timestamp = 0
        
        # Challenge system
        self.challenge_state = 0
        self.challenger = ''
        self.challenge_target = ''
        self.challenge_seed = ''
        self.challenge_timeout = 0
        self.last_challenge_state = 0
        self.system_command_sent = False
        
        # Buddy system
        self.buddy_socket = None
        self.buddy_connected = False
        self.buddy_list = []        
        
        # Game-specific state initialization
        if game_mode == 'nascar':
            # NASCAR Thunder 2004
            self.race_state = 'INACTIVE'
            self.race_track = 'DAYTONA'
            self.race_laps = '10'
            self.race_difficulty = '2'
            self.race_start_time = 0
            self.lap_times = []
            self.race_position = 1
            self.race_config = {}
            
        elif game_mode == 'nbav3':
            # NBA Street v3
            self.street_rank = 1
            self.game_mode = 'STREET'
            self.character_data = {}
            
        elif game_mode in ['nfsu', 'nfsu2']:
            # Need for Speed Underground
            self.car_data = {}
            self.current_car = 'default'
            self.race_type = 'circuit'
            self.drift_score = 0
            
        elif game_mode in ['bo3u', 'bo3r', 'bop_ps3', 'bop_pc']:
            # Burnout series
            self.crash_mode = False
            self.takedown_count = 0
            self.vehicle_type = 'car'
            
        elif game_mode == 'nfl05':
            # Madden NFL 2005
            self.team_name = 'Unknown'
            self.playbook = 'default'
            self.quarter_length = 5
            
        elif game_mode == 'ssx3':
            # SSX 3
            self.boarder_name = 'Unknown'
            self.trick_score = 0
            self.current_mountain = 'peak'
            
        # Protocol state
        self.client_state = 0x72646972
        self.client_flags = 0
        self.direct_address = 0
        self.direct_port = 0
        self.server_address = ""
        self.public_key_sent = self.room_flags = 0
        
        # Game state tracking
        self.game_state = 0x4b1  # MULTIPLAYER_LOBBY
        
        # Protocol management
        self.protocol_timeout = 0
        self.last_protocol_activity = time.time()
        
        # Multiplayer initialization tracking
        self.buddy_config_sent = False
        self.multiplayer_initialized = False
        self.expecting_chal = False
        
        # Initialize client data fields
        fields = ['ALTS', 'VERS', 'MAC', 'SKU', 'PERS', 'LAST', 'LKEY', 'PLAST', 'MAIL', 
                 'ADDR', 'MADDR', 'BORN', 'PASS', 'PROD', 'SESS', 'SLUS', 'MINSIZE', 'MAXSIZE',
                 'CUSTFLAGS', 'PARAMS', 'PRIV', 'PERSONAS', 'SEED', 'SYSFLAGS', 'HWFLAG', 'HWMASK', 
                 'DEFPER', 'SDKVER', 'PID', 'CHAN', 'INDEX', 'START', 'RANGE', 'roomNAME', 'roomPASS',
                 'roomDESC', 'roomMAX', 'moveNAME', 'movePASS', 'NEWS_PAYLOAD', 'pingREF', 'pingTIME',
                 'FROM', 'TO', 'WHEN', 'TEXT']
        
        # Game-specific fields
        if game_mode == 'nascar':
            fields.extend(['SET_TRACK', 'SET_RACELEN', 'SET_AIDIFF', 'SET_DAMAGE',
                          'SET_RANKED', 'SET_SETUPS', 'SET_NUMAI', 'SET_ASSISTS',
                          'SET_CAUTIONS', 'SET_CONSUME', 'SET_TRACKID'])
        elif game_mode in ['nfsu', 'nfsu2']:
            fields.extend(['CAR_MODEL', 'CAR_TUNE', 'RACE_TYPE', 'NITROUS_LEVEL'])
        elif game_mode in ['bo3u', 'bo3r', 'bop_ps3', 'bop_pc']:
            fields.extend(['VEHICLE', 'SPEED', 'CRASH_MODE', 'TAKEDOWNS'])
        elif game_mode == 'nfl05':
            fields.extend(['TEAM', 'PLAYBOOK', 'QUARTER_LENGTH', 'DIFFICULTY'])
        elif game_mode == 'ssx3':
            fields.extend(['BOARDER', 'TRICK_SCORE', 'MOUNTAIN', 'BOOST_LEVEL'])
        
        for field in fields:
            attr_name = f"client{field}" if not field.startswith(('room', 'move', 'NEWS', 'ping', 'SET_', 'FROM', 'TO', 'WHEN', 'TEXT', 'CAR_', 'NITROUS_', 'VEHICLE', 'SPEED', 'CRASH_', 'TAKEDOWNS', 'TEAM', 'PLAYBOOK', 'QUARTER_', 'DIFFICULTY', 'BOARDER', 'TRICK_', 'MOUNTAIN', 'BOOST_')) else field
            setattr(self, attr_name, '')

    def update_client_state(self, new_state):
        old_state = self.client_state
        self.client_state = new_state
        self.last_protocol_activity = time.time()
        
        old_state_name = PROTOCOL_STATES.get(old_state, f"UNKNOWN({old_state:08x})")
        new_state_name = PROTOCOL_STATES.get(new_state, f"UNKNOWN({new_state:08x})")
        
        print(f"PROTOCOL STATE: {self.connection_id} {old_state_name} -> {new_state_name}")
        
        if new_state == 0x69646c65:
            self.protocol_timeout = int(time.time() * 1000) + 300000
        elif new_state == 0x61757468:
            self.protocol_timeout = int(time.time() * 1000) + 30000
            
    def check_protocol_timeout(self):
        if self.protocol_timeout == 0:
            return False
            
        current_time = int(time.time() * 1000)
        
        if self.client_state == 0x69646c65:
            time_since_activity = (current_time - self.protocol_timeout) / 1000
            if time_since_activity > 300:
                print(f"PROTOCOL TIMEOUT: {self.connection_id} idle for {time_since_activity:.0f}s")
                self.client_state = 0x74696d65
                return True
            return False
        else:
            if current_time > self.protocol_timeout:
                print(f"PROTOCOL TIMEOUT: {self.connection_id} state {self.client_state:08x}")
                self.client_state = 0x74696d65
                return True
        return False

    def update_activity(self):
        self.last_activity = time.time()
        self.protocol_timeout = int(time.time() * 1000) + 300000

    def set_client_flag(self, flag):
        self.client_flags |= flag
        print(f"PROTOCOL FLAG: {self.connection_id} flags = {self.client_flags:08x}")

    def clear_client_flag(self, flag):
        self.client_flags &= ~flag
        print(f"PROTOCOL FLAG: {self.connection_id} flags = {self.client_flags:08x}")

# System instances
challenge_system = None
auth_handlers = None
session_manager = None
network_handlers = None
ping_manager = None
data_server_manager = None
room_manager = None
room_handlers = None
message_handlers = None
buddy_handlers = None

def send_online_status(session):
    """Send online status to client after authentication"""
    if session.connection:
        try:
            online_packet = create_packet('onln', '', f"STATUS=1\nUSER={session.clientNAME}\nROOM={session.current_room}\n")
            session.connection.sendall(online_packet)
            print(f"ONLN: Sent online status to {session.clientNAME}")
        except Exception as e:
            print(f"ONLN: Error sending online status: {e}")
            	
def get_next_data_port():
    global current_data_port
    with locks['data']:
        port = current_data_port
        current_data_port = PORTS['data_start'] if current_data_port > PORTS['data_start'] + 1000 else current_data_port + 1
        return port
        
def create_packet(cmd, subcmd, payload):
    if isinstance(payload, str): 
        payload = payload.encode('ascii')
        payload += b'\0'
    size = len(payload)
    return struct.pack(">4s4sL%ds" % size, bytearray(cmd, 'ascii'), 
                      bytearray(subcmd, 'ascii'), size + 12, payload)

# Game-specific handler dispatcher
def handle_game_specific_command(cmd_str, data, session):
    """Route commands to game-specific handlers"""
    global current_game_mode
    
    if not current_game_mode or current_game_mode not in GAME_MODES:
        print(f"ERROR: No game mode set for command {cmd_str}")
        return None
    
    game_handlers = GAME_MODES[current_game_mode]['handlers']
    
    if not game_handlers:
        print(f"ERROR: No handlers loaded for game mode {current_game_mode}")
        return None
    
    # Dispatch to game-specific handlers
    if current_game_mode == 'nascar':
        if cmd_str == 'rank':
            return game_handlers.handle_rank(data, session)
    
    elif current_game_mode == 'nbav3':
        # Map commands to handlers
        command_map = {
            'gpro': game_handlers.handle_gpro,
            'usld': game_handlers.handle_usld,
            'uatr': game_handlers.handle_uatr,
            'cbal': game_handlers.handle_cbal,
            'ccrt': game_handlers.handle_ccrt,
            'gqwk': game_handlers.handle_gqwk,
            'glea': game_handlers.handle_glea,
            'set%': game_handlers.handle_set_percent,
        }
        
        # Check direct mapping first
        if cmd_str in command_map:
            return command_map[cmd_str](data, session)
        
        # Check if it's a data chunk
        elif game_handlers.is_hex_continuation(cmd_str):
            return game_handlers.handle_data_chunk(cmd_str, data, session)
    
    return None

def update_game_state(session, new_state):
    old_state = session.game_state
    session.game_state = new_state
    print(f"GAME STATE: {session.connection_id} 0x{old_state:04x} -> 0x{new_state:04x}")

def parse_data(data, session):
    if not data: return
    
    # Store original data as bytes
    if isinstance(data, bytes):
        data_bytes = data
    else:
        data_bytes = str(data).encode('latin1')
    
    lines = data_bytes.split(b'\x0A')
    
    if session.msgType == b'news':
        session.NEWS_PAYLOAD = next((line.decode('latin1')[5:] for line in lines if line.startswith(b'NAME')), '')
    elif session.msgType == b'~png':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("REF"): session.pingREF = text[4:]
            elif text.startswith("TIME"): session.pingTIME = text[5:]
    elif session.msgType == b'room':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("NAME"): session.roomNAME = text[5:]
            elif text.startswith("PASS"): session.roomPASS = text[5:]
            elif text.startswith("DESC"): session.roomDESC = text[5:]
            elif text.startswith("MAX"): session.roomMAX = text[4:]
    elif session.msgType == b'move':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("NAME"): 
                session.moveNAME = text[5:] if text[5:] else 'Lobby'
            elif text.startswith("PASS"): session.movePASS = text[5:]
    elif session.msgType == b'chal':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("FROM"): session.FROM = text[5:]
            elif text.startswith("TO"): session.TO = text[3:]
    elif session.msgType == b'mesg':
        # Convert to string for debugging
        data_str = data_bytes.decode('latin1', errors='ignore') if data_bytes else ""
        print(f"MESG DEBUG from {session.clientNAME}:")
        print(f"  Raw data: {data_str}")
        
        # Check if it's a challenge response
        if 'T=ACPT' in data_str or 'T=DECL' in data_str or 'T=BLOC' in data_str:
            print(f"  CHALLENGE RESPONSE DETECTED!")
        
        # Parse and log all fields
        for line in lines:
            if line.strip():
                print(f"  Field: {line.decode('latin1', errors='ignore')}")
        for line in lines:
            text = line.decode('latin1', errors='ignore')
            if text.startswith("N"): 
                session.mesg_target = text[2:]
            elif text.startswith("T"): session.TEXT = text[2:]
    elif session.msgType == b'auxi':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("TEXT"): session.TEXT = text[5:]
    elif session.msgType == b'peek':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("NAME"): 
                session.peekNAME = text[5:]
                print(f"PARSE PEEK: Found NAME='{session.peekNAME}'")
    elif session.msgType == b'rank':
        for line in lines:
            text = line.decode('latin1')
            if text.startswith("SET_TRACK"): session.SET_TRACK = text[10:]
            elif text.startswith("SET_RACELEN"): session.SET_RACELEN = text[12:]
            elif text.startswith("SET_AIDIFF"): session.SET_AIDIFF = text[11:]
            elif text.startswith("SET_DAMAGE"): session.SET_DAMAGE = text[11:]
            elif text.startswith("SET_RANKED"): session.SET_RANKED = text[11:]
            elif text.startswith("SET_SETUPS"): session.SET_SETUPS = text[11:]
            elif text.startswith("SET_NUMAI"): session.SET_NUMAI = text[10:]
            elif text.startswith("SET_ASSISTS"): session.SET_ASSISTS = text[12:]
            elif text.startswith("SET_CAUTIONS"): session.SET_CAUTIONS = text[13:]
            elif text.startswith("SET_CONSUME"): session.SET_CONSUME = text[12:]
            elif text.startswith("SET_TRACKID"): session.SET_TRACKID = text[12:]
    else:
        field_map = {
            'MID': 'MAC', 'MAC': 'MAC', 'PID': 'PID', 'SKU': 'SKU', 'ALTS': 'ALTS',
            'BORN': 'BORN', 'SLUS': 'SLUS', 'VERS': 'VERS', 'NAME': 'NAME', 'USER': 'USER',
            'PASS': 'PASS', 'PERS': 'PERS', 'PROD': 'PROD', 'SEED': 'SEED', 'MAIL': 'MAIL',
            'LAST': 'LAST', 'LKEY': 'LKEY', 'PRIV': 'PRIV', 'PLAST': 'PLAST', 'MADDR': 'MADDR',
            'HWFLAG': 'HWFLAG', 'HWMASK': 'HWMASK', 'DEFPER': 'DEFPER', 'PARAMS': 'PARAMS',
            'SDKVER': 'SDKVER', 'MINSIZE': 'MINSIZE', 'MAXSIZE': 'MAXSIZE', 'SYSFLAGS': 'SYSFLAGS',
            'CUSTFLAGS': 'CUSTFLAGS', 'PERSONAS': 'PERSONAS', 'FROM': 'FROM', 'TO': 'TO',
            'WHEN': 'WHEN', 'TEXT': 'TEXT', 'TOS': 'TOS', 'LANG': 'LANG'
        }
        
        for line in lines:
            text = line.decode('latin1')
            for prefix, field in field_map.items():
                if text.upper().startswith(prefix + '='):
                    value = text[text.find('=') + 1:]
                    
                    if session.msgType == b'auth' and prefix == 'NAME':
                        setattr(session, f"client{field}", value)
                        print(f"PARSE AUTH: Found NAME='{value}'")
                        break
                    elif prefix == 'NAME' and session.msgType == b'peek':
                        setattr(session, f"peek{field}", value)
                        print(f"PARSE PEEK: Found NAME='{value}' for targeting")
                        break
                    elif prefix == 'NAME' and hasattr(session, 'auth_complete') and session.auth_complete:
                        print(f"PARSE DEBUG: Ignoring NAME='{value}' after authentication")
                    else:
                        if value or field in ['PASS', 'TEXT']:
                            setattr(session, f"client{field}", value)
                    break

def handle_system_command(data, session):
    """Handle system commands - delegate to challenge system"""
    return challenge_system.handle_system_command(data, session)

def handle_onln(data, session):
    print(f"ONLN: Online status check from {session.clientNAME}")
    response = f"STATUS=1\nSERVER=VTSTech\nVERSION={BUILD}\nUSERS={len(session_manager.client_sessions)}\n"
    return create_packet('onln', '', response)

def handle_snap(data, session):
    data_str = data.decode('latin1') if data else ""
    print(f"SNAP: Snapshot request: {data_str}")
    
    config = {}
    for line in data_str.split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            config[key] = value
    
    snapshot_type = config.get('CHAN', '0')
    response = f"CHAN={snapshot_type}\nSTATUS=1\n"
    return create_packet('snap', '', response)

def handle_rept(data, session):
    data_str = data.decode('latin1') if data else ""
    print(f"REPT: Report from {session.clientNAME}")
    
    # Parse PERS field if present
    for line in data_str.split('\n'):
        if line.startswith('PERS='):
            persona = line[5:]
            print(f"REPT: Persona report for {persona}")
    
    return create_packet('rept', '', "STATUS=1\n")

def handle_tic(data, session):
		pass

def create_272_byte_session_data(session):
    session_data = bytearray(272)
    session_data[0:4] = struct.pack(">I", 1)
    session_data[4:8] = struct.pack(">I", session.current_room_id or 1)
    session.session_data_ready = True
    return bytes(session_data)

def reply_play(data, session):
    parse_data(data, session)
    print(f"PLAY: Race start for {session.clientNAME}, state={session.challenge_state}")
    
    if session.challenge_state != 6:
        print(f"PLAY ERROR: Invalid state {session.challenge_state}, expected 6")
        return create_packet('play', '', "STATUS=0\nERROR=Invalid state\n")
    
    session_data = create_272_byte_session_data(session)
    
    response_lines = [
        "SELF=1", "HOST=1", "OPPO=0", "P1=1", "P2=0", "P3=0", "P4=0",
        "AUTH=1", f"FROM={session.clientNAME}", 
        f"SEED={int(time.time())}", f"WHEN={int(time.time())}", "STATUS=1"
    ]
    
    response = '\n'.join(response_lines) + '\n'
    play_packet = create_packet('play', '', response)
    
    def send_session_data():
        time.sleep(0.5)
        if session.connection:
            try:
                ses_packet = create_packet('+ses', '', session_data)
                session.connection.sendall(ses_packet)
                print(f"SESSION: Sent 272-byte data to {session.clientNAME}")
            except Exception as e:
                print(f"SESSION: Error sending data: {e}")
    
    threading.Thread(target=send_session_data, daemon=True).start()
    return play_packet

def send_multiplayer_initialization(session):
    """Send multiplayer initialization sequence AFTER room join"""
    if session.multiplayer_initialized:
        print(f"MULTIPLAYER: Already initialized for {session.clientNAME}")
        return
    
    print(f"\n=== MULTIPLAYER INIT for {session.clientNAME} (in room: {session.current_room}) ===")
    
    # 1. Send 272-byte session data
    print("  Step 1: Sending 272-byte session data (+ses)")
    session_data = create_272_byte_session_data(session)
    ses_packet = create_packet('+ses', '', session_data)
    session.connection.sendall(ses_packet)
    time.sleep(0.5)    
    print(f"=== MULTIPLAYER INIT COMPLETE ===\n")    
    session.multiplayer_initialized = True
    session.expecting_chal = True

def handle_mesg_command(data, session):
    """Route mesg commands: challenge messages -> challenge system, others -> message system"""
    
    # First try challenge system
    challenge_response = challenge_system.handle_mesg(data, session)
    
    if challenge_response is None:
        # Not a challenge message, send to message system
        print(f"MESG: Routing to message system (non-challenge message)")
        return message_handlers.handle_mesg(data, session)
    else:
        # Challenge system handled it
        return challenge_response
            
def build_reply(data, session):
    global challenge_system, auth_handlers, network_handlers, ping_manager, room_handlers
    global message_handlers, ranking_handlers, buddy_handlers
    
    cmd_str = session.msgType.decode('latin1') if isinstance(session.msgType, bytes) else str(session.msgType)
    
    # First, try game-specific handlers
    game_response = handle_game_specific_command(cmd_str, data, session)
    if game_response:
        return game_response
    
    # Common handlers (shared across games)
    handlers = {
        '@dir': lambda d, s: network_handlers.handle_dir_command(d, s),
        '@tic': handle_tic,
        'addr': lambda d, s: network_handlers.handle_addr_command(d, s),
        'peek': lambda d, s: challenge_system.handle_peek(d, s),
        'skey': lambda d, s: network_handlers.handle_skey(s),
        'news': lambda d, s: network_handlers.handle_news(d, s),
        '~png': lambda d, s: ping_manager.handle_ping(d, s),
        
        'auth': lambda d, s: auth_handlers.handle_auth(d, s),
        'acct': lambda d, s: auth_handlers.handle_acct(d, s),
        'cper': lambda d, s: auth_handlers.handle_cper(d, s),
        'dper': lambda d, s: auth_handlers.handle_dper(d, s),
        'pers': lambda d, s: auth_handlers.handle_pers(d, s),
        'user': lambda d, s: auth_handlers.handle_user(d, s),
        'edit': lambda d, s: auth_handlers.handle_edit(d, s),
        
        'sele': lambda d, s: room_handlers.handle_sele(d, s),
        'room': lambda d, s: room_handlers.handle_room(d, s),
        'move': lambda d, s: room_handlers.handle_move(d, s),
        
        'chal': lambda d, s: challenge_system.handle_chal(d, s),
        'auxi': lambda d, s: challenge_system.handle_auxi(d, s),
        'mesg': lambda d, s: handle_mesg_command(d, s),  # Special handling for mesg
        'play': reply_play,
        
        'sysc': lambda d, s: challenge_system.handle_system_command(d, s),
        'onln': handle_onln,
        'snap': handle_snap,
        'rept': handle_rept,

        'gqwk': lambda d, s: handle_game_specific_command('gqwk', d, s),
        'glea': lambda d, s: handle_game_specific_command('glea', d, s),
        'ccrt': lambda d, s: handle_game_specific_command('ccrt', d, s),
        	        
        # Buddy API commands
        'RGET': lambda d, s: buddy_handlers.handle_buddy_command(d, s),
        'ROST': lambda d, s: buddy_handlers.handle_buddy_command(d, s),
        'PGET': lambda d, s: buddy_handlers.handle_buddy_command(d, s),
        'RADD': lambda d, s: buddy_handlers.handle_buddy_command(d, s),
        'RDEL': lambda d, s: buddy_handlers.handle_buddy_command(d, s),        
        'BLOC': lambda d, s: buddy_handlers.handle_buddy_command(d, s),
    }
    
    if cmd_str in handlers:
        parse_data(data, session)
        return handlers[cmd_str](data, session)
                     
    print(f"UNKNOWN COMMAND: {cmd_str}")
    return create_packet(cmd_str, '', "STATUS=1\n")
    
def threaded_client(connection, address, socket_type):
    global session_manager, ping_manager, data_server_manager, room_manager, challenge_system
    
    connection_id = f"conn_{uuid.uuid4().hex[:8]}"
    session = session_manager.create_session(connection_id)
    session.connection = connection
    
    session_manager.add_session(connection_id, session)
    thread_count = session_manager.increment_thread_count()
        
    print(f'New {socket_type} connection: {connection_id} from {address[0]}:{address[1]} (Thread: {thread_count})')
    
    try:
        connection.settimeout(500)
        
        # BUDDY SOCKET HANDLING
        if socket_type == 'Buddy':
            print(f"BUDDY: Starting buddy protocol for {connection_id}")
            while True:
                session.curr_time = time.time()
                
                if session.check_protocol_timeout():
                    print(f"BUDDY PROTOCOL: Timeout detected for {connection_id}")
                    timeout_response = create_packet('time', '', "STATUS=0\nERROR=Protocol timeout\n")
                    try:
                        connection.sendall(timeout_response)
                    except:
                        pass
                    break
                
                try: 
                    header = connection.recv(12)
                    session.NO_DATA = False
                    session.update_activity()
                except socket.timeout: 
                    session.NO_DATA = True
                    time.sleep(0.1)
                    continue
                except (socket.error, OSError) as e: 
                    print(f"BUDDY: Connection error {connection_id}: {e}")
                    break
                
                if not header: 
                    print(f"BUDDY: Connection closed by client {connection_id}")
                    break
                
                session.msgType = header[:4]
                session.msgSubType = header[4:8]
                session.msgSize = (header[10] + header[11]) - 12
                
                if header[10] == 0: 
                    session.msgSize = header[11] - 12
                if session.msgSize == 1: 
                    session.msgSize += 255 - 12
                
                data = b''
                if session.msgSize > 0:
                    try:
                        data = connection.recv(session.msgSize)
                        if not data: 
                            print(f"BUDDY: Connection closed during data receive {connection_id}")
                            break
                    except (socket.error, OSError) as e: 
                        print(f"BUDDY: Error receiving data {connection_id}: {e}")
                        break
                
                cmd_str = session.msgType.decode('latin1') if isinstance(session.msgType, bytes) else str(session.msgType)
                print(f"BUDDY RECV from {connection_id}: {cmd_str}")
                
                # Use buddy command handler for all buddy socket commands
                reply = buddy_handlers.handle_buddy_command(data, session)
                
                if reply:
                    try: 
                        connection.sendall(reply)
                    except (socket.error, OSError) as e: 
                        print(f"BUDDY: Error sending reply to {connection_id}: {e}")
                        break
                session.update_activity()
                
                time.sleep(0.01)
        
        # GAME SOCKET HANDLING
        else:
            while True:
                session.curr_time = time.time()
                
                if session.check_protocol_timeout():
                    print(f"PROTOCOL: Timeout detected for {connection_id}")
                    timeout_response = create_packet('time', '', "STATUS=0\nERROR=Protocol timeout\n")
                    try:
                        connection.sendall(timeout_response)
                    except:
                        pass
                    break
                
                if challenge_system:
                    current_state = challenge_system.ChallengeState_Get(session)
                    if hasattr(session, 'last_challenge_state') and session.last_challenge_state != current_state:
                        state_name = challenge_system.states.get(current_state, f"UNKNOWN({current_state:02x})")
                        print(f"CHALLENGE STATE: {session.connection_id} -> {state_name}")
                        session.last_challenge_state = current_state
                    
                    challenge_system.update_challenge_state(session)
                    
                try: 
                    header = connection.recv(12)
                    session.NO_DATA = False
                    session.update_activity()
                except socket.timeout: 
                    session.NO_DATA = True
                    time.sleep(0.1)
                    continue
                except (socket.error, OSError) as e: 
                    print(f"Connection error {connection_id}: {e}")
                    break
                
                if not header: 
                    print(f"Connection closed by client {connection_id}")
                    break
                
                session.msgType = header[:4]
                session.msgSize = (header[10] + header[11]) - 12
                if header[10] == 0: 
                    session.msgSize = header[11] - 12
                if session.msgSize == 1: 
                    session.msgSize += 255 - 12
                
                data = b''
                if session.msgSize > 0:
                    try:
                        data = connection.recv(session.msgSize)
                        if not data: 
                            print(f"Connection closed during data receive {connection_id}")
                            break
                        # Check for binary events
                        if handle_binary_event(data, session):
                            session.update_activity()
                            continue                            
                    except (socket.error, OSError) as e: 
                        print(f"Error receiving data {connection_id}: {e}")
                        break

                if data:
                    data_str = data.decode('latin1', errors='ignore')
                    if session.msgType != b'~png':
                        print(f"COMMAND: {session.clientNAME} sent {session.msgType}")
                        print(f"  Data: {data_str[:200]}")
                
                if session.msgType != b'~png':
                    print(f"RECV from {connection_id}: {session.msgType}")
                
                reply = build_reply(data, session)
                if reply:
                    try: 
                        connection.sendall(reply)
                    except (socket.error, OSError) as e: 
                        print(f"Error sending reply to {connection_id}: {e}")
                        break
                session.update_activity()
                
                # Handle post-command actions in the right sequence
                if session.msgType == b'auth' and session.authsent == 1 and not session.ping_initiated:
                    print(f"AUTH: Sending initial ping to {connection_id}")
                    time.sleep(0.5)
                    ping_manager.send_initial_ping(session)
                
                elif session.msgType == b'auth' and session.authsent == 1:
                    print(f"AUTH: Scheduling automatic PERS response for {connection_id}")
                    time.sleep(0.3)
                    current_persona = session.current_persona if session.current_persona else session.clientNAME
                    response = f"PERS={current_persona}\nSTATUS=1\nLAST={time.strftime('%Y.%m.%d-%H:%M:%S')}\n"
                    try:
                        connection.sendall(create_packet('pers', '', response))
                        print(f"AUTH: Sent automatic PERS confirmation for {connection_id}")
                        session.authsent = 2
                        
                    except (socket.error, OSError) as e: 
                        print(f"Error sending PERS response to {connection_id}: {e}")
                        break
                
                elif session.msgType == b'pers':
                    # Client selected persona, send WHO list
                    time.sleep(0.3)
                    try: 
                        connection.sendall(room_handlers.reply_who(session))
                    except (socket.error, OSError) as e: 
                        print(f"Error sending WHO response to {connection_id}: {e}")
                        break
                
                elif session.msgType == b'move':
                    # Client joined a room - NOW trigger multiplayer initialization
                    time.sleep(1.0)  # Wait for room system to process
                    if not session.multiplayer_initialized:
                        print(f"MOVE: {session.clientNAME} joined room, triggering multiplayer init")
                        send_multiplayer_initialization(session)
                
                elif session.msgType == b'room':
                    # Room creation/update
                    for response_func in [room_handlers.reply_pop, room_handlers.reply_usr, room_handlers.reply_who]:
                        time.sleep(0.3)
                        try: 
                            connection.sendall(response_func(session))
                        except (socket.error, OSError) as e: 
                            print(f"Error sending room response to {connection_id}: {e}")
                            break
                
                if session.msgType == b'@dir' and session.data_port > 0:
                    start_new_thread(data_server_manager.start_data_server, (session,))
                
                time.sleep(0.01)
    
    except Exception as e: 
        print(f"Client connection error {connection_id}: {e}")
    finally:
        if session.ping_timer: 
            session.ping_timer.cancel()
            print(f"Cancelled pending ping timer for {connection_id}")
        
        username = getattr(session, 'clientNAME', 'Unknown')
        persona = getattr(session, 'current_persona', 'Unknown')
        room = getattr(session, 'current_room', 'Unknown')
        room_id = getattr(session, 'current_room_id', 0)
        
        # Update buddy status on disconnect
        if username and username != 'Unknown':
            buddy_handlers.update_buddy_status(username, False)
        
        room_manager.update_user_presence(connection_id, username, persona, room, room_id, False)
        
        try: 
            connection.close()
        except: 
            pass
        
        session_manager.remove_session(connection_id)
        session_manager.decrement_thread_count()
        
        print(f"Client disconnected: {connection_id} ({username})")
        
        if challenge_system:
            challenge_system.ChallengeCallback_Cleanup(session)

def accept_connections(sock, socket_type):
    while True:
        try:
            client, address = sock.accept()
            print(f"ACCEPT: New {socket_type} connection from {address[0]}:{address[1]}")
            start_new_thread(threaded_client, (client, address, socket_type))
        except Exception as e: 
            print(f"Accept error on {socket_type}: {e}")
            	
def handle_binary_event(data, session):
    """Handle binary event packets (like 0xC03C, 0xC03D)"""
    if len(data) < 8:
        return False
    
    # Check if this looks like a binary event
    # Binary events start with event code in little-endian
    try:
        event_code = struct.unpack('<I', data[:4])[0]
        data_size = struct.unpack('<I', data[4:8])[0]
        
        if event_code in [0xC03C, 0xC03D]:
            print(f"BINARY EVENT: Received event 0x{event_code:08X} from client")
            # Client is acknowledging the event
            return True
    except:
        pass
    
    return False
def initialize_systems(game_mode=None):
    global challenge_system, auth_handlers, session_manager, network_handlers
    global ping_manager, data_server_manager, room_manager, room_handlers
    global message_handlers, ranking_handlers, buddy_handlers, current_game_mode
    global state_trigger
    
    current_game_mode = game_mode
    
    print(f"INIT: Starting system initialization for {game_mode if game_mode else 'default'}...")
    
    room_manager = RoomManager(create_packet, SERVER_IP)
    print("INIT: Room manager initialized")
    
    state_trigger = StateTrigger(create_packet, SERVER_IP, PORTS, room_manager)
    print("STATE: State trigger system initialized")    
    
    session_manager = SessionManager(create_packet, room_manager.update_user_presence, 
                                     lambda conn_id: ClientSession(conn_id, game_mode))
    print("INIT: Session manager initialized")
    
    def get_client_sessions():
        return session_manager.client_sessions
    
    room_handlers = RoomHandlers(
        create_packet, 
        room_manager, 
        room_manager.update_user_presence, 
        get_client_sessions
    )
    print("INIT: Room handlers initialized")
    
    network_handlers = NetworkHandlers(create_packet, get_next_data_port, SERVER_IP, PORTS)
    ping_manager = PingManager(create_packet)
    data_server_manager = DataServerManager(SERVER_IP)
    print("INIT: Network components initialized")
    
    auth_handlers = AuthenticationHandlers(create_packet)
    print("INIT: Authentication handlers initialized")
    
    buddy_handlers = BuddyHandlers(create_packet, room_manager.active_users)
    print("BUDDY: Buddy system initialized")
    
    # Initialize game-specific modules
    if game_mode == 'nascar' and HAS_NASCAR:
        print("INIT: Loading NASCAR Thunder 2004 module")
        GAME_MODES['nascar']['module'] = NascarHandlers
        GAME_MODES['nascar']['handlers'] = NascarHandlers(create_packet, SERVER_IP)
    elif game_mode == 'nbav3' and HAS_NBAV3:
        print("INIT: Loading NBA Street v3 module")
        GAME_MODES['nbav3']['module'] = NBAv3Handlers
        GAME_MODES['nbav3']['handlers'] = NBAv3Handlers(create_packet, SERVER_IP)
    
    # FIXED: Pass room_manager to ChallengeSystem
    challenge_system = ChallengeSystem(create_packet, room_manager.active_users, 
                                       session_manager.client_sessions, 
                                       session_manager, room_manager)
    print("CHALLENGE: Challenge system initialized")
    
    message_handlers = MessageHandlers(create_packet, room_manager.active_users, challenge_system)
    print("MESSAGE: Message system initialized")
    
    print(f"INIT: All systems initialized successfully for {game_mode}")
    
def bind_server():
    global current_game_mode
    
    game_mode = None
    game_port = None
    
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "-nc04": 
            game_mode = 'nascar'
            game_port = PORT_NC04_PS2
            print(f"Now running in {GAME_MODES['nascar']['name']} Mode\n")
        elif arg == "-nbav3": 
            game_mode = 'nbav3'
            game_port = PORT_NBAV3_PS2
            print(f"Now running in {GAME_MODES['nbav3']['name']} Mode\n")
        elif arg == "-nfsu":
            game_mode = 'nfsu'
            game_port = PORT_NFSU_PS2
            print(f"Now running in {GAME_MODES['nfsu']['name']} Mode\n")
        elif arg == "-nfsu2":
            game_mode = 'nfsu2'
            game_port = PORT_NFSU2_PS2
            print(f"Now running in {GAME_MODES['nfsu2']['name']} Mode\n")
        elif arg == "-bo3u":
            game_mode = 'bo3u'
            game_port = PORT_BO3U_PS2
            print(f"Now running in {GAME_MODES['bo3u']['name']} Mode\n")
        elif arg == "-bo3r":
            game_mode = 'bo3r'
            game_port = PORT_BO3R_PS2
            print(f"Now running in {GAME_MODES['bo3r']['name']} Mode\n")
        elif arg == "-nfl05":
            game_mode = 'nfl05'
            game_port = PORT_NFL05_PS2
            print(f"Now running in {GAME_MODES['nfl05']['name']} Mode\n")
        elif arg == "-bop_ps3":
            game_mode = 'bop_ps3'
            game_port = PORT_BOP_PS3
            print(f"Now running in {GAME_MODES['bop_ps3']['name']} Mode\n")
        elif arg == "-bop_pc":
            game_mode = 'bop_pc'
            game_port = PORT_BOP_PC
            print(f"Now running in {GAME_MODES['bop_pc']['name']} Mode\n")
        elif arg == "-ssx3":
            game_mode = 'ssx3'
            game_port = PORT_SSX3_PS2
            print(f"Now running in {GAME_MODES['ssx3']['name']} Mode\n")
        elif arg == "-p" and i + 1 < len(sys.argv): 
            game_port = int(sys.argv[i + 1])
            print("Now running in Custom Game Mode\n")
        elif arg == "-i" and i + 1 < len(sys.argv): 
            global SERVER_IP
            SERVER_IP = sys.argv[i + 1]
            
     # ADD: Check if SERVER_IP was provided
    if not SERVER_IP:
        print("ERROR: Server IP must be specified with -i argument!")
        usage()
        return
           
    if not game_port: 
        print("No game mode specified!")
        usage()
        return
    
    if game_mode:
        current_game_mode = game_mode
    
    for name, sock in sockets.items():
        if name == 'game':
            port = game_port
        elif name in PORTS:
            port = PORTS[name]
        else:
            # Default to listener port for non-game sockets
            port = PORTS['listener']
            
        sock.bind((SERVER_IP, port))
        print(f"Socket {name}: {SERVER_IP}:{port}")
        sock.listen(8)
    
    print("Bind complete.\n")
    return game_mode

def usage():
    print("Usage:")
    print("-nc04    Run in NASCAR Thunder 04 Mode (PS2)")
    print("-nbav3   Run in NBA Street v3 Mode (PS2)")
    print("-nfsu    Run in Need for Speed Underground Mode (PS2)")
    print("-nfsu2   Run in Need for Speed Underground 2 Mode (PS2)")
    print("-bo3u    Run in Burnout 3: Takedown (Update) Mode (PS2)")
    print("-bo3r    Run in Burnout 3: Takedown (Release) Mode (PS2)")
    print("-nfl05   Run in Madden NFL 2005 Mode (PS2)")
    print("-bop_ps3 Run in Burnout Paradise (PS3) Mode")
    print("-bop_pc  Run in Burnout Paradise (PC) Mode")
    print("-ssx3    Run in SSX 3 Mode (PS2)")
    print("-p 123   Run in Custom Game Mode on this TCP Port")
    print("-i ip    Run on this IPv4 Address (REQUIRED)")
    print("\nExample: python server_r10.py -nc04 -i 192.168.1.100")
    quit()

if __name__ == "__main__":
    print(f"VTSTech-SRVEmu v{BUILD}")
    print(f"FEATURES: Modular Game Support | Multi-Game Protocol")
    print(f"GitHub: https://github.com/VTSTech/VTSTech-SRVEmu\n")
    
    # Bind first to detect game mode
    game_mode = bind_server()
    
    # Initialize systems with detected game mode
    initialize_systems(game_mode)
    
    print('Waiting for connections...')
    
    for name, sock in sockets.items(): 
        start_new_thread(accept_connections, (sock, name.capitalize()))
    
    try:
        while True: 
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        for sock in sockets.values(): 
            sock.close()
        print("Server stopped.")