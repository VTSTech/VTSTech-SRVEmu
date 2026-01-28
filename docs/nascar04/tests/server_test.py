#!/usr/bin/env python3
"""
NASCAR Thunder 2004 Server - Phase 1 Challenge Testing
Complete drop-in replacement with enhanced challenge system
"""

import socket
import threading
import struct
import time
import logging
import random
from typing import Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nascar_server.log'),
        logging.StreamHandler()
    ]
)

class ClientSession:
    """Represents a connected client session"""
    def __init__(self, conn, addr, conn_id):
        self.connection = conn
        self.address = addr
        self.conn_id = conn_id
        self.clientNAME = f"Player{random.randint(1000, 9999)}"
        self.room_id = 1
        self.room_name = "East"
        self.game_state = 0x4b1  # MULTIPLAYER_LOBBY
        
        # Challenge system attributes
        self.challenge_state = 0  # 0=INACTIVE, 1=PENDING, etc.
        self.challenge_token = None
        self.challenger = None
        self.challenge_seed = None

class ChallengeSystem:
    """Enhanced challenge system with Phase 1 testing"""
    
    def __init__(self, server):
        self.server = server
        self.logger = logging.getLogger('challenge_system')
        self.test_results = []
        
    def create_packet(self, cmd: str, subcmd: str, payload: str) -> bytes:
        """Create binary packet with proper NASCAR Thunder 2004 format"""
        if isinstance(payload, str): 
            payload = payload.encode('ascii')
        payload += b'\0'
        size = len(payload)
        
        return struct.pack(
            ">4s4sL%ds" % size,
            cmd.encode('ascii').ljust(4, b'\0'),
            subcmd.encode('ascii').ljust(4, b'\0'),
            size + 12,
            payload
        )
    
    def handle_auxi_command(self, session: ClientSession, data: bytes):
        """Process AUXI challenge initiation from client"""
        try:
            # Extract token from AUXI data
            token = self._extract_token_from_data(data)
            
            self.logger.info(f"CHALLENGE AUXI: {session.clientNAME} token='{token}' state={session.challenge_state}")
            
            # Store challenge data
            session.challenge_token = token
            session.challenge_state = 0  # INACTIVE
            
            # Find target user for challenge
            target_session = self._find_challenge_target(session)
            if target_session:
                self._initiate_challenge(session, target_session, token)
            else:
                self.logger.warning("CHALLENGE: No target user found")
                
        except Exception as e:
            self.logger.error(f"CHALLENGE AUXI ERROR: {e}")
    
    def _extract_token_from_data(self, data: bytes) -> str:
        """Extract token from AUXI command data"""
        if b'TEXT=' in data:
            text_start = data.find(b'TEXT=') + 5
            text_end = data.find(b'\0', text_start)
            if text_end == -1:
                text_end = len(data)
            return data[text_start:text_end].decode('ascii', errors='ignore')
        return "unknown_token"
    
    def _find_challenge_target(self, session: ClientSession) -> Optional[ClientSession]:
        """Find a user to challenge"""
        for conn_id, user_session in self.server.sessions.items():
            if (conn_id != session.conn_id and 
                hasattr(user_session, 'clientNAME') and 
                user_session.clientNAME != session.clientNAME and
                self._is_client_connected(user_session)):
                return user_session
        return None
    
    def _initiate_challenge(self, challenger: ClientSession, target: ClientSession, token: str):
        """Main challenge initiation function"""
        self.logger.info(f"CHALLENGE INIT: {challenger.clientNAME} starting challenge with token '{token}'")
        self.logger.info(f"CHALLENGE: Targeting {target.clientNAME}")
        
        # Log test conditions
        self._log_test_conditions(challenger, target)
        
        # Phase 1: Test different MESG formats
        self._test_mesg_formats_phase1(challenger, target)
        
        # Update challenge states
        challenger.challenge_state = 1  # PENDING
        target.challenge_state = 1  # PENDING
        target.challenger = challenger.clientNAME
        
        self.logger.info(f"CHALLENGE STATE: {challenger.conn_id} -> PENDING")
        self.logger.info(f"CHALLENGE STATE: {target.conn_id} -> PENDING")
    
    def _test_mesg_formats_phase1(self, challenger: ClientSession, target: ClientSession):
        """Phase 1: Test different MESG field combinations"""
        self.logger.info("=== PHASE 1 TESTING: MESG FORMATS ===")
        
        test_cases = [
            # Group 1: Basic TEXT formats
            {"name": "Basic CHALLENGE", "payload": "TEXT=CHALLENGE"},
            {"name": "Named CHALLENGE", "payload": f"TEXT=CHALLENGE:{challenger.clientNAME}"},
            
            # Group 2: With N= field
            {"name": "With N field", "payload": f"N={target.clientNAME}\nTEXT=CHALLENGE"},
            {"name": "Named with N field", "payload": f"N={target.clientNAME}\nTEXT=CHALLENGE:{challenger.clientNAME}"},
            
            # Group 3: Basic flag variations
            {"name": "Flag 0", "payload": "TEXT=CHALLENGE\nF=0"},
            {"name": "Flag 1", "payload": "TEXT=CHALLENGE\nF=1"},
            
            # Group 4: Binary analysis flag variations
            {"name": "Flag 0x10000", "payload": "TEXT=CHALLENGE\nF=0x10000"},
            {"name": "Flag 0x20000", "payload": "TEXT=CHALLENGE\nF=0x20000"},
            {"name": "Flag 0x40000", "payload": "TEXT=CHALLENGE\nF=0x40000"},
            
            # Group 5: Combined N= and flags
            {"name": "N+Flag 0x10000", "payload": f"N={target.clientNAME}\nTEXT=CHALLENGE\nF=0x10000"},
            {"name": "N+Flag 0x20000", "payload": f"N={target.clientNAME}\nTEXT=CHALLENGE\nF=0x20000"},
            
            # Group 6: Field order variations
            {"name": "Order: N-TEXT-F", "payload": f"N={target.clientNAME}\nTEXT=CHALLENGE\nF=0x10000"},
            {"name": "Order: TEXT-N-F", "payload": f"TEXT=CHALLENGE\nN={target.clientNAME}\nF=0x10000"},
            {"name": "Order: F-TEXT-N", "payload": f"F=0x10000\nTEXT=CHALLENGE\nN={target.clientNAME}"},
        ]
        
        for i, test_case in enumerate(test_cases):
            if not self._is_client_connected(target):
                self.logger.error("TARGET DISCONNECTED - stopping tests")
                break
                
            try:
                self.logger.info(f"TEST {i+1:2d}: {test_case['name']}")
                self.logger.info(f"       Payload: {test_case['payload']}")
                
                packet = self.create_packet('mesg', '', test_case['payload'])
                target.connection.sendall(packet)
                
                # Log packet details
                packet_hex = packet.hex()[:80] + "..." if len(packet.hex()) > 80 else packet.hex()
                self.logger.info(f"       Bytes: {packet_hex}")
                
                # Record test result
                self.test_results.append({
                    'test_number': i + 1,
                    'name': test_case['name'],
                    'payload': test_case['payload'],
                    'timestamp': time.time(),
                    'target_connected': self._is_client_connected(target)
                })
                
                # Wait for client processing
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"       ERROR: {e}")
                self.test_results.append({
                    'test_number': i + 1,
                    'name': test_case['name'],
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        self.logger.info("=== PHASE 1 TESTING COMPLETE ===")
        self._analyze_test_results()
    
    def _log_test_conditions(self, challenger: ClientSession, target: ClientSession):
        """Log detailed conditions for challenge testing"""
        conditions = {
            'challenger': challenger.clientNAME,
            'target': target.clientNAME,
            'challenger_state': hex(challenger.game_state),
            'target_state': hex(target.game_state),
            'same_room': challenger.room_id == target.room_id,
            'challenger_connected': self._is_client_connected(challenger),
            'target_connected': self._is_client_connected(target),
        }
        
        self.logger.info("CHALLENGE CONDITIONS:")
        for key, value in conditions.items():
            self.logger.info(f"  {key}: {value}")
    
    def _analyze_test_results(self):
        """Analyze Phase 1 test results"""
        total_tests = len(self.test_results)
        successful_deliveries = len([r for r in self.test_results if r.get('target_connected', False)])
        errors = len([r for r in self.test_results if 'error' in r])
        
        self.logger.info("=== PHASE 1 ANALYSIS ===")
        self.logger.info(f"Total tests: {total_tests}")
        self.logger.info(f"Successful deliveries: {successful_deliveries}")
        self.logger.info(f"Errors: {errors}")
        self.logger.info(f"Success rate: {successful_deliveries/total_tests*100:.1f}%")
    
    def handle_mesg_command(self, session: ClientSession, data: bytes):
        """Handle MESG commands (both challenges and responses)"""
        try:
            text_content = self._extract_text_from_data(data)
            
            # Check if this is a challenge response
            if text_content.upper() in ['ACPT', 'DECL', 'BLOC']:
                self._handle_challenge_response(session, text_content.upper())
            else:
                self.logger.info(f"REGULAR MESG: {session.clientNAME} -> {text_content}")
                
        except Exception as e:
            self.logger.error(f"MESG HANDLING ERROR: {e}")
    
    def _extract_text_from_data(self, data: bytes) -> str:
        """Extract TEXT content from command data"""
        if b'TEXT=' in data:
            text_start = data.find(b'TEXT=') + 5
            text_end = data.find(b'\0', text_start)
            if text_end == -1:
                text_end = len(data)
            return data[text_start:text_end].decode('ascii', errors='ignore')
        return ""
    
    def _handle_challenge_response(self, session: ClientSession, response: str):
        """Process challenge responses (ACPT/DECL/BLOC)"""
        self.logger.info(f"CHALLENGE RESPONSE: {session.clientNAME} -> {response}")
        
        # Update challenge state based on response
        state_map = {'ACPT': 4, 'DECL': 2, 'BLOC': 3}
        session.challenge_state = state_map.get(response, 0)
        
        self.logger.info(f"CHALLENGE STATE: {session.conn_id} -> {session.challenge_state}")
        
        # Notify challenger of response
        if hasattr(session, 'challenger') and session.challenger:
            self._notify_challenger_of_response(session, response)
    
    def _notify_challenger_of_response(self, session: ClientSession, response: str):
        """Notify the original challenger of the response"""
        challenger_session = self._find_session_by_username(session.challenger)
        if challenger_session and self._is_client_connected(challenger_session):
            response_msg = f"{session.clientNAME} {response}'d your challenge"
            packet = self.create_packet('mesg', '', f"TEXT={response_msg}")
            challenger_session.connection.sendall(packet)
            self.logger.info(f"CHALLENGE NOTIFY: Sent response to {session.challenger}")
    
    def _find_session_by_username(self, username: str) -> Optional[ClientSession]:
        """Find session by username"""
        for session in self.server.sessions.values():
            if hasattr(session, 'clientNAME') and session.clientNAME == username:
                return session
        return None
    
    def _is_client_connected(self, session: ClientSession) -> bool:
        """Check if client connection is still active"""
        try:
            if hasattr(session, 'connection'):
                fileno = session.connection.fileno()
                return fileno != -1
        except:
            pass
        return False

class NASCARServer:
    """Main NASCAR Thunder 2004 server with enhanced challenge system"""
    
    def __init__(self, host='192.168.2.123', port=10600):
        self.host = host
        self.port = port
        self.socket = None
        self.sessions: Dict[str, ClientSession] = {}
        self.running = False
        self.logger = logging.getLogger('nascar_server')
        
        # Initialize challenge system
        self.challenge_system = ChallengeSystem(self)
        
        self.logger.info("NASCAR Thunder 2004 Server v9.0 (Phase 1 Challenge Testing) Initialized")
    
    def start(self):
        """Start the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            self.logger.info(f"Server listening on {self.host}:{self.port}")
            
            while self.running:
                conn, addr = self.socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client_connection,
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
                
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.socket:
            self.socket.close()
        self.logger.info("Server stopped")
    
    def handle_client_connection(self, conn, addr):
        """Handle individual client connection"""
        conn_id = f"conn_{id(conn):x}"
        session = ClientSession(conn, addr, conn_id)
        self.sessions[conn_id] = session
        
        self.logger.info(f"CLIENT CONNECTED: {conn_id} from {addr}")
        
        try:
            # Send initial welcome/authentication
            self.send_welcome_message(session)
            
            while self.running and self.challenge_system._is_client_connected(session):
                data = conn.recv(4096)
                if not data:
                    break
                    
                self.handle_client_data(session, data)
                
        except Exception as e:
            self.logger.error(f"Client handling error {conn_id}: {e}")
        finally:
            self.handle_client_disconnect(session)
    
    def handle_client_data(self, session: ClientSession, data: bytes):
        """Handle incoming client data"""
        try:
            # Parse command from data
            command = self.parse_command(data)
            
            if command:
                self.logger.info(f"RECV from {session.conn_id}: b'{command}'")
                self.handle_client_command(session, command, data)
            else:
                self.logger.debug(f"UNKNOWN DATA from {session.conn_id}: {data.hex()[:100]}...")
                
        except Exception as e:
            self.logger.error(f"Data handling error {session.conn_id}: {e}")
    
    def parse_command(self, data: bytes) -> str:
        """Parse command from binary data"""
        try:
            if len(data) >= 4:
                command = data[:4].decode('ascii', errors='ignore').strip('\0')
                return command
        except:
            pass
        return ""
    
    def handle_client_command(self, session: ClientSession, command: str, data: bytes):
        """Handle specific client commands"""
        try:
            if command == 'auxi':
                self.challenge_system.handle_auxi_command(session, data)
                
            elif command == 'mesg':
                self.challenge_system.handle_mesg_command(session, data)
                
            elif command == 'auth':
                self.handle_auth_command(session, data)
                
            elif command == 'sele':
                self.handle_sele_command(session)
                
            elif command == 'room':
                self.handle_room_command(session, data)
                
            elif command == 'move':
                self.handle_move_command(session, data)
                
            else:
                self.logger.info(f"UNHANDLED COMMAND: {command} from {session.clientNAME}")
                
        except Exception as e:
            self.logger.error(f"Command handling error {session.conn_id}: {e}")
    
    def send_welcome_message(self, session: ClientSession):
        """Send welcome message to new client"""
        welcome_msg = "Welcome to NASCAR Thunder 2004 Server"
        packet = self.challenge_system.create_packet('mesg', '', f"TEXT={welcome_msg}")
        session.connection.sendall(packet)
    
    def handle_auth_command(self, session: ClientSession, data: bytes):
        """Handle authentication command"""
        self.logger.info(f"AUTH: {session.conn_id} authenticating")
        # Send auth success response
        response = "STATUS=1"
        packet = self.challenge_system.create_packet('auth', '', response)
        session.connection.sendall(packet)
    
    def handle_sele_command(self, session: ClientSession):
        """Handle room selection command"""
        self.logger.info(f"SELE: {session.conn_id} requesting room data")
        # Send basic room data
        room_data = "ROOMS=1\nUSERS=1"
        packet = self.challenge_system.create_packet('sele', '', room_data)
        session.connection.sendall(packet)
    
    def handle_room_command(self, session: ClientSession, data: bytes):
        """Handle room creation/joining"""
        self.logger.info(f"ROOM: {session.clientNAME} room command")
        response = "STATUS=1"
        packet = self.challenge_system.create_packet('room', '', response)
        session.connection.sendall(packet)
    
    def handle_move_command(self, session: ClientSession, data: bytes):
        """Handle room movement"""
        self.logger.info(f"MOVE: {session.clientNAME} moving rooms")
        response = "STATUS=1"
        packet = self.challenge_system.create_packet('move', '', response)
        session.connection.sendall(packet)
    
    def handle_client_disconnect(self, session: ClientSession):
        """Handle client disconnection"""
        if session.conn_id in self.sessions:
            del self.sessions[session.conn_id]
            self.logger.info(f"CLIENT DISCONNECTED: {session.conn_id} ({session.clientNAME})")

def main():
    """Main entry point"""
    server = NASCARServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.logger.info("Server shutdown requested")
    finally:
        server.stop()

if __name__ == "__main__":
    main()