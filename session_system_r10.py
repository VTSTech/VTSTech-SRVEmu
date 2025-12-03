# session_system_r08.py - CLEANED & OPTIMIZED
import time
import random
import threading
import socket
import struct
from _thread import *

class SessionManager:
    def __init__(self, create_packet_func, update_user_presence_func, client_session_class):
        self.create_packet = create_packet_func
        self.update_user_presence = update_user_presence_func
        self.ClientSession = client_session_class
        self.thread_count = 0
        self.client_sessions = {}
        self.thread_lock = threading.Lock()
        self.session_lock = threading.Lock()
    
    def create_session(self, connection_id):
        # Pass through to client session class constructor
        # The constructor will handle game_mode if needed
        return self.ClientSession(connection_id)
    
    def add_session(self, connection_id, session):
        with self.session_lock:
            self.client_sessions[connection_id] = session
    
    def remove_session(self, connection_id):
        with self.session_lock:
            if connection_id in self.client_sessions:
                del self.client_sessions[connection_id]
    
    def get_session(self, connection_id):
        return self.client_sessions.get(connection_id)
    
    def increment_thread_count(self):
        with self.thread_lock:
            self.thread_count += 1
            return self.thread_count
    
    def decrement_thread_count(self):
        with self.thread_lock:
            self.thread_count -= 1

class NetworkHandlers:
    def __init__(self, create_packet_func, get_next_data_port_func, server_ip, ports):
        self.create_packet = create_packet_func
        self.get_next_data_port = get_next_data_port_func
        self.server_ip = server_ip
        self.ports = ports
    
    def handle_dir_command(self, data, session):
        session.clientSESS = f"{random.randint(1000, 9999)}{random.randint(1000, 9999)}{random.randint(10, 99)}"
        session.data_port = self.get_next_data_port()
        
        dir_fields = [
            f"ADDR={self.server_ip}", f"PORT={self.ports['listener']}",
            f"SESS={session.clientSESS}", f"MASK={random.randint(1000, 9999)}f3f70ecb1757cd7001b9a7a{random.randint(1000, 9999)}"
        ]
        
        dir_response = '\n'.join(dir_fields) + '\n'
        session.client_state = 0x72646972
        print(f"DIR: Assigned data port {session.data_port}, state=DIRECTORY")
        
        return self.create_packet('@dir', '', dir_response)
    
    def handle_addr_command(self, data, session):
        print(f"ADDR: Connection established from {session.connection_id}")
        session.client_state = 0x636f6e6e
        print(f"PROTOCOL: {session.connection_id} -> STATE_CONNECTED")
        return self.create_packet('addr', '', "STATUS=1\n")
    
    def handle_skey(self, session):
        session.SKEYSENT = 1
        session.client_state = 0x736b6579
        session.client_flags |= 0x1
        session.public_key_sent = 1
        print(f"PROTOCOL: {session.connection_id} -> STATE_KEY_EXCHANGE, flags={session.client_flags:08x}")
        return self.create_packet('skey', '', "SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7\n")
            
    def handle_news(self, data, session):
		    # Parse NAME field
		    name_value = 0
		    if data:
		        try:
		            data_str = data.decode('latin1', errors='ignore')
		            for line in data_str.split('\n'):
		                if line.startswith('NAME='):
		                    try:
		                        name_value = int(line[5:].strip())
		                    except:
		                        name_value = 0
		                    break
		        except:
		            pass
		    
		    print(f"NEWS: Client requested NAME={name_value}")
		    
		    # Build identifier: "new0", "new1", etc.
		    identifier = f"new{name_value}"
		    
		    # Get game-specific news response
		    if hasattr(self, 'game_handlers') and self.game_handlers:
		        response_lines = self.game_handlers.get_news_response(name_value)
		    else:
		        # Default response
		        if name_value == 0:
		            response_lines = [
		                f"BUDDY_URL={self.server_ip}", 
		                f"BUDDY_PORT={self.ports['buddy']}",		             
		                "STATUS=1"
		            ]
		        elif name_value == 1:
		            response_lines = [
		                "NEWS_TEXT=VTSTech Server Online",
		                "NEWS_TEXT=Multiplayer System Active", 
		                "NEWS_TEXT=Challenge System Ready",
		                "NEWS_TEXT=Room Creation Available",
		                "COUNT=4",
		                "STATUS=1"
		            ]
		        else:
		            response_lines = [
		                f"STATUS=0",
		                f"ERROR=Unknown news type {name_value}"
		            ]
		    
		    # Combine identifier and response
		    full_response = identifier + '\n' + '\n'.join(response_lines) + '\n'
		    
		    # Use appropriate subcommand
		    subcmd = '\x00\x00\x00\x01' if name_value == 1 else ''
		    
		    print(f"NEWS: Sending response with identifier '{identifier}'")
		    
		    return self.create_packet('news', subcmd, full_response)

class PingManager:
    def __init__(self, create_packet_func):
        self.create_packet = create_packet_func
    
    def send_initial_ping(self, session):
        if not session.connection: 
            return
        
        try: 
            session.connection.getpeername()
        except: 
            return
        
        session.ping_initiated = True
        session.ping_cnt += 1
        
        sess_value = getattr(session, 'clientSESS', 'UNSET')
        response = f"REF={time.strftime('%Y.%m.%d-%H:%M:%S')}\nTIME=2\nSESS={sess_value}\nNAME={session.clientNAME}\nSTATUS=0\n"
        session.connection.sendall(self.create_packet('~png', '', response))
        print(f"PING: Sent initial ping (#{session.ping_cnt}) with SESS={sess_value}")
    
    def handle_ping(self, data, session):
        if not data: 
            return None
        
        client_time = getattr(session, 'pingTIME', '3')
        try: 
            delay_seconds = int(client_time)
        except: 
            delay_seconds = 3
            
        def send_delayed_response():
            time.sleep(delay_seconds)
            if session.connection:
                try:
                    session.connection.getpeername()
                    session.ping_cnt += 1
                    response = f"REF={time.strftime('%Y.%m.%d-%H:%M:%S')}\nTIME={client_time}\nNAME={session.clientNAME}\nSESS={getattr(session, 'clientSESS', '0')}\nSTATUS=1\n"
                    session.connection.sendall(self.create_packet('~png', '', response))
                except:
                    print("PING: Connection closed before response")
        
        threading.Thread(target=send_delayed_response, daemon=True).start()
        return None

class DataServerManager:
    def __init__(self, server_ip):
        self.server_ip = server_ip
    
    def start_data_server(self, session):
        data_socket = socket.socket()
        data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            data_socket.bind((self.server_ip, session.data_port))
            data_socket.listen(1)
            data_socket.settimeout(10)
            print(f"DATA: Listening on port {session.data_port} for {session.connection_id}")
            
            try:
                data_client, data_address = data_socket.accept()
                print(f"DATA: Connection from {data_address} for {session.connection_id}")
                start_new_thread(self.handle_data_connection, (data_client, session))
            except socket.timeout:
                print(f"DATA: No connection on port {session.data_port} (normal)")
            except Exception as e:
                print(f"DATA: Accept error: {e}")
                
        except Exception as e: 
            print(f"DATA: Setup error on port {session.data_port}: {e}")
        finally: 
            data_socket.close()
    
    def handle_data_connection(self, client_socket, session):
        print(f"DATA: Active for {session.clientNAME}")
        try:
            client_socket.settimeout(30)
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                print(f"DATA: Received {len(data)} bytes from {session.clientNAME}")
        except socket.timeout:
            print(f"DATA: Timeout for {session.clientNAME}")
        except Exception as e: 
            print(f"DATA: Error for {session.clientNAME}: {e}")
        finally: 
            client_socket.close()