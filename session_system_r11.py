# session_system_r11.py - OPTIMIZED
import time, random, threading, socket, struct
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

LKEY_CACHE = {} # Index by SESS string
GLOBAL_LKEY_MAP = {}

class NetworkHandlers:
    def __init__(self, create_packet_func, get_next_data_port_func, server_ip, ports):
        self.create_packet = create_packet_func
        self.get_next_data_port = get_next_data_port_func
        self.server_ip = server_ip
        self.ports = ports
    
    def handle_dir_command(self, data, session):
		        # Generate a unique 10-digit SESS and a 32-char LKEY
		        sess_id = str(random.randint(1000000000, 9999999999))
		        lkey = f"3fcf27540c92935b0a66fd3b0000{random.randint(100, 999)}c"
		        
		        # Store the relationship in the global map
		        from session_system_r11 import GLOBAL_LKEY_MAP
		        GLOBAL_LKEY_MAP[sess_id] = lkey
		        
		        session.clientSESS = sess_id
		        session.clientLKEY = lkey
		        
		        dir_fields = [
		            f"ADDR={self.server_ip}", 
		            f"PORT={self.ports['listener']}",
		            f"LKEY={lkey}",
		            f"SESS={sess_id}", 
		            "MASK=4294967295"
		        ]
		        
		        dir_response = '\n'.join(dir_fields) + '\n'
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
        return self.create_packet('skey', '', "SKEY=0\n")
        
    def extract_int_param(self, data, key):
		        """Helper to find an integer value in the EA param string."""
		        # Convert bytes to string if necessary
		        d = data.decode('latin1') if isinstance(data, bytes) else str(data)
		        for line in d.split('\n'):
		            if line.startswith(f"{key}="):
		                try:
		                    # Extracts the '0' from 'NAME=0'
		                    return int(line.split('=')[1].strip())
		                except (IndexError, ValueError):
		                    return 0
		        return 0
            
    def handle_news(self, data, session):
		        name_val = self.extract_int_param(data, "NAME")
		        
		        # Ghidra logic: sub_cmd = 0x6e657730 ('new0') + name_val
		        sub_hex = 0x6e657730 + name_val
		        sub_str = struct.pack(">I", sub_hex).decode('latin1') 

		        server_ip = "192.168.2.123" # Double check this is your actual IP!
		        
		        # The "Buddy Trigger" Payload
		        out = (
		            f"BUDDY_URL={server_ip}\n"
		            f"BUDDY_PORT=10899\n"
		            f"BUDDY_SERVER={server_ip}\n"
		            "TOS_TEXT=VTSTech_TOS\n"
		            "NEWS_TEXT=VTSTech_NEWS\n"
		            "USE_ETOKEN=0\n"
		            "S=0\nSTATUS=0\n"
		        )
		        
		        return self.create_packet('news', sub_str, out)

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
        response = f"REF={time.strftime('%Y-%m-%d %H:%M:%S')}\nTIME=2\nSESS={sess_value}\nNAME={session.clientNAME}\nSTATUS=0\n"
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
                    response = f"REF={time.strftime('%Y-%m-%d %H:%M:%S')}\nTIME={client_time}\nNAME={session.clientNAME}\nSESS={getattr(session, 'clientSESS', '0')}\nSTATUS=1\n"
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