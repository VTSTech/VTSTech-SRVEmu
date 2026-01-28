import socket
import time
import random
import struct
import threading

class MultiClientTester:
    def __init__(self, server_ip='127.0.0.1', server_port=10600, num_clients=5):
        self.server_ip = server_ip
        self.server_port = server_port
        self.num_clients = num_clients
        self.clients = []
        self.results = []
        self.test_duration = 30
        
    def run_concurrent_test(self):
        """Test multiple clients connecting simultaneously"""
        print(f"=== Starting Multi-Client Test ({self.num_clients} clients) ===")
        
        threads = []
        start_barrier = threading.Barrier(self.num_clients + 1)  # +1 for main thread
        
        # Create and start all clients
        for i in range(self.num_clients):
            client = ConcurrentTestClient(
                self.server_ip, 
                self.server_port, 
                client_id=i,
                start_barrier=start_barrier
            )
            self.clients.append(client)
            
            thread = threading.Thread(target=client.run_test)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all clients to be ready
        print("Waiting for all clients to initialize...")
        start_barrier.wait()
        print("All clients ready - starting concurrent operations!")
        
        # Let clients run for test duration
        time.sleep(self.test_duration)
        
        # Stop all clients
        for client in self.clients:
            client.stop()
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=5)
        
        # Report results
        self._report_results()
    
    def _report_results(self):
        """Report test results"""
        successful = sum(1 for client in self.clients if client.successful)
        failed = self.num_clients - successful
        
        print(f"\n=== Multi-Client Test Results ===")
        print(f"Total clients: {self.num_clients}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Test duration: {self.test_duration}s")
        
        for client in self.clients:
            status = "SUCCESS" if client.successful else "FAILED"
            print(f"Client {client.client_id}: {status} | Pings: {client.ping_count} | Errors: {len(client.errors)}")

class ConcurrentTestClient:
    def __init__(self, server_ip, server_port, client_id, start_barrier):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_id = client_id
        self.start_barrier = start_barrier
        self.username = f"STRESS_{client_id:03d}"
        self.sock = None
        self.running = False
        self.successful = False
        self.ping_count = 0
        self.errors = []
        self.session_id = None
        
    def run_test(self):
        """Run the client test"""
        try:
            if not self._connect():
                return
                
            self._handshake()
            self._authenticate()
            
            # Signal ready and wait for all clients
            self.start_barrier.wait()
            
            self.running = True
            self._concurrent_operations()
            self.successful = True
            
        except Exception as e:
            self.errors.append(f"Main loop: {e}")
        finally:
            self._disconnect()
    
    def _connect(self):
        """Connect to server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.server_ip, self.server_port))
            print(f"[Client {self.client_id}] Connected successfully")
            return True
        except Exception as e:
            self.errors.append(f"Connection: {e}")
            return False
    
    def _handshake(self):
        """Perform handshake"""
        try:
            self._send_packet('addr', '', f"ADDR={self.server_ip}\nPORT={12345 + self.client_id}")
            self._receive_response()
            
            self._send_packet('skey', '', "SKEY=$5075626c6963204b6579")
            self._receive_response()
        except Exception as e:
            self.errors.append(f"Handshake: {e}")
            raise
    
    def _authenticate(self):
        """Authenticate with server"""
        try:
            auth_data = f"""NAME={self.username}
TOS=1
PASS=test{self.client_id}
MID=$00041f82bee5
HWFLAG=4
HWMASK=65828
PROD=NASCAR-PS2-2004
VERS=PS2/XXX-Jul  2 2003
LANG=en
SLUS=BASLUS-20824"""
            
            self._send_packet('auth', '', auth_data)
            cmd, data = self._receive_response()
            
            # Extract session ID
            if data and "SESS=" in data:
                for line in data.split('\n'):
                    if line.startswith("SESS="):
                        self.session_id = line[5:]
                        break
            
            self._send_packet('pers', '', f"PERS={self.username}")
            self._receive_response()
            
            print(f"[Client {self.client_id}] Authenticated as {self.username}")
        except Exception as e:
            self.errors.append(f"Authentication: {e}")
            raise
    
    def _concurrent_operations(self):
        """Perform concurrent operations"""
        start_time = time.time()
        operation_count = 0
        
        while self.running and (time.time() - start_time) < 30:
            try:
                # Randomly choose an operation
                operations = [
                    self._send_ping,
                    self._request_lobby_info,
                    self._peek_room,
                    self._join_leave_room
                ]
                
                operation = random.choice(operations)
                operation()
                operation_count += 1
                
                # Small random delay between operations
                time.sleep(random.uniform(0.5, 2.0))
                
            except Exception as e:
                self.errors.append(f"Operation {operation_count}: {e}")
                time.sleep(1)  # Back off on error
        
        print(f"[Client {self.client_id}] Completed {operation_count} operations")
    
    def _send_ping(self):
        """Send ping"""
        ref_time = time.strftime('%Y.%m.%d-%H:%M:%S')
        ping_data = f"REF={ref_time}\nTIME=2\nSESS={self.session_id or '0'}\nSTATUS=1"
        self._send_packet('~png', '', ping_data)
        self._receive_response(timeout=3)
        self.ping_count += 1
    
    def _request_lobby_info(self):
        """Request lobby information"""
        self._send_packet('sele', '', "ROOMS=1 USERS=1 RANKS=1")
        self._receive_response()
    
    def _peek_room(self):
        """Peek at a random room"""
        rooms = ['East', 'West', 'Beginner', 'Lobby']
        room = random.choice(rooms)
        self._send_packet('peek', '', f"NAME={room}")
        self._receive_response()
    
    def _join_leave_room(self):
        """Join and then leave a room"""
        rooms = ['East', 'West', 'Beginner']
        room = random.choice(rooms)
        
        # Join room
        self._send_packet('move', '', f"NAME={room}\nPASS=")
        self._receive_response()
        
        # Wait a bit
        time.sleep(random.uniform(1, 3))
        
        # Leave room
        self._send_packet('move', '', "NAME=\nPASS=")
        self._receive_response()
    
    def _send_packet(self, cmd, subcmd, payload):
        """Send protocol packet"""
        if isinstance(payload, str):
            payload = payload.encode('ascii')
        payload += b'\0'
        size = len(payload)
        packet = struct.pack(">4s4sL%ds" % size, 
                           bytearray(cmd, 'ascii'), 
                           bytearray(subcmd, 'ascii'), 
                           size + 12, payload)
        self.sock.sendall(packet)
    
    def _receive_response(self, timeout=5):
        """Receive server response"""
        self.sock.settimeout(timeout)
        try:
            header = self.sock.recv(12)
            if not header:
                return None, None
            
            cmd_type = header[:4]
            msg_size = (header[10] + header[11]) - 12
            if header[10] == 0:
                msg_size = header[11] - 12
            
            data = b''
            if msg_size > 0:
                data = self.sock.recv(msg_size)
            
            return cmd_type.decode('ascii', errors='ignore'), data.decode('ascii', errors='ignore')
            
        except socket.timeout:
            return None, None
        except Exception as e:
            self.errors.append(f"Receive: {e}")
            return None, None
    
    def stop(self):
        """Stop the client"""
        self.running = False
    
    def _disconnect(self):
        """Disconnect from server"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

# Run the test
if __name__ == "__main__":
    SERVER_IP = "192.168.2.123"  # Your server IP
    SERVER_PORT = 10600
    
    # Test with 3 concurrent clients first, then increase if stable
    tester = MultiClientTester(SERVER_IP, SERVER_PORT, num_clients=3)
    tester.run_concurrent_test()