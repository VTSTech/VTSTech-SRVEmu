# RC4 Implementation for NASCAR Thunder 2004
# Based on Ghidra analysis of Crypto_RC4_Initialize and Crypto_RC4_Process

# Load the extracted RC4 table
import struct

RC4_TABLE = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01, 
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79, 
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d, 

]

class CustomRC4:
    def __init__(self, rc4_table):
        self.rc4_table = rc4_table  # 256 uint32 entries
        self.S = bytearray(256)     # S-box
        self.i = 0                  # Current i index
        self.j = 0                  # Current j value (32-bit)
        
    def initialize(self, key, key_length=16, iterations=4096):
        """
        Initialize RC4 state matching Crypto_RC4_Initialize
        
        Args:
            key: 16-byte public key
            key_length: Length of key (should be 16)
            iterations: Number of iterations (param_4 << 8 = 4096)
        """
        # Initialize S-box with 0..255
        for i in range(256):
            self.S[i] = i
        
        # Reset indices
        self.i = 0
        self.j = 0
        
        if key_length <= 0:
            key_length = len(key)
        
        if key_length > 0:
            temp_j = 0
            k = 0
            
            for idx in range(iterations):
                # Get current S[i]
                i_idx = idx % 256
                key_idx = idx % key_length
                
                # Get values
                s_val = self.S[i_idx]
                key_byte = key[key_idx]
                
                # Update temp_j using RC4 table
                # uVar5 = uVar5 >> 8 ^ RC4_Table[(uVar4 ^ key_byte) * 4]
                temp_j = (temp_j >> 8) ^ self.rc4_table[(k ^ key_byte) & 0xFF]
                
                # Update k using RC4 table
                # uVar4 = temp_j & 0xFF
                k = temp_j & 0xFF
                temp_j = (temp_j >> 8) ^ self.rc4_table[(k ^ s_val) & 0xFF]
                k = temp_j & 0xFF
                
                # Swap S[i] and S[k]
                self.S[i_idx], self.S[k] = self.S[k], self.S[i_idx]
    
    def process(self, data):
        """
        Encrypt/decrypt data matching Crypto_RC4_Process
        
        Args:
            data: Bytes to process
        Returns:
            Processed bytes
        """
        result = bytearray(data)
        
        for n in range(len(data)):
            # Increment i
            self.i = (self.i + 1) & 0xFF
            
            # Get S[i]
            si = self.S[self.i]
            
            # Update j using RC4 table
            # uVar4 = uVar4 >> 8 ^ RC4_Table[(uVar5 ^ si) * 4]
            self.j = (self.j >> 8) ^ self.rc4_table[(self.j & 0xFF) ^ si]
            k = self.j & 0xFF
            
            # Get S[j]
            sj = self.S[k]
            
            # Swap S[i] and S[j]
            self.S[self.i] = sj
            self.S[k] = si
            
            # Generate keystream byte
            # Note: The game uses (si - sj) & 0xFF for the index
            keystream_idx = (si - sj) & 0xFF
            keystream_byte = self.S[keystream_idx]
            
            # XOR with data
            result[n] ^= keystream_byte
        
        return bytes(result)
    
    def encrypt_password(self, password, key):
        """
        Encrypt password matching Crypto_RC4_EncryptPassword
        
        Args:
            password: Plaintext password string
            key: 16-byte public key
        Returns:
            Encrypted password string
        """
        # Create local RC4 state
        local_rc4 = CustomRC4(self.rc4_table)
        local_rc4.initialize(key, 16, 4096)
        
        # Create global RC4 state
        global_rc4 = CustomRC4(self.rc4_table)
        global_rc4.initialize(key, 16, 4096)
        
        # Re-initialize global state with "ru paranoid?"
        global_rc4.initialize(b"ru paranoid?", -1, 4096)
        
        encrypted_chars = []
        
        for char in password:
            # Get keystream byte from local state
            keystream_byte = local_rc4.process(b'\x00')[0]
            
            # Apply custom formula
            # ((password_char + (keystream_byte % 0x60) + 0x40) % 0x60) + 0x20
            password_ord = ord(char)
            encrypted_ord = ((password_ord + (keystream_byte % 0x60) + 0x40) % 0x60) + 0x20
            
            # Ensure printable ASCII
            if encrypted_ord > 0x7E:
                encrypted_ord = 0x7F
            
            encrypted_chars.append(chr(encrypted_ord))
        
        return ''.join(encrypted_chars)
    
    def decrypt_password(self, encrypted_password, key):
        """
        Decrypt password (reverse of Crypto_RC4_EncryptPassword)
        
        Args:
            encrypted_password: Encrypted password string
            key: 16-byte public key
        Returns:
            Decrypted password string
        """
        # Create local RC4 state (same as encryption)
        local_rc4 = CustomRC4(self.rc4_table)
        local_rc4.initialize(key, 16, 4096)
        
        decrypted_chars = []
        
        for char in encrypted_password:
            # Get keystream byte from local state
            keystream_byte = local_rc4.process(b'\x00')[0]
            
            # Reverse the encryption formula
            encrypted_ord = ord(char)
            
            # Step 1: Subtract 0x20 to get X
            X = encrypted_ord - 0x20
            
            # Step 2: Reverse ((password_char + (keystream_byte % 0x60) + 0x40) % 0x60) = X
            # We need to find password_char such that:
            # (password_char + (keystream_byte % 0x60) + 0x40) ? X (mod 0x60)
            k_mod = keystream_byte % 0x60
            
            # password_char ? X - k_mod - 0x40 (mod 0x60)
            password_ord = (X - k_mod - 0x40) % 0x60
            
            # The original formula added 0x20 to make it printable, but we already subtracted 0x20
            # The password character should be in ASCII range
            if password_ord < 0x20:
                password_ord += 0x60
            
            # Ensure it's printable ASCII
            if password_ord < 0x20 or password_ord > 0x7E:
                # Try alternative calculation
                for add in range(0, 256, 0x60):
                    test_ord = password_ord + add
                    if 0x20 <= test_ord <= 0x7E:
                        password_ord = test_ord
                        break
            
            decrypted_chars.append(chr(password_ord))
        
        return ''.join(decrypted_chars)

# Server-side implementation for handling authentication
class RC4AuthHandler:
    def __init__(self, rc4_table_path=None):
        if rc4_table_path:
            # Load RC4 table from file
            with open(rc4_table_path, 'rb') as f:
                rc4_table_data = f.read(1024)
                self.rc4_table = struct.unpack('<256I', rc4_table_data)
        else:
            # Use hardcoded table (first 8 entries shown)
            self.rc4_table = RC4_TABLE
        
        self.client_keys = {}  # Store keys per client
        
    def generate_public_key(self):
        """Generate a 16-byte public key for a client"""
        import os
        return os.urandom(16)
    
    def store_client_key(self, client_id, key):
        """Store public key for a client"""
        self.client_keys[client_id] = key
    
    def encrypt_for_client(self, client_id, data):
        """Encrypt data for a specific client"""
        if client_id not in self.client_keys:
            return data
        
        key = self.client_keys[client_id]
        rc4 = CustomRC4(self.rc4_table)
        rc4.initialize(key, 16, 4096)
        return rc4.process(data)
    
    def decrypt_from_client(self, client_id, data):
        """Decrypt data from a specific client"""
        if client_id not in self.client_keys:
            return data
        
        key = self.client_keys[client_id]
        rc4 = CustomRC4(self.rc4_table)
        rc4.initialize(key, 16, 4096)
        return rc4.process(data)
    
    def handle_password_authentication(self, client_id, encrypted_password):
        """
        Handle password authentication
        
        Args:
            client_id: Unique client identifier
            encrypted_password: Password encrypted by client
        Returns:
            Decrypted password or None if error
        """
        if client_id not in self.client_keys:
            return None
        
        key = self.client_keys[client_id]
        rc4 = CustomRC4(self.rc4_table)
        
        try:
            # Try to decrypt password
            password = rc4.decrypt_password(encrypted_password, key)
            return password
        except:
            return None

# Test the implementation
def test_rc4():
    """Simple test to verify RC4 implementation"""
    print("Testing RC4 implementation...")
    
    # Create RC4 instance
    rc4 = CustomRC4(RC4_TABLE[:256])  # Use first 256 entries
    
    # Test key
    test_key = b'\x00' * 16
    
    # Test encryption/decryption
    rc4.initialize(test_key, 16, 4096)
    
    test_data = b"Hello World!"
    encrypted = rc4.process(test_data)
    
    # Reset and decrypt
    rc4.initialize(test_key, 16, 4096)
    decrypted = rc4.process(encrypted)
    
    print(f"Original: {test_data}")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_data == decrypted}")
    
    # Test password encryption
    test_password = "test123"
    encrypted_password = rc4.encrypt_password(test_password, test_key)
    decrypted_password = rc4.decrypt_password(encrypted_password, test_key)
    
    print(f"\nPassword test:")
    print(f"Original: {test_password}")
    print(f"Encrypted: {encrypted_password}")
    print(f"Decrypted: {decrypted_password}")
    print(f"Match: {test_password == decrypted_password}")

if __name__ == "__main__":
    # If you have the extracted RC4 table, load it:
    # with open('rc4_table.py', 'r') as f:
    #     exec(f.read())  # This loads RC4_TABLE
    
    # Run test
    test_rc4()