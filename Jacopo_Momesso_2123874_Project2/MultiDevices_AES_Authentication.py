"""
IoT Secure Mutual Authentication System with AES-128 and Vault-Based Key Management

Jacopo Momesso 2123874
"""

import hashlib
import hmac
import os
import random
import threading
import time
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from prettytable import PrettyTable

# Number of devices connected to the server
DEVICE_NUMBER = 10

# Cryptographic parameters
N = 5  # Number of keys in the Secure Vault
M = 16  # Size of each key in bytes (128 bits for AES-128)

# Authentication challenge parameters
CHALLENGE_1_LENGTH = 4  # Number of keys to combine for first challenge
CHALLENGE_2_LENGTH = 3  # Number of keys to combine for second challenges

class SecureVault:
    """
    Class representing secure cryptographic key storage and management system.
    Implements dynamic key updates using HMAC-based key derivation
    """
    
    def __init__(self, n=N, m=M):
        """
        Initialize vault with random cryptographic keys
        
        Args:
            n (int): Number of keys to generate
            m (int): Size of each key in bytes
        """
        self.keys = [os.urandom(m) for _ in range(n)]

    def key_xor(self, indices):
        """
        Combine multiple keys using XOR operation
        
        Args:
            indices (list): List of key indices to combine
            
        Returns:
            bytes: XOR-combined key material
        """
        key = self.keys[indices[0]]
        for idx in indices[1:]:
            # Iteratively XOR subsequent keys
            key = bytes(a ^ b for a, b in zip(key, self.keys[idx]))
        return key

    def update_vault(self, data):
        """
        Update all keys in the vault using HMAC-based key derivation
        
        Args:
            data (bytes): Input data for key update derivation
        """
        # Generate HMAC-SHA256 of current keys using input data
        h = hmac.new(data, b''.join(self.keys), hashlib.sha256).digest()
        
        # Split HMAC output into key-sized partitions
        partitions = [h[i:i+len(self.keys[0])] for i in range(0, len(h), len(self.keys[0]))]
        
        # Update each key with XOR of current key and partition
        for i in range(len(self.keys)):
            self.keys[i] = bytes(a ^ b for a, b in zip(self.keys[i], partitions[i % len(partitions)]))


class IoTServer(threading.Thread):
    """
    Class representing a server able to handle multiple IoT devices.
    Manages secure sessions and cryptographic challenges
    """
    
    def __init__(self):
        super().__init__()
        self.device_vaults = {}  # {device_id: SecureVault}
        self.sessions = {}       # {device_id: session_data}
        self.lock = threading.Lock()

    def register_device(self, device):
        """Register a new IoT device with its vault"""
        with self.lock:
            self.device_vaults[device.device_id] = device.vault

    def is_valid_session(self, device_id, session_id):
        """Validate session ID and initialize session tracking"""
        with self.lock:
            if 0 < session_id < 100 and device_id in self.device_vaults:
                self.sessions[device_id] = {
                    'vault': self.device_vaults[device_id],
                    'session_id': session_id
                }
                return True
        return False

    def generate_challenge(self, device_id):
        """
        Generate first authentication challenge
        Returns tuple of (key indices, random nonce)
        """
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return None
            
            # Select random keys for challenge
            vault = session['vault']
            c1 = random.sample(range(len(vault.keys)), CHALLENGE_1_LENGTH)
            r1 = os.urandom(16)  # 128-bit random nonce
            
            session.update({'c1': c1, 'r1': r1})
            return (c1, r1)

    def validate_challenge_response(self, device_id, encrypted_response):
        """Validate device's response to first challenge"""
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return False
            
            # Retrieve session parameters
            vault = session['vault']
            c1 = session['c1']
            r1 = session['r1']

            # Decrypt response using combined key
            k1 = vault.key_xor(c1)
            decrypted = AES.new(k1, AES.MODE_ECB).decrypt(encrypted_response)
            
            # Parse decrypted components
            r1_received = decrypted[:16]
            t1 = decrypted[16:32]
            c2 = list(decrypted[32:35])
            r2 = decrypted[35:51]

            # Validate nonce and store session data
            if r1_received != r1:
                return False

            session.update({'c2': c2, 'r2': r2, 't1': t1})
            return True

    def generate_final_response(self, device_id):
        """Generate final authentication response to device"""
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return None
            
            # Retrieve session parameters
            vault = session['vault']
            c2 = session['c2']
            r2 = session['r2']
            t1 = session['t1']

            # Create dynamic session key
            k2 = vault.key_xor(c2)
            dynamic_key = bytes(a ^ b for a, b in zip(k2, t1))
            
            # Encrypt final response
            t2 = os.urandom(16)  # Server-generated nonce
            payload = r2 + t2
            encrypted = AES.new(dynamic_key, AES.MODE_ECB).encrypt(pad(payload, 16))
            
            session['t2'] = t2
            return encrypted

    def finalize_auth(self, device_id):
        """Finalize authentication and update vault"""
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return
            
            # Update vault with session nonces
            vault = session['vault']
            r1 = session['r1']
            r2 = session['r2']
            vault.update_vault(r1 + r2)
            
            # Synchronize updated vault
            self.device_vaults[device_id] = vault


class IoTDevice(threading.Thread):
    """
    Class representing IoT device able to handle secure authentication
    """
    
    def __init__(self, device_id, server):
        super().__init__()
        self.device_id = device_id
        self.server = server
        self.vault = SecureVault()
        self.authenticated = False
        self.encrypt_time = None
        self.decrypt_time = None
        self.vault_update_time = None
        self.server.register_device(self)

    def run(self):
        """Main authentication sequence"""
        # Session initialization
        session_id = random.randint(1, 99)
        if not self.server.is_valid_session(self.device_id, session_id):
            return

        # Process first challenge
        challenge1 = self.server.generate_challenge(self.device_id)
        if not challenge1:
            return
        c1, r1 = challenge1

        # Generate challenge response
        k1 = self.vault.key_xor(c1)
        t1 = os.urandom(16)  # Device-generated nonce
        c2 = random.sample(range(len(self.vault.keys)), CHALLENGE_2_LENGTH)
        r2 = os.urandom(16)  # Device challenge nonce
        
        # Time encryption operation
        payload = r1 + t1 + bytes(c2) + r2
        encrypt_start = time.time()
        encrypted_response = AES.new(k1, AES.MODE_ECB).encrypt(pad(payload, 16))
        self.encrypt_time = time.time() - encrypt_start

        if not self.server.validate_challenge_response(self.device_id, encrypted_response):
            return

        # Process final challenge
        final_response = self.server.generate_final_response(self.device_id)
        if not final_response:
            return

        # Decrypt and validate final response
        session_data = self.server.sessions[self.device_id]
        k2 = self.vault.key_xor(session_data['c2'])
        dynamic_key = bytes(a ^ b for a, b in zip(k2, t1))
        
        # Time decryption operation
        decrypt_start = time.time()
        decrypted = AES.new(dynamic_key, AES.MODE_ECB).decrypt(final_response)
        self.decrypt_time = time.time() - decrypt_start
        
        # Validate server response
        r2_received = decrypted[:16]
        if r2_received == r2:
            # Time vault update operation
            vault_start = time.time()
            self.server.finalize_auth(self.device_id)
            self.vault_update_time = time.time() - vault_start
            self.authenticated = True


if __name__ == "__main__":
    # Initialize authentication server
    server = IoTServer()
    server.start()

    # Create and start 10 IoT devices
    devices = [IoTDevice(f"Device{i+1:02}", server) for i in range(DEVICE_NUMBER)]
    for device in devices:
        device.start()

    # Wait for all devices to complete authentication
    for device in devices:
        device.join()
    server.join()

    # Collect and display performance metrics
    metrics_table = PrettyTable()
    metrics_table.field_names = ["Device ID", "Encrypt (ms)", "Decrypt (ms)", "Vault Update (ms)", "Status"]
    
    encrypt_times = []
    decrypt_times = []
    vault_times = []

    # Populate metrics table
    for device in devices:
        status = "Success" if device.authenticated else "Failed"
        encrypt = f"{device.encrypt_time*1000:.4f}" if device.encrypt_time else "N/A"
        decrypt = f"{device.decrypt_time*1000:.4f}" if device.decrypt_time else "N/A"
        vault = f"{device.vault_update_time*1000:.4f}" if device.vault_update_time else "N/A"
        
        if device.authenticated:
            encrypt_times.append(device.encrypt_time)
            decrypt_times.append(device.decrypt_time)
            vault_times.append(device.vault_update_time)
        
        metrics_table.add_row([
            device.device_id,
            encrypt,
            decrypt,
            vault,
            status
        ])

    # Calculate and display averages
    avg_table = PrettyTable()
    avg_table.field_names = ["Metric", "Average Time (ms)"]
    # Initialize sum variables
    total_sum = 0.0
    components_added = 0
    # Calculate individual averages and track components
    encrypt_avg = decrypt_avg = vault_avg = 0.0

    if encrypt_times:
        encrypt_avg = sum(encrypt_times) * 1000 / len(encrypt_times)
        avg_table.add_row(["Encryption", f"{encrypt_avg:.4f}"])
        total_sum += encrypt_avg
        components_added += 1

    if decrypt_times:
        decrypt_avg = sum(decrypt_times) * 1000 / len(decrypt_times)
        avg_table.add_row(["Decryption", f"{decrypt_avg:.4f}"])
        total_sum += decrypt_avg
        components_added += 1

    if vault_times:
        vault_avg = sum(vault_times) * 1000 / len(vault_times)
        avg_table.add_row(["Vault Update", f"{vault_avg:.4f}"])
        total_sum += vault_avg
        components_added += 1

    # Add total row only if we have at least one component
    if components_added > 0:
        avg_table.add_row(["Total Time", f"{total_sum:.4f}"])

    print("\nAES-128 Authentication Performance Metrics:")
    print(metrics_table)
    print("\nAverage Operation Times:")
    print(avg_table)

    # Launch comparative ECC authentication system
    print("\nInitiating ECC Authentication Comparison...\n")
    try:
        subprocess.run(['python', 'MultiDevices_ECC_Authentication.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"ECC Authentication Error: {e}")
    except FileNotFoundError:
        print("ECC Authentication System Not Found")