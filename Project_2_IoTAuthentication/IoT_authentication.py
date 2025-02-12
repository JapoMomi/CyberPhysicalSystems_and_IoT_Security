"""
IoT Secure Vault-Based Mutual Authentication

This script simulates a secure mutual authentication protocol between an IoT device and an IoT server. 
The authentication relies on a Secure Vault that contains multiple secret keys, which are combined using XOR 
and updated using HMAC-based transformations. The protocol uses AES-128bit cryptography algorithm and it ensures mutual 
authentication through cryptographic challenges and responses.

Classes:
    - SecureVault: Manages secret keys and provides methods for key retrieval and vault updating.
    - IoTServer: Simulates an IoT server handling authentication requests from devices.
    - IoTDevice: Simulates an IoT device that authenticates with the server using the vault-based approach.

Usage:
    Run the script to simulate an authentication process between the IoT server and an IoT device.
"""

import hashlib
import hmac
import os
import random
import threading
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

N = 5  # Number of keys in the Secure Vault
M = 16 # Size of each key in bytes

# Challenges length
# Challenges length must be <= N
CHALLENGE_1_LENGTH = 4
CHALLENGE_2_LENGTH = 3

# Class representing the secure vault containing the keys
class SecureVault:
    """
    Secure vault that stores a set of cryptographic keys. Provides methods to retrieve a composite key 
    using XOR operations and update the vault using HMAC.
    """
    def __init__(self, n=N, m=M):  
        """
        Initializes the vault with `n` randomly generated keys, each of size `m` bytes.
        """
        # Generate n random keys of size m bytes
        self.keys = [os.urandom(m) for _ in range(n)]
        print(f"Initial Vault (keys):")
        # Print the initial vault keys in hexadecimal format
        for i, key in enumerate(self.keys):
            print(f"  Key {i}: {key.hex()}")

    def key_xor(self, indices):
        """
        Retrieves a composite key by XORing keys at specified indices.
        
        Parameters:
            indices (list): List of key indices to XOR.
        
        Returns:
            bytes: The computed XOR result as a new key.
        """
        # Start with the first key in the list
        key = self.keys[indices[0]]
        print(f"  Initial Key from Vault: {key.hex()}")
        for idx in indices[1:]:
            # XOR the current key with the next key in the list
            print(f"  XOR between key {key.hex()} and key {self.keys[idx].hex()}")
            key = bytes(a ^ b for a, b in zip(key, self.keys[idx]))
            print(f"  XOR result: {key.hex()}")
        print("")
        return key

    def update_vault(self, data):
        """
        Updates the vault keys using an HMAC transformation with the provided data.
        
        Parameters:
            data (bytes): Input data used for updating the vault.
        """
        print("Updating key ...")
        h = hmac.new(data, b''.join(self.keys), hashlib.sha256).digest()
        # Partition the HMAC result into segments corresponding to key sizes
        partitions = [h[i:i+len(self.keys[0])] for i in range(0, len(h), len(self.keys[0]))]
        for i in range(len(self.keys)):
            # XOR each key with the corresponding partition
            print(f"  XOR between key {self.keys[i].hex()} and partition {partitions[i % len(partitions)].hex()}")
            self.keys[i] = bytes(a ^ b for a, b in zip(self.keys[i], partitions[i % len(partitions)]))
            print(f"  New Key {i}: {self.keys[i].hex()}")


class IoTServer(threading.Thread):
    """
    Simulates an IoT server that authenticates connected IoT devices using a secure vault-based protocol.
    """
    def __init__(self):
        super().__init__()
        self.vault = None
        self.devices = []

    def run(self):
        pass

    def get_device_by_id(self, device_id):
        """
        Retrieves a device instance by its ID.
        
        Parameters:
            device_id (str): The unique identifier of the device.
        
        Returns:
            IoTDevice or None: The corresponding device if found, else None.
        """
        return next((device for device in self.devices if device.device_id == device_id), None)

    def connect(self, device):
        """
        Registers a device with the server.
        """
        self.devices.append(device)

    def is_valid_session(self, message):
        """
        Checks if the session ID is valid.
        """
        if 0 < message[1] < 100:
            self.init_msg = message
            print("Valid session\n")
            return True
        return False 
    
    def generate_challenge(self):
        """
        Generates a challenge for the device including a list of indices (c1) and a random number (r1).
        
        Returns:
            tuple: A challenge containing (c1, r1)
        """
        c1 = random.sample(range(len(self.vault.keys)), CHALLENGE_1_LENGTH)
        r1 = os.urandom(16)
        challenge = (c1, r1)
        print(f"Challenge 1 sent to device {self.get_device_by_id(self.init_msg[0])}: c1={challenge[0]} || r1={challenge[1].hex()}")
        
        self.c1 = c1
        self.r1 = r1
        return challenge

    def validate_challenge(self, encrypted_message):
        """
        Validates the challenge response from the device by decrypting and verifying r1.
        
        Parameters:
            encrypted_message (bytes): The encrypted response from the device.
        
        Returns:
            bool: True if the response is valid, False otherwise.
        """
        print("Server computing k1 for validating r1 ...")
        k1 = self.vault.key_xor(self.c1)
        decrypted_message = AES.new(k1, AES.MODE_ECB).decrypt(encrypted_message)
        r1_received = decrypted_message[:16]
        t1_received = decrypted_message[16:32]
        c2 = list(decrypted_message[32:35])
        r2 = decrypted_message[35:51]

        if r1_received == self.r1 and all(0 <= idx < len(self.vault.keys) for idx in c2):
            print(f"Server validates r1={self.r1.hex()} == r1_received={r1_received.hex()} --> OK")

            self.c2 = c2
            self.r2 = r2
            self.t1_received = t1_received
            return True
        return False

    def final_response(self):
        """
        Generates and sends the final authentication response to the device.
        
        Returns:
            bytes: The encrypted final response message (ENC(k2 xor t1, r2 || t2)).
        """
        print("Server compunting k2 ...")
        k2 = self.vault.key_xor(self.c2)
        key = bytes(a ^ b for a, b in zip(k2, self.t1_received))
        t2 = os.urandom(16)
        payload = self.r2 + t2
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(payload, 16))

        print(f"Sending final response to the device: r2={self.r2.hex()} || t2={t2.hex()}, encrypted --> {encrypted.hex()}")
        return encrypted


class IoTDevice(threading.Thread):
    """
    Simulates an IoT device that authenticates with the IoT server using a secure vault.
    """
    def __init__(self, device_id, server):
        super().__init__()
        self.device_id = device_id
        self.vault = SecureVault()
        # Connect the device to a server
        self.server = server
        self.server.connect(self)
        self.authenticated = False
        self.verification_report = {}

        self.auth_start_time = None  # Timer start
        self.auth_end_time = None    # Timer end

    def run(self):
        """
        Executes the authentication process between the device and the server.
        """
        # Sending vault to the server
        self.server.vault = self.vault
        if self.vault != self.server.vault:
            print("Something went wrong on vault transmission")
            return
        
        print("Authentication process is starting ...")

        while self.server.get_device_by_id(self.device_id) is None:
            pass
        
        # Start the timer
        self.auth_start_time = time.time()

        # Send the first message of the device to the server
        msg1 = self.send_initial_message()
        
        # Server checks the correctness of the session ID
        if self.server.is_valid_session(msg1):
            self.verification_report['valid_session'] = True
            # Server generates the first challenge and sends it to the device
            msg2 = self.server.generate_challenge() #(c1, r1)

            # Device processes the challenge and generate the response 
            msg3 = self.process_challenge(msg2) #encrypted message: ENC(k1, r1 || t1 || {c2, r2})
            
            # Server checks if self.r1 matches the r1 sent by the device
            if self.server.validate_challenge(msg3):
                self.verification_report['r1_match'] = True
                # Server sends the final response to the device
                final_response = self.server.final_response() #encryted message: ENC(k2 xor t1, r2 || t2)

                # Device checks if self.r2 matches the r2 sent back by the server
                if self.validate_final_response(final_response):
                    self.verification_report['r2_match'] = True
                    self.authenticated = True
                else:
                    self.verification_report['r2_match'] = False
                    print("Something went wrong on the final response of the server to the device")
            
            else:
                self.verification_report['r1_match'] = False
                print("Something went wrong on the second message sent by the device to the server")
                self.display_authentication_status(success=False)

        else:
            self.verification_report['valid_session'] = False
            print("Invalid session ID")
            self.display_authentication_status(success=False)

        if self.authenticated:
            previous_vault = self.vault.keys.copy()
            self.vault.update_vault(self.r1 + self.r2)

            # Verify if the vault was updated correctly
            self.verification_report['vault_updated'] = (previous_vault != self.vault.keys)
            self.server.vault = self.vault
            
            self.auth_end_time = time.time()  # Stop the timer
            self.display_authentication_status(success=True)
            print("Update done")

        # Display the verification report
        self.display_verification_report()

    def send_initial_message(self):
        """
        Sends the initial message containing the device ID and a random session ID.
        """
        message = (self.device_id, random.randint(1, 100))
        print(f"Initial message sent by the device: {message}")
        return message
    
    def process_challenge(self, challenge):
        """
        Processes the received challenge and generates an encrypted response.
        
        Parameters:
            challenge (tuple): A challenge containing (c1, r1).
        
        Returns:
            bytes: The encrypted response message (ENC(k1, r1 || t1 || {C2, r2})).
        """
        c1, r1 = challenge
        k1 = self.vault.key_xor(c1)
        t1 = os.urandom(16)
        c2 = random.sample(range(len(self.vault.keys)), CHALLENGE_2_LENGTH)
        r2 = os.urandom(16)
        payload = r1 + t1 + bytes(c2) + r2
        encrypted = AES.new(k1, AES.MODE_ECB).encrypt(pad(payload, 16))

        print(f"Sending response to the server: (r1={r1.hex()} || t1={t1.hex()} || c2={c2} || r2={r2.hex()}), encryption --> {encrypted.hex()}")

        self.r1 = r1
        self.t1 = t1
        self.c2 = c2
        self.r2 = r2
        return encrypted
    
    def validate_final_response(self, encrypted_final_response):
        """
        Validates the final response from the server by decrypting and verifying r2.
        
        Parameters:
            encrypted_final_response (bytes): The encrypted response from the server.
        
        Returns:
            bool: True if the response is valid, False otherwise.
        """
        print("Device computing k2 for validating r2 ...")
        k2 = self.vault.key_xor(self.c2)
        key = bytes(a ^ b for a, b in zip(k2, self.t1))

        decrypted_response = AES.new(key, AES.MODE_ECB).decrypt(encrypted_final_response)
        #r2_received = unpad(decrypted_response, 16)
        r2_received = decrypted_response[:16]

        if r2_received == self.r2:
            print(f"Device validates r2={self.r2.hex()} == r2_received={r2_received.hex()} --> OK\n")
            return True
        return False
    
    def display_authentication_status(self, success):
        """
        Displays whether authentication was successful or not.
        """
        if success:
            print("\nAuthentication successful!")
            #print("\n✅ Authentication successful! ✅")
            # Calculate and display the elapsed time
            if self.auth_start_time and self.auth_end_time:
                elapsed_time = self.auth_end_time - self.auth_start_time
                print(f"Authentication Time: {elapsed_time:.4f} seconds\n")
                #print(f"⏱️ Authentication Time: {elapsed_time:.4f} seconds\n")
        else:
            print("\nAuthentication failed. Please try again.")
            #print("\n❌ Authentication failed. Please try again. ❌")

    def display_verification_report(self):
        """
        Displays the detailed verification report
        """
        print("\nVerification Report:")
        #print("\n📊 Verification Report:")
        for key, value in self.verification_report.items():
            status = "ok" if value else "error"
            #status = "✔️" if value else "❌"
            print(f" - {key.replace('_', ' ').capitalize()}: {status}")


# Main function to run the server and device authentication process
if __name__ == "__main__":
    # Create a server and device to perform authentication
    server = IoTServer()
    device = IoTDevice("Device01", server)

    # Start server and device threads
    server.start()
    device.start()

    # Wait for both threads to finish
    server.join()
    device.join() 