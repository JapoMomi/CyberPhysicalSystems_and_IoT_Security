import os
import time
from ecdsa import SigningKey, VerifyingKey, NIST256p

# Simulated IoT Device
class IoTDevice:
    def __init__(self):
        # Generate a private key for the device
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.verifying_key

    def get_public_key(self):
        # Return the public key in PEM format
        return self.public_key.to_pem()

    def sign_challenge(self, challenge):
        # Sign the challenge using the device's private key
        return self.private_key.sign(challenge)

# Simulated Server
class Server:
    def __init__(self):
        # Store registered devices (public keys)
        self.registered_devices = {}

    def register_device(self, device_id, public_key_pem):
        # Register a device by storing its public key
        public_key = VerifyingKey.from_pem(public_key_pem)
        self.registered_devices[device_id] = public_key

    def generate_challenge(self):
        # Generate a random challenge
        return os.urandom(32)

    def verify_signature(self, device_id, challenge, signature):
        # Verify the signature using the device's public key
        if device_id not in self.registered_devices:
            return False
        public_key = self.registered_devices[device_id]
        try:
            return public_key.verify(signature, challenge)
        except:
            return False

# Simulate the authentication process
def simulate_authentication():
    # Create a device and a server
    device = IoTDevice()
    server = Server()

    # Register the device with the server
    device_id = "device_123"
    server.register_device(device_id, device.get_public_key())

    # Start the timer
    start_time = time.time()

    # Server generates a challenge
    challenge = server.generate_challenge()
    print(f"Server: Generated challenge: {challenge.hex()}")

    # Device signs the challenge
    signature = device.sign_challenge(challenge)
    print(f"Device: Signed challenge: {signature.hex()}")

    # Server verifies the signature
    if server.verify_signature(device_id, challenge, signature):
        print("Server: Authentication successful!")
    else:
        print("Server: Authentication failed!")

    # End the timer
    end_time = time.time()

    # Calculate and print the total time taken
    total_time = end_time - start_time
    print(f"Total time taken for authentication: {total_time:.6f} seconds")

# Run the simulation
if __name__ == "__main__":
    simulate_authentication()