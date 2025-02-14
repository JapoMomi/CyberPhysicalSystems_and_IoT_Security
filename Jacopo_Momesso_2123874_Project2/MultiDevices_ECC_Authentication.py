"""
Elliptic Curve Digital Signature Algorithm (ECDSA) Authentication System

Jacopo Momesso 2123874
"""

import os
import time
from ecdsa import SigningKey, VerifyingKey, NIST256p
from prettytable import PrettyTable

# Number of IoT devices to simulate
DEVICE_NUMBER = 10  

class IoTDevice:
    """
    IoT Device implementation using ECDSA for cryptographic operations
    """
    
    def __init__(self, device_id):
        """
        Initialize device with cryptographic identity
        """
        self.device_id = device_id
        # Generate ECDSA key pair using NIST P-256 curve
        start_time = time.perf_counter()
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.verifying_key
        self.key_gen_time = (time.perf_counter() - start_time) * 1000
        self.sign_time = 0.0
        self.status = "Failed"

    def get_public_key(self):
        """
        Retrieve public key in PEM format
        """
        return self.public_key.to_pem()

    def sign_challenge(self, challenge):
        """
        Sign cryptographic challenge and measure execution time
        """
        start_time = time.perf_counter()
        sig = self.private_key.sign(challenge)
        # Store signing duration in milliseconds
        self.sign_time = (time.perf_counter() - start_time) * 1000
        return sig


class Server:
    """
    Central authentication server managing IoT devices
    """
    
    def __init__(self):
        """Initialize empty device registry and timing trackers"""
        self.registered_devices = {}
        self.verify_times = {}

    def register_device(self, device_id, public_key_pem):
        """
        Register device with public key
        """
        public_key = VerifyingKey.from_pem(public_key_pem)
        self.registered_devices[device_id] = public_key

    def generate_challenge(self, device_id):
        """
        Generate cryptographic challenge and track generation time
        """
        return os.urandom(32)  # 256-bit challenge

    def verify_signature(self, device_id, challenge, signature):
        """
        Verify device signature with timing metrics
        """
        if device_id not in self.registered_devices:
            return False
        
        public_key = self.registered_devices[device_id]
        start_time = time.perf_counter()
        
        try:
            # Attempt signature verification
            result = public_key.verify(signature, challenge)
        except Exception:
            # Handle invalid signature format/verification failures
            result = False
            
        # Store verification duration in milliseconds
        self.verify_times[device_id] = (time.perf_counter() - start_time) * 1000
        return result


def simulate_authentication(server, device):
    """
    Complete authentication sequence for a single device
    """
    # Registration phase
    server.register_device(device.device_id, device.get_public_key())
    
    total_start = time.perf_counter()
    
    # Challenge generation phase
    challenge = server.generate_challenge(device.device_id)
    
    # Device response phase
    signature = device.sign_challenge(challenge)
    
    # Server verification phase
    verification_result = server.verify_signature(device.device_id, challenge, signature)
    
    # Calculate total authentication duration
    total_time = (time.perf_counter() - total_start) * 1000
    device.status = "Success" if verification_result else "Failed"
    
    return {
        "key_gen_time": device.key_gen_time,
        "sign_time": device.sign_time,
        "verify_time": server.verify_times[device.device_id],
        "total_time": total_time,
        "status": device.status
    }

if __name__ == "__main__":
    # Initialize authentication infrastructure
    server = Server()
    devices = [IoTDevice(f"Device{i+1:02}") for i in range(DEVICE_NUMBER)]
    
    # Execute authentication for all devices
    results = [simulate_authentication(server, device) for device in devices]

    # Initialize results tables
    results_table = PrettyTable()
    avg_table = PrettyTable()
    
    # Configure table columns
    results_table.field_names = ["Device ID", "Key Gen (ms)", "Signing (ms)", 
                               "Verify (ms)", "Total (ms)", "Status"]
    
    # Data collection for averages
    key_gen_times = []
    sign_times = []
    verify_times = []
    total_times = []

    # Populate results table
    for i, result in enumerate(results):
        device = devices[i]
        results_table.add_row([
            device.device_id,
            f"{result['key_gen_time']:.4f}",
            f"{result['sign_time']:.4f}",
            f"{result['verify_time']:.4f}",
            f"{result['total_time']:.4f}",
            result['status']
        ])
        
        # Collect metrics for successful authentications
        if result['status'] == "Success":
            key_gen_times.append(result['key_gen_time'])
            sign_times.append(result['sign_time'])
            verify_times.append(result['verify_time'])
            total_times.append(result['total_time'])

    # Configure averages table
    avg_table.field_names = ["Metric", "Average Time (ms)"]
    
    # Calculate and add averages for successful authentications
    if key_gen_times:
        avg_table.add_row(["Key Generation", f"{sum(key_gen_times)/len(key_gen_times):.4f}"])
        avg_table.add_row(["Signature Creation", f"{sum(sign_times)/len(sign_times):.4f}"])
        avg_table.add_row(["Signature Verification", f"{sum(verify_times)/len(verify_times):.4f}"])
        avg_table.add_row(["Total Authentication", f"{sum(total_times)/len(total_times):.4f}"])

    # Display results
    print("\nECC Authentication Performance Metrics")
    print(results_table)
    
    print("\nPerformance Averages (Successful Authentications Only)")
    print(avg_table)



    