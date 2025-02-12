import os
import time
from ecdsa import SigningKey, VerifyingKey, NIST256p
from prettytable import PrettyTable

# Simulated IoT Device
class IoTDevice:
    def __init__(self, device_id):
        self.device_id = device_id
        # Generate a private key for the device
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.verifying_key
        self.sign_time = 0
        self.status = "Failed"

    def get_public_key(self):
        return self.public_key.to_pem()

    def sign_challenge(self, challenge):
        start_time = time.perf_counter()
        sig = self.private_key.sign(challenge)
        self.sign_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
        return sig

# Simulated Server
class Server:
    def __init__(self):
        self.registered_devices = {}
        self.challenge_times = {}
        self.verify_times = {}

    def register_device(self, device_id, public_key_pem):
        public_key = VerifyingKey.from_pem(public_key_pem)
        self.registered_devices[device_id] = public_key

    def generate_challenge(self, device_id):
        start_time = time.perf_counter()
        challenge = os.urandom(32)
        self.challenge_times[device_id] = (time.perf_counter() - start_time) * 1000
        return challenge

    def verify_signature(self, device_id, challenge, signature):
        if device_id not in self.registered_devices:
            return False
        public_key = self.registered_devices[device_id]
        start_time = time.perf_counter()
        try:
            result = public_key.verify(signature, challenge)
        except:
            result = False
        self.verify_times[device_id] = (time.perf_counter() - start_time) * 1000
        return result

def simulate_authentication(server, device):
    # Register the device with the server
    server.register_device(device.device_id, device.get_public_key())
    
    total_start = time.perf_counter()
    
    # Generate challenge
    challenge = server.generate_challenge(device.device_id)
    
    # Sign challenge
    signature = device.sign_challenge(challenge)
    
    # Verify signature
    verification_result = server.verify_signature(device.device_id, challenge, signature)
    
    total_time = (time.perf_counter() - total_start) * 1000
    device.status = "Success" if verification_result else "Failed"
    
    return {
        "challenge_time": server.challenge_times[device.device_id],
        "sign_time": device.sign_time,
        "verify_time": server.verify_times[device.device_id],
        "total_time": total_time,
        "status": device.status
    }

if __name__ == "__main__":
    # Create server and devices
    server = Server()
    num_devices = 10
    devices = [IoTDevice(f"Device{i+1:02}") for i in range(num_devices)]
    
    # Results storage
    results = []
    
    # Simulate authentication for all devices
    for device in devices:
        results.append(simulate_authentication(server, device))
    
    # Create and populate table
    table = PrettyTable()
    table.field_names = ["Device ID", "Challenge (ms)", "Signing (ms)", "Verify (ms)", "Total (ms)", "Status"]
    
    challenge_times = []
    sign_times = []
    verify_times = []
    total_times = []
    
    for i, result in enumerate(results):
        device_id = devices[i].device_id
        challenge = f"{result['challenge_time']:.4f}"
        sign = f"{result['sign_time']:.4f}"
        verify = f"{result['verify_time']:.4f}"
        total = f"{result['total_time']:.4f}"
        
        table.add_row([
            device_id,
            challenge,
            sign,
            verify,
            total,
            result['status']
        ])
        
        if result['status'] == "Success":
            challenge_times.append(result['challenge_time'])
            sign_times.append(result['sign_time'])
            verify_times.append(result['verify_time'])
            total_times.append(result['total_time'])
    
    # Create averages table
    avg_table = PrettyTable()
    avg_table.field_names = ["Metric", "Average Time (ms)"]
    
    if challenge_times:
        avg_table.add_row(["Challenge Generation", f"{sum(challenge_times)/len(challenge_times):.4f}"])
        avg_table.add_row(["Signature Creation", f"{sum(sign_times)/len(sign_times):.4f}"])
        avg_table.add_row(["Signature Verification", f"{sum(verify_times)/len(verify_times):.4f}"])
        avg_table.add_row(["Total Authentication", f"{sum(total_times)/len(total_times):.4f}"])
    
    # Print results
    print("ECC Authentication Performance Metrics:")
    print(table)
    print("\nAverage Times for Successful Authentications:")
    print(avg_table)