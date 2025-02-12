from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Generate ECC key pair
private_key = ECC.generate(curve='P-256')
public_key = private_key.public_key()

# Generate random values
r1 = os.urandom(16)
t1 = os.urandom(16)
r2 = os.urandom(16)

# Example array of integers
C2 = [1, 2, 3, 4, 5]

# Convert C2 to bytes
C2_bytes = bytes(C2)

# Concatenate r1, t1, C2_bytes, and r2
data_to_encrypt = r1 + t1 + C2_bytes + r2


# Encrypt using ECIES (Elliptic Curve Integrated Encryption Scheme)
# Step 1: Generate an ephemeral ECC key pair
ephemeral_private_key = ECC.generate(curve='P-256')
ephemeral_public_key = ephemeral_private_key.public_key()

# Step 2: Perform ECDH to derive a shared secret
# The shared secret is the x-coordinate of the product of the ephemeral private key and the recipient's public key
shared_point = ephemeral_private_key.d * public_key.pointQ
shared_secret = shared_point.x.to_bytes(32, 'big')  # Use the x-coordinate of the shared point

# Step 3: Derive a symmetric key using HKDF (HMAC-based Key Derivation Function)
key = HKDF(shared_secret, 32, salt=b'', context=b'', hashmod=SHA256)

# Step 4: Encrypt the data using AES (simulating ECIES)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_data = iv + cipher.encrypt(pad(data_to_encrypt, AES.block_size))

# Step 5: Package the ephemeral public key and encrypted data
# In ECIES, the ephemeral public key is sent alongside the encrypted data
package = ephemeral_public_key.export_key(format='DER') + encrypted_data


# Decrypt using the private key
# Step 1: Extract the ephemeral public key and encrypted data from the package
ephemeral_public_key_der = package[:91]  # DER-encoded ECC public key is 91 bytes for P-256
encrypted_data = package[91:]

ephemeral_public_key = ECC.import_key(ephemeral_public_key_der)

# Step 2: Perform ECDH to derive the shared secret
shared_point = private_key.d * ephemeral_public_key.pointQ
shared_secret = shared_point.x.to_bytes(32, 'big')  # Use the x-coordinate of the shared point

# Step 3: Derive the symmetric key using HKDF
key = HKDF(shared_secret, 32, salt=b'', context=b'', hashmod=SHA256)

# Step 4: Decrypt the data using AES
iv = encrypted_data[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)


# Split the decrypted data back into r1, t1, C2_bytes, and r2
decrypted_r1 = decrypted_data[:16]
decrypted_t1 = decrypted_data[16:32]
decrypted_C2_bytes = decrypted_data[32:32+len(C2_bytes)]
decrypted_r2 = decrypted_data[32+len(C2_bytes):]

# Convert C2_bytes back to list of integers
decrypted_C2 = list(decrypted_C2_bytes)

# Print results
print("Original r1:", r1)
print("Decrypted r1:", decrypted_r1)
print("Original t1:", t1)
print("Decrypted t1:", decrypted_t1)
print("Original C2:", C2)
print("Decrypted C2:", decrypted_C2)
print("Original r2:", r2)
print("Decrypted r2:", decrypted_r2)