import os
import sys
import base64
import pickle
from pathlib import Path
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Add Ransomware folder to path so we can import its modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Ransomware'))

import symmetric
import utils
import environment

print("Z434M4 FULL DECRYPTOR - OFFLINE VERSION")
print("This decryptor recovers files using the complete decryption chain")

ransomware_name = "Z434M4"
home = environment.get_home_path()
ransomware_path = os.path.join(home, ransomware_name)

# Step 1: Load server private key (would normally be on C&C server)
# This key is needed to decrypt the client's private key
print("\n[1/4] Loading server private key...")
# Use correct path to server's private key file


server_private_key_data = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxF5BOX3N5UN1CsHpnfuU58lOw0+scQ39hOn6Q/QvM6aTOnYZ
ki57O6/JtgV2CetE+G5IZrRwYPAipFdChGM9RNZVegpnmGQCSRPlkfjN0TjfCFja
UX80PgRVm0ZHaeCeoNjit0yeW3YZ5nBjPjNr36BLaswJo1zbzhctK2SYX+Miov04
D3iC83Vc8bbJ8Wiip4jpKPDFhyO1I3QkykL04T1+tQXaGujLzc3QxJN3wo8rWkQ4
CaLAu1pb9QkdYhFG0D3TrljkRNiH0QnF3AscXAQNI94ZPaqD6e2rWcSy2ZMiKVJg
CWA40p9qe34H8+9ub3TgC52oSyapwbxzqs5vDQIDAQABAoIBAC3HA1GRwGQH+8sM
NZf8xFPcnB3v/vVEG6vWl98rl61k0cG5MnDfoR7i9hUW5NOfIy7/FqXKvr/6ezjw
lrMiJ3BavwZ6Ung2KEo89zG2XNS/e08I16xUCSvD+uj90zwdfx1kMkYk+G299H/C
B4DCoA074xj8g+qvhRZgVMle5B7F/gdun6AUGSxHC5uFmibM39MmMuSH16oJGcn5
0VRBmaB8vqMOFIyVKraoX4XAQwKE3by/VTM0kxBjmUZeUs2C1Paag7g09TuzQbXm
y3Tsv4aCZwrZlEXaFHopGz3HVHot2Ps3Qaq8WD76+SbzBm3pHayo3cDXvQwC1L7O
i/bihAkCgYEA23sqvBSVdMtWF+ktSXkt2OfVJsFpp3ym+qm2U5q9M+BTeyf4dnfP
/+Z5O5x6blFyf7ug8h2+8b0L6o34QfuaSXbJBtpmFS2GqG8B3KAYC4nnxonUxGuZ
ECc7wJRvo22A55rKVicmDWWr8rqNmbrNy9eoWUNYvNEouwr9nSW2Z9MCgYEA5QqW
rkUnmbIFd5gEKX+m9IKTUZ+dbuh1oHO3QqgmpeyZdxIvNa5C3bwuk6WBFGMjtCNl
NZeLGN8plcwlPxGEdCBTnhmKw0ikQWubYCx/NNNI2sWXidiym2bHI+2JkdOVx0HA
OU27+sbxyjqExCID+9b+c+t3MKZlzshif7L/YZ8CgYBLu8ZVO+0ObhN5ELbVwYC2
ddixFNA2QOcFW4ZUdvKOcfucZYBwsIsPTCHNFgORCX2u4bl5khYPKCJyfyaI7h6g
9uILAVV0PU9X02YbEQr7AEz/zxOh61bXohIWM6IKDIEMafcjn0KcINciXIj74N+e
VP38PybhkHKzh+lXTmoQjQKBgBKDHZSuUDoS8nAtIED+aU8f8qpJPV9GeKNkVu6T
SrRkgC7okFpFYHAtkpIqcVllffBEYBzJx9tVxjWuT2BemRcNudRweg+4olYLTX6j
ehCZ9yx/hfUFR8JZt0THITRhJpz5SoEXMFdflxFiU3LK0Qmc4eoaoQKUoGvrNFLf
89Y/AoGABgsbLx258EPtVqgY9uS9ta/XpUyKKjVGIqEY+jhn9lNhxQK+0iRQvD6C
eSopcx2e09eODLXAxOpi+f6K2mxJVMjxhvIthnad4vhtJjaBojaMG23+uOpX9Gj/
u7KSAN0pGuIw57saMWU1KFy2POKHI8+PP4rGeJhKx6isAt+3ZFk=
-----END RSA PRIVATE KEY-----"""

server_private_key = serialization.load_pem_private_key(
    server_private_key_data.encode('utf-8'),  # Convert string to bytes
    password=None
)
print("✓ Server private key loaded successfully")

# Step 2: Decrypt client's private key using server's private key
print("\n[2/4] Decrypting client private key...")

client_private_key_path = os.path.join(ransomware_path, "encrypted_client_private_key.key")
if not os.path.exists(client_private_key_path):
    print(f"ERROR: Encrypted client private key not found at {client_private_key_path}")
    print("Make sure the ransomware has run and this file was created")
    sys.exit(1)

# Load encrypted client private key
with open(client_private_key_path, "rb") as f:
    encrypted_client_private_key = pickle.load(f)

# Decrypt it using server's private key
client_private_key_parts = []
for encrypted_chunk in encrypted_client_private_key:
    try:
        decrypted_chunk = server_private_key.decrypt(
            encrypted_chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_private_key_parts.append(decrypted_chunk)
    except Exception as e:
        print(f"Error decrypting part of client private key: {e}")

# Combine the parts to get the complete client private key
client_private_key_data = b"".join(client_private_key_parts)
client_private_key = serialization.load_pem_private_key(
    client_private_key_data,
    password=None
)
print("✓ Client private key decrypted successfully")

# Save decrypted client private key for reference (optional)
with open(os.path.join(ransomware_path, "decrypted_client_private_key.pem"), "wb") as f:
    f.write(client_private_key_data)

# Step 3: Decrypt the AES keys for each file
print("\n[3/4] Decrypting file AES keys...")
aes_keys_path = os.path.join(ransomware_path, "AES_encrypted_keys.txt")
if not os.path.exists(aes_keys_path):
    print(f"ERROR: AES keys file not found at {aes_keys_path}")
    print("Make sure the ransomware has run and this file was created")
    sys.exit(1)

file_keys = {}
try:
    with open(aes_keys_path, "r") as f:
        encrypted_keys_data = f.read().strip().split('\n')
    
    for line in encrypted_keys_data:
        if not line:
            continue
            
        parts = line.split(' ')
        if len(parts) != 2:
            print(f"WARNING: Invalid line format in keys file: {line}")
            continue
            
        encrypted_key_base64, encrypted_path_base64 = parts
        
        # Decrypt the AES key using client's private key
        try:
            encrypted_key = base64.b64decode(encrypted_key_base64)
            decrypted_key = client_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Store in dictionary: filepath -> decryption key
            file_path = base64.b64decode(encrypted_path_base64).decode('utf-8')
            file_keys[file_path] = decrypted_key
        except Exception as e:
            print(f"Error decrypting key: {e}")
    
    print(f"✓ Successfully decrypted {len(file_keys)} file keys")
except Exception as e:
    print(f"Error processing keys file: {e}")

# Step 4: Decrypt all files
print("\n[4/4] Decrypting files...")
success_count = 0
failed_count = 0

for encrypted_path, aes_key in file_keys.items():
    try:
        print(f"Processing: {encrypted_path}")
        
        # Check if file exists
        if not os.path.exists(encrypted_path):
            print(f"  File not found: {encrypted_path}")
            failed_count += 1
            continue
        
        # Create decrypter with the correct key
        decrypter = symmetric.AESCipher(aes_key)
        
        # Read encrypted content
        with open(encrypted_path, 'rb') as f:
            encrypted_content = f.read()
        
        # Decrypt content
        decrypted_content = decrypter.decrypt(encrypted_content)
        
        # Determine original filename (remove .Z434M4 extension)
        original_path = encrypted_path.replace('.Z434M4', '')
        
        # Write the decrypted file
        with open(original_path, 'wb') as f:
            f.write(decrypted_content)
        
        print(f"  ✓ Decrypted: {original_path}")
        
        # Delete the encrypted file
        os.remove(encrypted_path)
        success_count += 1
        
    except Exception as e:
        print(f"  ✗ Failed to decrypt {encrypted_path}: {e}")
        failed_count += 1

# Handle the encrypted extensions file if it exists
extensions_file_path = os.path.join(ransomware_path, "file_extensions.dat.Z434M4")
if os.path.exists(extensions_file_path) and extensions_file_path in file_keys:
    try:
        print("\nRestoring original file extensions...")
        
        # Get the key for the extensions file
        ext_key = file_keys[extensions_file_path]
        
        # Read and decrypt the file
        with open(extensions_file_path, 'rb') as f:
            encrypted_content = f.read()
            
        # Decrypt the extensions file
        decrypter = symmetric.AESCipher(ext_key)
        decrypted_content = decrypter.decrypt(encrypted_content)
        
        # Load the extensions map
        extensions_map = pickle.loads(decrypted_content)
        
        # Restore original extensions
        for file_path, original_ext in extensions_map.items():
            if os.path.exists(file_path):
                try:
                    base_name, _ = os.path.splitext(file_path)
                    os.rename(file_path, base_name + original_ext)
                    print(f"  ✓ Restored extension: {base_name + original_ext}")
                except Exception as e:
                    print(f"  ✗ Failed to restore extension for {file_path}: {e}")
    except Exception as e:
        print(f"Error processing extensions file: {e}")

print("\nDecryption Complete!")
print(f"Successfully decrypted: {success_count} files")
print(f"Failed to decrypt: {failed_count} files")
print("\nYour files have been recovered!")