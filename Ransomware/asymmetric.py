#!/usr/bin/env python
# coding=UTF-8
import os
from os import chmod
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class assymetric():
    # Constructor
    def __init__(self):
        self.private_key_path = ""
        self.public_key_path = ""
        self.bit_len = 2048
        self.private_key_PEM = None
        self.public_key_PEM = None
        self.key = None

    def generate_keys(self):
        # Generate a private key
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.bit_len,
        )
        
        # Export private key in OpenSSH format
        self.private_key_PEM = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Export public key in OpenSSH format
        self.public_key_PEM = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

    def encrypt(self, data):
        """Encrypt data with public key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Use the public key for encryption
        public_key = self.key.public_key()
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, data):
        """Decrypt data with private key"""
        plaintext = self.key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def save_to_file(self, path):
        self.private_key_path = os.path.join(path, "private_key.key")
        self.public_key_path = os.path.join(path, "public_key.key")

        # Write private key to file
        with open(self.private_key_path, 'wb') as content_file:
            chmod(self.private_key_path, 0o600)  # -rw------- permissions 
            content_file.write(self.private_key_PEM)

        # Write public key to file
        with open(self.public_key_path, 'wb') as content_file:
            content_file.write(self.public_key_PEM)

if __name__ == "__main__":
    cipher = assymetric()
    cipher.generate_keys()
    print(cipher.private_key_PEM.decode('utf-8'))
    print(cipher.public_key_PEM.decode('utf-8'))
    
    # Test encryption and decryption
    test_data = b"Test message to encrypt and decrypt"
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)
    print(f"Original: {test_data}")
    print(f"Decrypted: {decrypted}")