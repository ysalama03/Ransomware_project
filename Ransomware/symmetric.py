import base64
import hashlib
import os

import generate_keys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class AESCipher(object):

    def __init__(self, key):
        self.bs = 32  # Block size in bytes
        # Convert key to bytes if it's not already
        if isinstance(key, str):
            key = key.encode('utf-8')
        # Hash the key to get a 32-byte key
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        # Convert to bytes if string
        if isinstance(raw, str):
            raw = raw.encode('utf-8')
            
        # Apply padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(raw) + padder.finalize()
        
        # Generate random IV
        iv = os.urandom(16)  # 16 bytes = 128 bits, standard for AES
        
        # Create encryptor
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext)

    def decrypt(self, enc, decryption_key=None):
        # Update key if a new one is provided
        if decryption_key:
            if isinstance(decryption_key, str):
                decryption_key = decryption_key.encode('utf-8')
            self.key = hashlib.sha256(decryption_key).digest()
            
        # Base64 decode
        enc = base64.b64decode(enc)
        
        # Extract IV (first 16 bytes)
        iv = enc[:16]
        ciphertext = enc[16:]
        
        # Create decryptor
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Return as string
        return data

if __name__ == "__main__":
    key = generate_keys.generate_key(32, True)
    cipher_obj = AESCipher(key)
    print("key: {}".format(key))
    
    # Test encryption (convert to bytes if needed)
    plaintext = "TEST CRYPT"
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    enc = cipher_obj.encrypt(plaintext)
    print("Encrypted:", enc)

    # Test decryption
    back = cipher_obj.decrypt(enc, key)
    print("Decrypted:", back.decode('utf-8'))