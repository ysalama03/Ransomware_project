import os
import platform
import socket
import getpass
import uuid

def get_username():
    return getpass.getuser()

def get_home_path():
    return os.path.expanduser("~")

def get_desktop_path():
    return os.path.join(get_home_path(), "Desktop")

def get_documents_path():
    return os.path.join(get_home_path(), "Documents")
    

def get_unique_machine_id():
    """Get a unique identifier for the current machine"""
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 2*6, 8)][::-1])
    hostname = socket.gethostname()
    return f"{hostname}-{mac_address}"

