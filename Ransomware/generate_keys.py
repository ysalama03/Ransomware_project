import os
import base64

def generate_key(size=32, encode=False):
    """
    Generate a random key of specified size
    
    Args:
        size (int): Size of the key in bytes
        encode (bool): Whether to base64 encode the key
        
    Returns:
        bytes or str: Generated key
    """
    # Generate random bytes using os.urandom
    key = os.urandom(size)
    
    # Encode if requested
    if encode:
        return base64.b64encode(key).decode('utf-8')
    return key
    
if __name__ == "__main__":
    # Test the function
    key_32 = generate_key(32, True)
    print(f"32-byte key (encoded): {key_32}")
    
    key_16 = generate_key(16, False)
    print(f"16-byte key (raw): {key_16}")
    print(f"16-byte key (hex): {key_16.hex()}")