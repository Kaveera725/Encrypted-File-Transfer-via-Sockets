import os
import socket
import time
from Crypto.Cipher import AES

# Configuration
HOST = "localhost"
PORT = 23809
KEY = b"AnushaKaveeraKey"  # 16 bytes for AES-128
NONCE = b"UniqueNonce12"    # 13 bytes (must be unique per message)

def encrypt_file(file_path, output_name):
    """Encrypt file and return ciphertext and tag"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found")
    
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=NONCE)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return output_name, ciphertext, tag

def send_file(file_path, output_name="received_file.txt"):
    """Send encrypted file to server"""
    file_name, ciphertext, tag = encrypt_file(file_path, output_name)
    
    # Connect to server with retries
    for attempt in range(10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect((HOST, PORT))
                
                # Send metadata
                client.sendall(len(file_name).to_bytes(2, 'big'))  # Filename length (2 bytes)
                client.sendall(file_name.encode())                 # Filename
                client.sendall(len(ciphertext).to_bytes(8, 'big')) # File size (8 bytes)
                client.sendall(tag)                                # AES tag (16 bytes)
                
                # Send encrypted data
                client.sendall(ciphertext)
                
                print(f"File '{file_path}' sent successfully as '{file_name}'")
                return True
                
        except ConnectionRefusedError:
            print(f"Connection attempt {attempt + 1}/10 failed, retrying...")
            time.sleep(1)
    
    print("Failed to connect after 10 attempts")
    return False

if __name__ == "__main__":
    send_file("file", "file.txt")