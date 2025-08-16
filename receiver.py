import socket
from Crypto.Cipher import AES
from tqdm import tqdm

# Configuration
HOST = "localhost"
PORT = 23809
KEY = b"AnushaKaveeraKey"  # Must match sender
NONCE = b"UniqueNonce12"   # Must match sender
BUFFER_SIZE = 4096

def receive_file():
    """Receive and decrypt file from client"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        
        print(f"Server listening on {HOST}:{PORT}")
        client, addr = server.accept()
        
        with client:
            print(f"Connected by {addr}")
            
            # Receive metadata
            fname_len = int.from_bytes(client.recv(2), 'big')  # Filename length (2 bytes)
            file_name = client.recv(fname_len).decode()       # Filename
            file_size = int.from_bytes(client.recv(8), 'big')  # File size (8 bytes)
            tag = client.recv(16)                             # AES tag (16 bytes)
            
            # Receive encrypted data
            ciphertext = b""
            progress = tqdm(total=file_size, unit='B', unit_scale=True, desc="Receiving")
            
            while len(ciphertext) < file_size:
                bytes_left = file_size - len(ciphertext)
                data = client.recv(min(BUFFER_SIZE, bytes_left))
                if not data:
                    break
                ciphertext += data
                progress.update(len(data))
            
            progress.close()
            
            # Decrypt and verify
            cipher = AES.new(KEY, AES.MODE_EAX, nonce=NONCE)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                # Save file
                with open(file_name, "wb") as f:
                    f.write(plaintext)
                
                print(f"File successfully saved as '{file_name}'")
                return True
                
            except ValueError as e:
                print(f"Decryption failed: {e}")
                return False

if __name__ == "__main__":
    receive_file()