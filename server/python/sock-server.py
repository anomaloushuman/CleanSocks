#   Created by anomaloushuman - Patrick Garcia
#   Email - patrick@ubiquityglass.com
#   12/19/2024 - Sock Server v0.0.1

import socket
import ssl
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

server_key = b'your-very-secure-key'  # Shared secret key for HMAC and encryption

# TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/path/to/server_cert.pem', '/path/to/server_key.pem')
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('/path/to/ca_cert.pem')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 9000))
server_socket.listen()

print("Secure protocol server started on port 9000")

while True:
    conn, addr = server_socket.accept()
    with context.wrap_socket(conn, server_side=True) as s:
        print("Client connected")

        # Handshake
        s.sendall(b"HELLO CLIENT\r\n")
        response = s.recv(1024).decode().strip()
        if response != "HELLO SERVER":
            s.sendall(b"ERROR: INVALID HANDSHAKE\r\n")
            continue

        s.sendall(b"HANDSHAKE COMPLETE\r\n")

        while True:
            data = s.recv(2048).decode().strip()
            hmac, encrypted_message = data.split(":", 1)

            # Verify HMAC
            if not verify_hmac(encrypted_message, hmac, server_key):
                s.sendall(b"ERROR: INVALID MESSAGE\r\n")
                break

            # Decrypt the message
            message = decrypt_message(encrypted_message, server_key)
            print(f"Received: {message}")

            response = f"You sent: {message}"
            encrypted_response = encrypt_message(response, server_key)
            hmac = generate_hmac(encrypted_response, server_key)

            s.sendall(f"{hmac}:{encrypted_response}\r\n".encode())

        print("Client disconnected")

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(data, key):
    data = base64.b64decode(data)
    iv = data[:16]
    encrypted = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    padded_unpadded = unpadder.update(decrypted_padded) + unpadder.finalize()
    return padded_unpadded.decode()

def generate_hmac(data, key):
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data, hmac, key):
    return hmac == generate_hmac(data, key)