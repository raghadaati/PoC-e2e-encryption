import socket
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend

# Key Generation (Server Side)
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()

# Serialize public key
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Start server


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(1)
    print("[SERVER] Waiting for connection...")
    conn, addr = server.accept()
    print(f"[SERVER] Connected to {addr}")

    # Send public key to client
    conn.send(server_public_pem)

    # Receive client's public key
    client_public_pem = conn.recv(1024)
    client_public_key = load_pem_public_key(
        client_public_pem, backend=default_backend())

    # Thread for receiving messages
    def receive_messages():
        while True:
            try:
                encrypted_message = conn.recv(1024)
                if encrypted_message:
                    # Decrypt message
                    decrypted_message = server_private_key.decrypt(
                        encrypted_message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print(f"[CLIENT]: {decrypted_message.decode()}")
            except:
                break

    # Thread for sending messages
    def send_messages():
        while True:
            message = input("[YOU]: ").encode()
            encrypted_message = client_public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            conn.send(encrypted_message)

    # Start threads
    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)
    receive_thread.start()
    send_thread.start()


start_server()
