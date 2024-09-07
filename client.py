import socket
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend

# Key Generation (Client Side)
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
client_public_key = client_private_key.public_key()

# Serialize public key
client_public_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Start client


def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5555))

    # Receive server's public key
    server_public_pem = client.recv(1024)
    server_public_key = load_pem_public_key(
        server_public_pem, backend=default_backend())

    # Send public key to server
    client.send(client_public_pem)

    # Thread for receiving messages
    def receive_messages():
        while True:
            try:
                encrypted_message = client.recv(1024)
                if encrypted_message:
                    # Decrypt message
                    decrypted_message = client_private_key.decrypt(
                        encrypted_message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print(f"[SERVER]: {decrypted_message.decode()}")
            except:
                break

    # Thread for sending messages
    def send_messages():
        while True:
            message = input("[YOU]: ").encode()
            encrypted_message = server_public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client.send(encrypted_message)

    # Start threads
    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)
    receive_thread.start()
    send_thread.start()


start_client()
