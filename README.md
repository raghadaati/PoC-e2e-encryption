# P2P Encrypted Messaging System using End-To-End Encryption

This program demonstrates a basic peer-to-peer (P2P) encrypted messaging system using RSA encryption. The system consists of two main components: a **Server** and a **Client**. Both peers exchange public keys and use them to encrypt and decrypt messages, ensuring secure communication between them.

## Key Features

- **RSA Key Pair Generation**: Both the server and client generate their own RSA key pairs (private and public keys).
- **Public Key Exchange**: Before communication begins, both the server and client exchange their public keys.
- **End-to-End Encryption**: Messages exchanged between the server and client are encrypted using the recipient's public key, ensuring that only the intended recipient can decrypt the message using their private key.
- **Multithreaded Communication**: The system uses multithreading to handle simultaneous sending and receiving of messages, enabling real-time encrypted chat.

## Encryption Process

### Key Generation

- Each peer (server and client) generates an RSA key pair (private and public key). The private key is kept secret, while the public key is shared with the other peer.

### Public Key Exchange

- After establishing a connection, the server sends its public key to the client, and the client responds by sending its public key back to the server.

### Message Encryption

- When sending a message, the sender encrypts the message using the recipient’s public key.
- This ensures that only the recipient, who has the corresponding private key, can decrypt the message.

### Message Decryption

- When receiving a message, the recipient decrypts it using their private key, allowing them to read the message securely.

## How to Run the Program

### Server (Peer 1)

1. Run the server code using Python.
2. The server will wait for a client to connect and will exchange public keys once a connection is established.
3. The server can send and receive encrypted messages to/from the client.

### Client (Peer 2)

1. Run the client code using Python.
2. The client will connect to the server's IP and port, then exchange public keys.
3. The client can send and receive encrypted messages to/from the server.

**Note**: The program uses hardcoded IP `'127.0.0.1'` and port `5555` for local testing. For actual communication across different networks, replace `'127.0.0.1'` with the actual server IP address and ensure the port is open.

## Requirements

- **Python 3.x**
- **`cryptography` Library**: This library is used for RSA encryption and decryption.

### Install the cryptography library:

bash
pip install cryptography

