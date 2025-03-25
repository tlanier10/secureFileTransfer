# Secure File Transfer and Broadcast System

## Overview
This project implements a secure file transfer and broadcast system using Python. It includes functionality for broadcasting messages, listening for messages, encrypting and decrypting data, signing data, and securely transferring files over a network.

## Features
- **UDP Broadcast Messaging**: Sends and listens for broadcast messages.
- **Symmetric Encryption (AES)**: Encrypts and decrypts data securely.
- **Asymmetric Encryption (RSA)**: Encrypts and decrypts data using public/private keys.
- **Digital Signatures**: Ensures data integrity using SHA-256 and RSA signatures.
- **Secure File Transfer**: Encrypts files and sends them over a TCP connection.

## Requirements
Ensure you have the following Python libraries installed:

```sh
pip install pycryptodome password-validator email-validator bcrypt
```

## Usage

### Running the Broadcast System
To start broadcasting and listening for messages, run:

```sh
python main.py
```

This will:
- Start sending broadcast messages every 5 seconds.
- Start listening for incoming broadcast messages on the specified port.

### Encryption & Decryption
To generate an RSA key pair:

```python
private_key, public_key = generate_key_pair()
```

To encrypt and decrypt data using AES:

```python
aes_key = get_random_bytes(16)
encrypted_data = encrypt_data(aes_key, "Sensitive Information")
decrypted_data = decrypt_data(aes_key, encrypted_data)
```

### File Encryption & Transfer
To securely send a file:

```python
send_file(aes_key, "path/to/file.txt", "recipient_ip", recipient_public_key, account_info)
```

To receive and decrypt a file:

```python
receive_file(aes_key, account_info, "save/path", "0.0.0.0", 25256)
```

## Security Considerations
- **AES Key Management**: Ensure AES keys are stored securely and never exposed.
- **Private Key Protection**: Private keys should never be shared.
- **Data Integrity**: Always verify signatures before trusting received data.

## License
This project is open-source and available for use under the MIT License.