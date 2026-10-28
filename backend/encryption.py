import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key():
    """Generate a secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(input_path, output_path, key):
    """Encrypt a file using AES-256-GCM."""
    with open(input_path, "rb") as file:
        plaintext = file.read()

    # Generate a unique 12-byte nonce for this encryption.
    nonce = secrets.token_bytes(12)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as file:
        file.write(nonce + ciphertext)

    print("File encrypted successfully!")


def decrypt_file(input_path, output_path, key):
    """Decrypt an AES-256-GCM encrypted file."""
    with open(input_path, "rb") as file:
        encrypted_data = file.read()

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(key)

    # Authentication fails if the ciphertext or key is incorrect.
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as file:
        file.write(plaintext)

    print("File decrypted successfully!")


if __name__ == "__main__":
    # Demonstration: encrypt and decrypt a sample file.
    sample_path = "sample.txt"
    encrypted_path = "sample.enc"
    decrypted_path = "decrypted_sample.txt"

    with open(sample_path, "w", encoding="utf-8") as file:
        file.write("Welcome to CipherVault! This is a secret file.")

    key = generate_key()

    encrypt_file(sample_path, encrypted_path, key)
    decrypt_file(encrypted_path, decrypted_path, key)

    print("\nOriginal and decrypted files should contain identical text.")
    print("Encryption test completed.")
