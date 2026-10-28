import os
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


def load_or_create_rsa_keys():
    """Load or create the RSA key pair."""

    os.makedirs(KEYS_DIR, exist_ok=True)

    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )

        with open(PUBLIC_KEY_PATH, "rb") as file:
            public_key = serialization.load_pem_public_key(file.read())

        return private_key, public_key

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(PUBLIC_KEY_PATH, "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key, public_key


def encrypt_file_data(file_data):
    """Encrypt file bytes using AES-256-GCM and RSA-OAEP."""

    _, public_key = load_or_create_rsa_keys()

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        file_data,
        None
    )

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "encrypted_aes_key": encrypted_aes_key
    }


def decrypt_file_data(ciphertext, nonce, encrypted_aes_key):
    """Decrypt file bytes using the RSA-protected AES key."""

    private_key, _ = load_or_create_rsa_keys()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext


if __name__ == "__main__":
    original_data = b"Welcome to CipherVault! Hybrid encryption test."

    encrypted = encrypt_file_data(original_data)

    decrypted = decrypt_file_data(
        encrypted["ciphertext"],
        encrypted["nonce"],
        encrypted["encrypted_aes_key"]
    )

    assert original_data == decrypted

    print("Hybrid encryption test passed!")
    print("AES algorithm: AES-256-GCM")
    print("Key protection: RSA-OAEP with SHA-256")
    print("Decrypted data matches original data.")