import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_service import load_or_create_rsa_keys


def sign_manifest(manifest):
    """Sign a manifest using RSA-PSS and SHA-256."""

    private_key, _ = load_or_create_rsa_keys()

    manifest_bytes = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    signature = private_key.sign(
        manifest_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature.hex()


def verify_manifest(manifest, signature_hex):
    """Verify a manifest signature using the RSA public key."""

    _, public_key = load_or_create_rsa_keys()

    manifest_bytes = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    try:
        signature = bytes.fromhex(signature_hex)

        public_key.verify(
            signature,
            manifest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except (ValueError, TypeError):
        return False

    except Exception as error:
        # Invalid signatures raise InvalidSignature.
        from cryptography.exceptions import InvalidSignature

        if isinstance(error, InvalidSignature):
            return False

        raise


if __name__ == "__main__":
    sample_manifest = {
        "filename": "sample_upload.txt",
        "size_bytes": 59,
        "encryption": "AES-256-GCM"
    }

    signature = sign_manifest(sample_manifest)

    print("Signature created successfully.")
    print("Valid signature:", verify_manifest(sample_manifest, signature))

    modified_manifest = sample_manifest.copy()
    modified_manifest["filename"] = "modified.txt"

    print(
        "Modified manifest accepted:",
        verify_manifest(modified_manifest, signature)
    )