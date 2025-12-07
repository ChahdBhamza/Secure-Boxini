"""
File encryption module using AES-GCM encryption.

"""

from __future__ import annotations

import base64
import os
import ast
from dataclasses import dataclass
from typing import Any, Dict, Optional


NONCE_SIZE = 12  # Recommended size for AES-GCM
KEY_BITS = 256   # 32-byte key


@dataclass(frozen=True)
class EncryptedPayload:
    """Serialized AES-GCM payload ready for persistence or transport."""

    nonce: str
    ciphertext: str

    def as_dict(self) -> Dict[str, str]:
        return {"nonce": self.nonce, "ciphertext": self.ciphertext}


def generate_key() -> str:
    """Generate a new AES-256 key and return as base64 string."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw_key = AESGCM.generate_key(bit_length=KEY_BITS)
    return base64.urlsafe_b64encode(raw_key).decode("utf-8")


def _ensure_bytes(value: Optional[Any]) -> Optional[bytes]:
    """Convert value to bytes if it's not already."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def encrypt(plaintext: Any, key_b64: str, *, associated_data: Any = None) -> EncryptedPayload:
    """
    Encrypt plaintext using AES-GCM.
    
    Args:
        plaintext: Data to encrypt (string or bytes)
        key_b64: Base64-encoded AES key
        associated_data: Optional associated data for authentication

    Returns:
        EncryptedPayload with nonce and ciphertext
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    plaintext_bytes = _ensure_bytes(plaintext)
    aad = _ensure_bytes(associated_data)

    key = base64.urlsafe_b64decode(key_b64)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return EncryptedPayload(
        nonce=base64.urlsafe_b64encode(nonce).decode("utf-8"),
        ciphertext=base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
    )


def decrypt(payload: EncryptedPayload | Dict[str, str], key_b64: str, *, associated_data: Any = None) -> bytes:
    """
    Decrypt an EncryptedPayload using AES-GCM.
    
    Args:
        payload: EncryptedPayload or dict with 'nonce' and 'ciphertext'
        key_b64: Base64-encoded AES key
        associated_data: Same AAD used during encryption
    
    Returns:
        Decrypted bytes
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    if isinstance(payload, dict):
        nonce_b64 = payload["nonce"]
        ciphertext_b64 = payload["ciphertext"]
    else:
        nonce_b64 = payload.nonce
        ciphertext_b64 = payload.ciphertext

    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    key = base64.urlsafe_b64decode(key_b64)
    aad = _ensure_bytes(associated_data)

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ============================================================
#   Reusable Functions for Flask Integration
# ============================================================

def encrypt_file(file_bytes: bytes, key_b64: str = None) -> tuple[EncryptedPayload, str]:
    """
    Encrypt file bytes using AES-GCM.
    
    Args:
        file_bytes: Raw file bytes to encrypt
        key_b64: Optional base64 key (generates new one if not provided)
    
    Returns:
        Tuple of (EncryptedPayload, key_b64)
    """
    if key_b64 is None:
        key_b64 = generate_key()
    
    encrypted_payload = encrypt(file_bytes, key_b64)
    return encrypted_payload, key_b64


def decrypt_file(payload: EncryptedPayload | Dict[str, str], key_b64: str) -> bytes:
    """
    Decrypt encrypted file data.
    
    Args:
        payload: EncryptedPayload or dict with nonce and ciphertext
        key_b64: Base64-encoded AES key
    
    Returns:
        Decrypted file bytes
    """
    return decrypt(payload, key_b64)


# ============================================================
#   Original Test Code (Standalone Usage)
# ============================================================

if __name__ == "__main__":
    # Original standalone file encryption/decryption test
    
    input_file = "res.pdf"          # file to encrypt
    encrypted_file = "resencrypted.pdf"      # encrypted output file
    decrypted_file = "resdecrypted.pdf"      # decrypted output file

    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Test file '{input_file}' not found. Creating a test file...")
        # Create a simple test file
        with open(input_file, "wb") as f:
            f.write(b"This is a test PDF content for encryption.")

    # Generate AES key
    key = generate_key()
    print("AES KEY:", key)

    # 1. Read original file
    with open(input_file, "rb") as f:
        original_data = f.read()

    # 2. Encrypt file
    encrypted = encrypt(original_data, key)

    # 3. Save encrypted dictionary
    with open(encrypted_file, "w") as f:
        f.write(str(encrypted.as_dict()))

    print("File encrypted →", encrypted_file)

    # 4. Load encrypted content
    with open(encrypted_file, "r") as f:
        payload_dict = ast.literal_eval(f.read())

    # 5. Decrypt file
    decrypted_bytes = decrypt(payload_dict, key)

    # 6. Save decrypted file
    with open(decrypted_file, "wb") as f:
        f.write(decrypted_bytes)

    print("File decrypted →", decrypted_file)
