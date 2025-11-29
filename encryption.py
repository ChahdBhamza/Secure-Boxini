from __future__ import annotations

import base64
import os
import ast
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
    """Create a new AES key encoded with url-safe base64 for easy storage."""
    raw_key = AESGCM.generate_key(bit_length=KEY_BITS)
    return base64.urlsafe_b64encode(raw_key).decode("utf-8")


def _ensure_bytes(value: Optional[Any]) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def encrypt(plaintext: Any, key_b64: str, *, associated_data: Any = None) -> EncryptedPayload:
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
#   FILE ENCRYPTION TEST (YOU CAN EDIT THIS PART ONLY)
# ============================================================

# Choose the file you want to encrypt
input_file = "example.pdf"       # <== CHANGE THIS
encrypted_file = "example.enc"
decrypted_file = "example_decrypted.pdf"

# Generate AES key
key = generate_key()
print("KEY:", key)

# 1. Read file as bytes
with open(input_file, "rb") as f:
    original_data = f.read()

# 2. Encrypt file bytes
encrypted = encrypt(original_data, key)

# 3. Save encrypted dictionary to file
with open(encrypted_file, "w") as f:
    f.write(str(encrypted.as_dict()))

print("File encrypted →", encrypted_file)

# 4. Read encrypted file back
with open(encrypted_file, "r") as f:
    payload_dict = ast.literal_eval(f.read())

# 5. Decrypt bytes
decrypted_bytes = decrypt(payload_dict, key)

# 6. Save decrypted file
with open(decrypted_file, "wb") as f:
    f.write(decrypted_bytes)

print("File decrypted →", decrypted_file)
