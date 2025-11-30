"""
Database encryption helpers for MongoDB integration.

This module provides functions to encrypt/decrypt sensitive data before
storing in MongoDB, using the AES-GCM encryption from encryption.py.
"""

from aessfile import encrypt, decrypt, generate_key
import os
# Get master key from environment
MASTER_KEY = os.getenv("MASTER_ENCRYPTION_KEY")

if not MASTER_KEY:
    raise ValueError(
        "MASTER_ENCRYPTION_KEY environment variable is required. "
        "Set it in your .env file or environment."
    )


def encrypt_field(value: str | bytes, associated_data: str | None = None) -> Dict[str, str]:
    """
    Encrypt a field value for MongoDB storage.
    
    Args:
        value: String or bytes to encrypt
        associated_data: Optional AAD (e.g., user_id for context binding)
    
    Returns:
        Dict with 'nonce' and 'ciphertext' (ready for MongoDB storage)
    
    Example:
        >>> encrypted = encrypt_field("sensitive_data", associated_data="user:123")
        >>> users_col.update_one(
        ...     {"user_id": "123"},
        ...     {"$set": {"secret_encrypted": encrypted}}
        ... )
    """
    payload = encrypt(value, MASTER_KEY, associated_data=associated_data)
    return payload.as_dict()


def decrypt_field(encrypted_data: Dict[str, str], associated_data: str | None = None) -> bytes:
    """
    Decrypt a field value from MongoDB.
    
    Args:
        encrypted_data: Dict with 'nonce' and 'ciphertext' from MongoDB
        associated_data: Same AAD used during encryption
    
    Returns:
        Decrypted bytes (decode to string if needed)
    
    Example:
        >>> user = users_col.find_one({"user_id": "123"})
        >>> encrypted = user.get("secret_encrypted")
        >>> decrypted = decrypt_field(encrypted, associated_data="user:123")
        >>> secret = decrypted.decode('utf-8')
    """
    return decrypt(encrypted_data, MASTER_KEY, associated_data=associated_data)


# ============================================================
#   User-Specific Encryption Helpers
# ============================================================

def encrypt_totp_secret(user_id: str, totp_secret: str) -> Dict[str, str]:
    """
    Encrypt TOTP secret with user_id as AAD.
    
    This binds the encryption to the specific user, preventing
    encrypted secrets from being swapped between users.
    """
    aad = f"totp_secret:user_id:{user_id}"
    return encrypt_field(totp_secret, associated_data=aad)


def decrypt_totp_secret(user_id: str, encrypted_data: Dict[str, str]) -> str:
    """Decrypt TOTP secret."""
    aad = f"totp_secret:user_id:{user_id}"
    return decrypt_field(encrypted_data, associated_data=aad).decode('utf-8')


def encrypt_backup_codes(user_id: str, backup_codes: List[str]) -> Dict[str, str]:
    """
    Encrypt backup codes array.
    
    Args:
        user_id: User identifier for AAD
        backup_codes: List of backup code strings
    
    Returns:
        Encrypted payload dict
    """
    codes_json = json.dumps(backup_codes)
    aad = f"backup_codes:user_id:{user_id}"
    return encrypt_field(codes_json, associated_data=aad)


def decrypt_backup_codes(user_id: str, encrypted_data: Dict[str, str]) -> List[str]:
    """Decrypt backup codes array."""
    aad = f"backup_codes:user_id:{user_id}"
    codes_json = decrypt_field(encrypted_data, associated_data=aad).decode('utf-8')
    return json.loads(codes_json)


def encrypt_reset_token(user_id: str, token: str) -> Dict[str, str]:
    """Encrypt password reset token."""
    aad = f"reset_token:user_id:{user_id}"
    return encrypt_field(token, associated_data=aad)


def decrypt_reset_token(user_id: str, encrypted_data: Dict[str, str]) -> str:
    """Decrypt password reset token."""
    aad = f"reset_token:user_id:{user_id}"
    return decrypt_field(encrypted_data, associated_data=aad).decode('utf-8')


# ============================================================
#   File Encryption Helpers
# ============================================================

def encrypt_file_key(file_id: str, file_key: str) -> Dict[str, str]:
    """
    Encrypt a file-specific encryption key with master key.
    
    Each file can have its own encryption key, which is then
    encrypted with the master key for storage.
    """
    aad = f"file_key:file_id:{file_id}"
    return encrypt_field(file_key, associated_data=aad)


def decrypt_file_key(file_id: str, encrypted_data: Dict[str, str]) -> str:
    """Decrypt file-specific encryption key."""
    aad = f"file_key:file_id:{file_id}"
    return decrypt_field(encrypted_data, associated_data=aad).decode('utf-8')


def encrypt_file_content(file_content: bytes, file_key: str, user_id: str, filename: str) -> Dict[str, str]:
    """
    Encrypt file content with file-specific key.
    
    Args:
        file_content: Raw file bytes
        file_key: File-specific encryption key (from generate_key())
        user_id: User identifier for AAD
        filename: Filename for AAD
    
    Returns:
        Encrypted payload dict with nonce and ciphertext
    """
    aad = f"file_content:user_id:{user_id}:filename:{filename}"
    payload = encrypt(file_content, file_key, associated_data=aad)
    return payload.as_dict()


def decrypt_file_content(
    encrypted_data: Dict[str, str],
    file_key: str,
    user_id: str,
    filename: str
) -> bytes:
    """Decrypt file content."""
    aad = f"file_content:user_id:{user_id}:filename:{filename}"
    return decrypt(encrypted_data, file_key, associated_data=aad)


# ============================================================
#   Session/Token Encryption
# ============================================================

def encrypt_session_data(session_id: str, session_data: Dict[str, Any]) -> Dict[str, str]:
    """Encrypt session data."""
    session_json = json.dumps(session_data)
    aad = f"session:session_id:{session_id}"
    return encrypt_field(session_json, associated_data=aad)


def decrypt_session_data(session_id: str, encrypted_data: Dict[str, str]) -> Dict[str, Any]:
    """Decrypt session data."""
    aad = f"session:session_id:{session_id}"
    session_json = decrypt_field(encrypted_data, associated_data=aad).decode('utf-8')
    return json.loads(session_json)


# ============================================================
#   Usage Examples
# ============================================================

if __name__ == "__main__":
    # Example: Encrypt TOTP secret
    user_id = "usr_abc123"
    totp_secret = "JBSWY3DPEHPK3PXP"
    
    print("Encrypting TOTP secret...")
    encrypted = encrypt_totp_secret(user_id, totp_secret)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = decrypt_totp_secret(user_id, encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == totp_secret}")
    
    # Example: Encrypt backup codes
    backup_codes = ["CODE123", "CODE456", "CODE789"]
    encrypted_codes = encrypt_backup_codes(user_id, backup_codes)
    print(f"\nEncrypted backup codes: {encrypted_codes}")
    
    decrypted_codes = decrypt_backup_codes(user_id, encrypted_codes)
    print(f"Decrypted backup codes: {decrypted_codes}")
    print(f"Match: {decrypted_codes == backup_codes}")



