"""
Image encryption module using AES-EAX encryption.
Refactored to provide reusable functions for Flask integration.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import numpy as np
from PIL import Image, ImageOps
import io
from typing import Dict, Tuple


# ============================================================
#   Reusable Functions for Flask Integration
# ============================================================

def encrypt_image(image_bytes: bytes) -> Tuple[bytes, bytes, Dict]:
    """
    Encrypt an image file using AES-EAX encryption.
    
    Args:
        image_bytes: Raw image file bytes (JPEG, PNG, etc.)
    
    Returns:
        Tuple of (encrypted_data, encryption_key, metadata)
        - encrypted_data: Encrypted pixel data as bytes
        - encryption_key: Unique 16-byte AES key for this image
        - metadata: Dict with width, height, data_length, nonce, tag
    """
    # Generate unique key for this image
    key = get_random_bytes(16)  # 128-bit key
    
    # Load and prepare image
    img = Image.open(io.BytesIO(image_bytes))
    img = ImageOps.exif_transpose(img)  # Handle EXIF orientation
    img = img.convert("RGB")  # Ensure RGB format
    
    width, height = img.size
    
    # Convert to raw pixel data
    pixel_data = np.array(img).tobytes()
    data_length = len(pixel_data)
    
    # Encryption
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(pixel_data)
    
    # Store metadata
    metadata = {
        "width": width,
        "height": height,
        "data_length": data_length,
        "nonce": nonce.hex(),  # Convert to hex for JSON storage
        "tag": tag.hex()
    }
    
    return ciphertext, key, metadata


def decrypt_image(ciphertext: bytes, key: bytes, metadata: Dict) -> bytes:
    """
    Decrypt an encrypted image and return as PNG bytes.
    
    Args:
        ciphertext: Encrypted pixel data
        key: 16-byte AES key used for encryption
        metadata: Dict with width, height, data_length, nonce, tag
    
    Returns:
        Decrypted image as PNG bytes (ready to serve or save)
    """
    # Extract metadata
    width = metadata["width"]
    height = metadata["height"]
    data_length = metadata["data_length"]
    nonce = bytes.fromhex(metadata["nonce"])
    tag = bytes.fromhex(metadata["tag"])
    
    # Decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Verify data length
    if len(decrypted_data) != data_length:
        raise ValueError(f"Decrypted data length mismatch: expected {data_length}, got {len(decrypted_data)}")
    
    # Reconstruct image
    restored_pixels = np.frombuffer(decrypted_data, dtype=np.uint8).reshape((height, width, 3))
    restored_img = Image.fromarray(restored_pixels, 'RGB')
    
    # Convert to PNG bytes
    output = io.BytesIO()
    restored_img.save(output, format='PNG')
    return output.getvalue()


def is_image_file(mime_type: str, filename: str = "") -> bool:
    """
    Check if a file is an image based on MIME type or filename.
    
    Args:
        mime_type: MIME type string (e.g., 'image/jpeg')
        filename: Optional filename for fallback check
    
    Returns:
        True if file is an image, False otherwise
    """
    # Check MIME type
    if mime_type and mime_type.startswith('image/'):
        return True
    
    # Fallback: check file extension
    if filename:
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.svg']
        return any(filename.lower().endswith(ext) for ext in image_extensions)
    
    return False


# ============================================================
#   Original Test Code (Standalone Usage)
# ============================================================

if __name__ == "__main__":
    # Original standalone encryption/decryption test
    import os
    
    # Check if test image exists
    if not os.path.exists("cupp.jpg"):
        print("Test image 'cupp.jpg' not found. Creating a test image...")
        # Create a simple test image
        test_img = Image.new('RGB', (200, 200), color='red')
        test_img.save("cupp.jpg")
    
    key = get_random_bytes(16)  # 128-bit key

    # Load and prepare image
    original_img = Image.open("cupp.jpg")
    original_img = ImageOps.exif_transpose(original_img)
    original_img = original_img.convert("RGB")

    width, height = original_img.size
    print(f"Original image size: {width}x{height}")

    # Convert to raw pixel data
    pixel_data = np.array(original_img).tobytes()
    data_length = len(pixel_data)
    print(f"Pixel data size: {data_length} bytes")

    # Encryption
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    ciphertext, tag = cipher.encrypt_and_digest(pixel_data)

    # Save encrypted data (with metadata for decryption)
    with open("boom.jpg.enc", "wb") as f:
        # Save dimensions, data length, nonce, tag, then ciphertext
        f.write(width.to_bytes(4, 'big'))
        f.write(height.to_bytes(4, 'big'))
        f.write(data_length.to_bytes(4, 'big'))
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    print(f"Encrypted. Nonce length: {len(cipher.nonce)}")

    # Create visualization of encrypted pixel data
    encrypted_pixels = np.frombuffer(ciphertext, dtype=np.uint8)
    # Pad to match original size if needed
    if len(encrypted_pixels) < width * height * 3:
        encrypted_pixels = np.pad(encrypted_pixels, (0, width * height * 3 - len(encrypted_pixels)))
    else:
        encrypted_pixels = encrypted_pixels[:width * height * 3]

    encrypted_visual = encrypted_pixels.reshape((height, width, 3))
    Image.fromarray(encrypted_visual, 'RGB').save("encrypted_visual.png")
    print(f"Saved encrypted visualization to encrypted_visual.png")

    # Decryption
    with open("boom.jpg.enc", "rb") as f:
        width_read = int.from_bytes(f.read(4), 'big')
        height_read = int.from_bytes(f.read(4), 'big')
        data_length_read = int.from_bytes(f.read(4), 'big')
        nonce_read = f.read(16)
        tag_read = f.read(16)
        ciphertext_read = f.read()

    print(f"Decrypting: {width_read}x{height_read}, {data_length_read} bytes")

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce_read)
    decrypted_data = cipher.decrypt_and_verify(ciphertext_read, tag_read)

    # Verify we got the right amount of data
    if len(decrypted_data) != data_length_read:
        print(f"WARNING: Expected {data_length_read} bytes, got {len(decrypted_data)}")

    # Reconstruct image
    restored_pixels = np.frombuffer(decrypted_data[:data_length_read], dtype=np.uint8).reshape((height_read, width_read, 3))
    restored_img = Image.fromarray(restored_pixels, 'RGB')
    restored_img.save("restored.png")

    print("Decryption successful. Saved to restored.png")
