def vigenere_encrypt(plaintext: str, key: str) -> str:
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""

    key_index = 0
    key_length = len(key)

    for char in plaintext:
        if char.isalpha():
            # Shift letter by key
            shift = ord(key[key_index % key_length]) - ord('A')
            cipher_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += cipher_char
            key_index += 1
        else:
            # Keep non-alphabet characters unchanged
            ciphertext += char

    return ciphertext


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""

    key_index = 0
    key_length = len(key)

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('A')
            plain_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            plaintext += plain_char
            key_index += 1
        else:
            plaintext += char

    return plaintext


# =========================
# Example usage
# =========================

if __name__ == "__main__":
    text = input("saisir:")
    key = "KEY"

    cipher = vigenere_encrypt(text, key)
    print("Encrypted:", cipher)

    decrypted = vigenere_decrypt(cipher, key)
    print("Decrypted:", decrypted)
