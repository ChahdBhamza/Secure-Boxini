import random
import string

def passwordhash_chaos_3589(password, salt=None, shift=None):
    """
    Core hashing algorithm with optional salt and shift parameters.
    If salt and shift are not provided, they will be generated randomly.
    """
    # Étape 1 : Majuscules
    pwd = password.upper()

    # Étape 2 & 3 : Salt + Shift (use provided or generate new)
    if salt is None:
        salt = ''.join(random.choices(string.ascii_uppercase + string.digits, k=18))
    if shift is None:
        shift = random.randint(1, 25)

    # Étape 4 : Mot de passe → chiffres + shift
    digits = []
    for c in pwd:
        if 'A' <= c <= 'Z':
            val = ord(c) - ord('A') + shift      # A=0 + shift
            digits.append(str(val))
        elif '0' <= c <= '9':
            digits.append(c)
        else:
            digits.append("998")                  # symbole → 998

    big_num = int(''.join(digits))

    # Étape 5 : Salt → grand nombre
    salt_num = 0
    for c in salt:
        salt_num = salt_num * 1000 + ord(c)      # chaque caractère → gros nombre

    # Étape 6 : Première combinaison
    combine = (big_num * 1337) + (salt_num * 31337)

    # Étape 7 : Two's complement 512 bits du salt_num (forcé négatif)
    BIT = 512
    salt_twos = salt_num % (1 << BIT)            # dans 512 bits
    if not (salt_twos & (1 << (BIT-1))):         # si bit de signe = 0
        salt_twos |= (1 << (BIT-1))              # on le force à 1 → négatif

    # Étape 8 : Multiplication + Modulo
    MOD = 15789463
    temp = (salt_twos * 3589) % MOD

    # Étape 9 : XOR final
    final_number = temp ^ combine

    # Étape 10 : Sortie en HEXADÉCIMAL (majuscules)
    final_hex = hex(final_number)[2:].upper()

    return {
        "hash": final_hex,
        "salt": salt,
        "shift": shift
    }


def hash_password(password):
    """
    Hash a password and return a combined string containing hash, salt, and shift.
    Format: {hash}${salt}${shift}
    """
    result = passwordhash_chaos_3589(password)
    return f"{result['hash']}${result['salt']}${result['shift']}"


def verify_password(password, stored_hash):
    """
    Verify a password against a stored hash.
    
    Args:
        password: The password to verify
        stored_hash: The stored hash in format {hash}${salt}${shift}
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        # Extract hash, salt, and shift from stored hash
        parts = stored_hash.split('$')
        if len(parts) != 3:
            return False
        
        stored_hash_value, salt, shift = parts
        shift = int(shift)
        
        # Hash the provided password with the stored salt and shift
        result = passwordhash_chaos_3589(password, salt=salt, shift=shift)
        
        # Compare the hashes
        return result['hash'] == stored_hash_value
    except (ValueError, IndexError, KeyError):
        return False
