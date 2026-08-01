"""
Symmetric encryption for confidential records "at rest".

Uses Fernet (AES-128 in CBC mode + HMAC for integrity) from the
`cryptography` library. This satisfies the proposal's requirement
for "encryption of stored data" without hand-rolling crypto.
"""
from cryptography.fernet import Fernet

# In production, load this from a secrets manager / KMS, not a source file.
# Generate once with Fernet.generate_key() and persist it securely.
_KEY_FILE = "backend/data/encryption.key"


def _load_or_create_key() -> bytes:
    import os
    os.makedirs("backend/data", exist_ok=True)
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return _fernet.decrypt(ciphertext.encode()).decode()
