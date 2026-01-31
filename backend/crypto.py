#backend/crypto.py
from cryptography.fernet import Fernet

# Generate key (for demo purpose only)
KEY = Fernet.generate_key()
fernet = Fernet(KEY)

def encrypt_data(data: str) -> bytes:
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes) -> str:
    return fernet.decrypt(encrypted_data).decode()
