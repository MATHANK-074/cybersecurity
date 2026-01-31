# backend/access_control.py
import time
import uuid

active_tokens = {}

def generate_access_token():
    token = str(uuid.uuid4())
    expiry_time = time.time() + 10  # 10 seconds
    active_tokens[token] = expiry_time
    return token

def validate_token(token: str) -> bool:
    if token not in active_tokens:
        return False

    if time.time() > active_tokens[token]:
        del active_tokens[token]
        return False

    # One-time access
    del active_tokens[token]
    return True
