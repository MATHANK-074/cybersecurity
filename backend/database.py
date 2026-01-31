# Simulated database (in-memory)
# backend/database.py
database = {}

def save_record(record_id: str, encrypted_data: bytes):
    database[record_id] = encrypted_data

def get_record(record_id: str):
    return database.get(record_id)
