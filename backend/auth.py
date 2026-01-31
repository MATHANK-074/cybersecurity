# backend/auth.py
import os
from authlib.integrations.starlette_client import OAuth
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "demo_secret_key")
ALGORITHM = "HS256"

# Setup Google OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

def create_token(username: str):
    payload = {"user": username}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)