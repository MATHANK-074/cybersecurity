import os
import io
import base64
import pyotp
import qrcode
import random
import time
from fastapi import FastAPI, Request, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

# Internal project imports
from crypto import decrypt_data
from database import get_record

# MANDATORY: Allows OAuth to work over HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

load_dotenv()
app = FastAPI(title="Secure Healthcare Backend")

# CORS Setup for React Integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. SETUP SESSION MIDDLEWARE
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))

# 2. SETUP GOOGLE OAUTH
oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Constants
SHARED_2FA_SECRET = "JBSWY3DPEHPK3PXP" 
MEDICAL_PHRASES = [
    "Verify Medical Access 782", 
    "Emergency Heart Rate Stable", 
    "Decrypt Patient Record Alpha",
    "Secure Bio Sync Active",
    "Confirm Identity Now 404"
]

# -------------------------------
# AUTHENTICATION & ROLE SELECTION
# -------------------------------

@app.get("/login")
async def login(request: Request):
    """Starts the Google Login process."""
    redirect_uri = request.url_for('auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Processes Google return and forces Role Selection."""
    try:
        token = await oauth.google.authorize_access_token(request)
        user = token.get('userinfo')
        
        # Reset security status for a new session
        request.session.clear() 
        request.session['user'] = dict(user)
        
        # Redirect to React Role Selection Page
        return RedirectResponse(url="http://localhost:3000/select-role")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Auth failed: {str(e)}")

@app.post("/select-role")
async def select_role(request: Request):
    """Saves user role and directs to correct security gate."""
    data = await request.json()
    role = data.get("role") # 'admin' or 'patient'
    
    if role not in ["admin", "patient"]:
        raise HTTPException(status_code=400, detail="Invalid role selection")
        
    request.session["role"] = role
    
    # Redirect logic based on role
    if role == "admin":
        return {"redirect": "http://localhost:3000/admin-biometric"}
    return {"redirect": "http://localhost:3000/setup-2fa"}

# -------------------------------
# ADMIN BIOMETRIC GATE (FACE + VOICE)
# -------------------------------

@app.get("/get-challenge-phrase")
async def get_challenge(request: Request):
    """Generates a random phrase rotating every 120 seconds."""
    if request.session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Unauthorized role")

    # Group time into 2-minute windows
    window = int(time.time() / 120) 
    random.seed(window)
    phrase = random.choice(MEDICAL_PHRASES)
    
    request.session['current_challenge'] = phrase
    return {
        "phrase": phrase, 
        "expires_in": 120 - (int(time.time()) % 120)
    }

@app.post("/verify-admin-bio")
async def verify_admin_bio(request: Request, video: UploadFile = File(...)):
    """Verifies combined Face + Voice sync for Admins."""
    if request.session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")

    # --- INTEGRATION POINT FOR YOUR AI MODELS ---
    # 1. Extract frames from 'video' for Face Recognition
    # 2. Extract audio from 'video' for Voice Recognition
    # 3. Match against request.session['current_challenge']
    
    # Placeholder: Assuming AI logic returns True
    biometric_match = True 
    
    if biometric_match:
        request.session['admin_verified'] = True
        return {"status": "Success", "message": "Admin Identity Confirmed"}
    
    raise HTTPException(status_code=403, detail="Biometric Verification Failed")

# -------------------------------
# PATIENT 2FA (GOOGLE AUTHENTICATOR)
# -------------------------------

@app.get("/setup-2fa")
async def setup_2fa(request: Request):
    """QR Code setup for Patients only."""
    user = request.session.get('user')
    if not user or request.session.get("role") != "patient":
        raise HTTPException(status_code=403, detail="Access Denied")

    totp = pyotp.TOTP(SHARED_2FA_SECRET)
    auth_url = totp.provisioning_uri(name=user['email'], issuer_name="HealthcareSecure")

    img = qrcode.make(auth_url)
    buf = io.BytesIO()
    img.save(buf)
    img_base64 = base64.b64encode(buf.getvalue()).decode()

    return {"qr_code": img_base64}

@app.post("/verify-2fa")
async def verify_2fa(request: Request):
    """Validates 6-digit OTP for Patients."""
    data = await request.json()
    code = data.get("code")
    
    totp = pyotp.TOTP(SHARED_2FA_SECRET)
    if totp.verify(code):
        request.session['2fa_verified'] = True
        return {"status": "Success", "redirect": "http://localhost:3000/dashboard"}
    
    raise HTTPException(status_code=400, detail="Invalid 2FA code")

# -------------------------------
# SECURED DATA ACCESS
# -------------------------------

@app.get("/view_record/{record_id}")
def view_record(record_id: str, request: Request):
    """Final gate: Checks role-specific verification flags."""
    user = request.session.get('user')
    role = request.session.get('role')

    if not user:
        raise HTTPException(status_code=401, detail="Login required")

    # Enforce role-based security paths
    if role == "admin" and not request.session.get('admin_verified'):
        raise HTTPException(status_code=403, detail="Biometric verification required for Admins")
    
    if role == "patient" and not request.session.get('2fa_verified'):
        raise HTTPException(status_code=403, detail="2FA required for Patients")

    # Fetch and Decrypt Data
    encrypted = get_record(record_id)
    decrypted = decrypt_data(encrypted)
    
    return {
        "record": decrypted, 
        "audit": f"Accessed by {user['email']} as {role}"
    }

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out"}