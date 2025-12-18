from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List, Dict, Any
import os, json, base64, hashlib
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature
from jose import JWTError, jwt

app = FastAPI(title="Security Service", version="1.0.0")

# KONFIGURASI JWT
SECRET_KEY = "rahasia wkwk"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# SECURITY SCHEME (Swagger Authorize)
security = HTTPBearer()

# STORAGE
STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

# SERVER KEYS (tanda tangan PDF oleh server)
SERVER_KEY_DIR = "punkhazard-keys"
SERVER_PRIV19 = os.path.join(SERVER_KEY_DIR, "priv19.pem")  # Ed25519
SERVER_PUB19  = os.path.join(SERVER_KEY_DIR, "pub19.pem")
SERVER_PRIV_EC = os.path.join(SERVER_KEY_DIR, "priv.pem")   # ECDSA
SERVER_PUB_EC  = os.path.join(SERVER_KEY_DIR, "pub.pem")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load_public_key(username: str):
    filepath = os.path.join(STORAGE_DIR, f"{username}_pub.pem")
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        try:
            return serialization.load_pem_public_key(f.read())
        except Exception:
            return None

def load_server_private_key_prefer_priv19():
    """
    Utamakan priv19.pem (Ed25519). Kalau tidak ada, fallback ke priv.pem (ECDSA).
    """
    if os.path.exists(SERVER_PRIV19):
        with open(SERVER_PRIV19, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None), "ed25519", SERVER_PUB19
    if os.path.exists(SERVER_PRIV_EC):
        with open(SERVER_PRIV_EC, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None), "ecdsa-sha256", SERVER_PUB_EC
    raise HTTPException(status_code=500, detail="Server private key tidak ditemukan di folder punkhazard-keys/")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    token = auth.credentials
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc
    return username

def append_inbox(recipient: str, record: Dict[str, Any]):
    path = os.path.join(STORAGE_DIR, f"inbox_{recipient}.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path

def read_inbox(recipient: str) -> List[Dict[str, Any]]:
    path = os.path.join(STORAGE_DIR, f"inbox_{recipient}.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

# Endpoints 
@app.get("/")
async def get_index():
    return {"message": "Selamat Datang Peneliti Punk Record"}

@app.get("/health")
async def health_check():
    return {"status": "Security Service is running", "timestamp": datetime.now().isoformat()}

# 1) Store Public Key (multiuser)
@app.post("/store")
async def store_pubkey(username: str = Form(...), file: UploadFile = File(...)):
    key_content = await file.read()
    try:
        serialization.load_pem_public_key(key_content) 
    except Exception:
        raise HTTPException(status_code=400, detail="Public key tidak valid (PEM).")

    save_path = os.path.join(STORAGE_DIR, f"{username}_pub.pem")
    with open(save_path, "wb") as f:
        f.write(key_content)

    return {
        "success": True,
        "message": f"Key {username} saved.",
        "pubkey_path": save_path,
        "pubkey_sha256": sha256_hex(key_content),
    }

# 2) Login untuk dapat JWT token (secure session)
@app.post("/login")
async def login(username: str = Form(...), signature_hex: str = Form(...)):
    LOGIN_MESSAGE = "LOGIN_ACTION"

    public_key = load_public_key(username)
    if not public_key:
        raise HTTPException(status_code=404, detail="User not found. Upload pubkey dulu via /store.")

    try:
        sig_bytes = bytes.fromhex(signature_hex)
        msg_bytes = LOGIN_MESSAGE.encode("utf-8")

        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig_bytes, msg_bytes)
        else:
            public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise HTTPException(status_code=401, detail="Signature invalid! Login failed.")

    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

# 3) Verify signature (Ddilindungi)
@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature_hex: str = Form(...),
    current_user: str = Depends(get_current_user),
):
    # Secure session: user hanya boleh verify atas nama sendiri
    if current_user != username:
        raise HTTPException(status_code=403, detail="Forbidden: token tidak cocok dengan username.")

    public_key = load_public_key(username)
    if not public_key:
        raise HTTPException(status_code=404, detail="User tidak ada. Upload pubkey dulu via /store.")

    try:
        sig_bytes = bytes.fromhex(signature_hex)
        msg_bytes = message.encode("utf-8")

        # cek original
        ok_original = True
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig_bytes, msg_bytes)
        else:
            public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        ok_original = False

    # cek tampered (integritas)
    try:
        tampered = (message + " [tampered]").encode("utf-8")
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig_bytes, tampered)
        else:
            public_key.verify(sig_bytes, tampered, ec.ECDSA(hashes.SHA256()))
        ok_tampered = True
    except Exception:
        ok_tampered = False

    return {
        "valid_original": ok_original,
        "valid_tampered": ok_tampered,
        "user": username,
        "timestamp": datetime.now().isoformat(),
    }

# 4) Relay (dilindungi) sender diambil dari token
@app.post("/relay")
async def relay(
    recipient: str = Form(...),
    message: str = Form(...),
    current_user: str = Depends(get_current_user),
):
    # cek penerima terdaftar (punya pubkey)
    if not load_public_key(recipient):
        raise HTTPException(status_code=404, detail=f"Recipient '{recipient}' not found. Upload pubkey dulu via /store.")

    record = {
        "sender": current_user,
        "recipient": recipient,
        "message": message,
        "timestamp": datetime.now().isoformat(),
    }
    inbox_path = append_inbox(recipient, record)

    return {"status": "sent", "inbox_path": inbox_path, "record": record}

# 5) Inbox (dilindungi) — hanya boleh baca inbox sendiri
@app.get("/inbox/{username}")
async def inbox(username: str, current_user: str = Depends(get_current_user)):
    if current_user != username:
        raise HTTPException(status_code=403, detail="Forbidden: tidak boleh lihat inbox user lain.")
    msgs = read_inbox(username)
    return {"username": username, "count": len(msgs), "messages": msgs}

# 6) Upload PDF (dilindungi) + tanda tangan server
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...), current_user: str = Depends(get_current_user)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="File must be PDF (application/pdf).")

    content = await file.read()

    priv, mode, pub_path = load_server_private_key_prefer_priv19()

    if mode == "ed25519":
        sig = priv.sign(content)
        sig_algo = "Ed25519 (priv19.pem)"
    else:
        sig = priv.sign(content, ec.ECDSA(hashes.SHA256()))
        sig_algo = "ECDSA-SHA256 (priv.pem)"

    return {
        "filename": file.filename,
        "uploaded_by": current_user,
        "sha256_pdf": sha256_hex(content),
        "server_signature_hex": sig.hex(),
        "server_signature_b64": base64.b64encode(sig).decode("utf-8"),
        "signature_algo": sig_algo,
        "server_pubkey_path": pub_path,
        "timestamp": datetime.now().isoformat(),
    }
