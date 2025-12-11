# qr_generator.py
import qrcode
import os
import secrets
import time
import json
import base64
import hashlib

QR_FOLDER = "qr_codes"
TOKEN_FILE = "qr_tokens.json"

# ensure folder exists
os.makedirs(QR_FOLDER, exist_ok=True)

# load token DB
if os.path.exists(TOKEN_FILE):
    try:
        with open(TOKEN_FILE, "r") as f:
            token_db = json.load(f)
    except Exception:
        token_db = {}
else:
    token_db = {}

def persist_tokens():
    with open(TOKEN_FILE, "w") as f:
        json.dump(token_db, f, indent=2)

def generate_secure_token(length=16):
    return secrets.token_hex(length)

# ---------------- PBKDF2 helpers ----------------
def pbkdf2_hash(password: str, iterations: int = 200_000) -> str:
    """Return string salt:iterations:hexhash"""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{base64.b64encode(salt).decode()}:{iterations}:{dk.hex()}"

def pbkdf2_verify(password: str, stored: str) -> bool:
    """Verify password against stored 'salt:iterations:hex' string"""
    try:
        salt_b64, iters_str, hexhash = stored.split(":")
        salt = base64.b64decode(salt_b64.encode())
        iters = int(iters_str)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
        return dk.hex() == hexhash
    except Exception:
        return False

# ---------------- token storage ----------------
def save_token(token: str, file_name: str, password: str = None, expiry_seconds: int = None):
    """
    Save token metadata.
    - file_name: path to encrypted file (or to file that will be encrypted).
    - password: user's password (we will store PBKDF2 hash or None)
    - expiry_seconds: TTL for token (optional)
    We also generate and store a random AES key (base64) for file encryption/decryption.
    """
    expiry_time = int(time.time()) + int(expiry_seconds) if expiry_seconds else None

    # generate random AES-256 key (32 bytes) and store base64
    aes_key = secrets.token_bytes(32)
    aes_key_b64 = base64.b64encode(aes_key).decode()

    stored_password = pbkdf2_hash(password) if password else None

    token_db[token] = {
        "file_name": file_name,
        "expiry": expiry_time,
        "password_hash": stored_password,
        "aes_key_b64": aes_key_b64
    }
    persist_tokens()

def validate_token(token: str):
    """Return token entry if present and not expired, else None"""
    entry = token_db.get(token)
    if not entry:
        return None
    expiry = entry.get("expiry")
    if expiry is None or expiry > int(time.time()):
        return entry
    # expired -> remove
    token_db.pop(token, None)
    persist_tokens()
    return None

def get_aes_key_for_token(token: str) -> bytes:
    entry = token_db.get(token)
    if not entry:
        return None
    b64 = entry.get("aes_key_b64")
    if not b64:
        return None
    return base64.b64decode(b64.encode())

def generate_qr_for_file(token: str, base_url: str = None):
    """
    Returns (img_path, url) where url is the full access URL that QR encodes.
    base_url should be a full URL like https://yourdomain/access?token=...
    """
    if base_url is None:
        raise ValueError("base_url must be provided")

    secure_url = base_url
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(secure_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    qr_filename = f"{token}_qr.png"
    img_path = os.path.join(QR_FOLDER, qr_filename)
    img.save(img_path)
    return img_path, secure_url
