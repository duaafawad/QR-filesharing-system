import qrcode
import os
import secrets
import time
import json
import base64
import hashlib

QR_FOLDER = "qr_codes"
TOKEN_FILE = "qr_tokens.json"
USER_FILE = "users.json"

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
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{base64.b64encode(salt).decode()}:{iterations}:{dk.hex()}"


def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        salt_b64, iters_str, hexhash = stored.split(":")
        salt = base64.b64decode(salt_b64.encode())
        iters = int(iters_str)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
        return dk.hex() == hexhash
    except Exception:
        return False


# ---------------- user storage ----------------
if os.path.exists(USER_FILE):
    try:
        with open(USER_FILE, "r") as f:
            user_db = json.load(f)
    except Exception:
        user_db = {}
else:
    user_db = {}


def persist_users():
    with open(USER_FILE, "w") as f:
        json.dump(user_db, f, indent=2)


def create_user(username: str, password: str) -> bool:
    """
    Create a new user with PBKDF2-hashed password.
    Returns False if the user already exists.
    """
    if not username or not password:
        return False
    if username in user_db:
        return False
    user_db[username] = {
        "password_hash": pbkdf2_hash(password)
    }
    persist_users()
    return True


def authenticate_user(username: str, password: str) -> bool:
    user = user_db.get(username)
    if not user:
        return False
    stored = user.get("password_hash", "")
    return pbkdf2_verify(password, stored)


def update_user_password(username: str, new_password: str) -> bool:
    """
    Overwrite the stored password hash for a user.
    """
    user = user_db.get(username)
    if not user or not new_password:
        return False
    user["password_hash"] = pbkdf2_hash(new_password)
    persist_users()
    return True


# ---------------- token storage ----------------
def save_token(
    token: str,
    file_name: str,
    password: str = None,
    expiry_seconds: int = None,
    aes_key: bytes = None,
    owner: str = None,
):
    """
    Save token metadata with optional AES key and owner.
    """
    expiry_time = int(time.time()) + int(expiry_seconds) if expiry_seconds else None

    # Use provided AES key if given
    if aes_key is None:
        aes_key = secrets.token_bytes(32)
    aes_key_b64 = base64.b64encode(aes_key).decode()

    stored_password = pbkdf2_hash(password) if password else None

    token_db[token] = {
        "file_name": file_name,
        "expiry": expiry_time,
        "password_hash": stored_password,
        "aes_key_b64": aes_key_b64,
        "owner": owner,
        "scan_count": 0,
        "download_count": 0,
        "last_scan_ts": None,
        "last_download_ts": None,
        "scan_users": [],
        "download_users": [],
        "allowed_users": [],
        "revoked": False,
    }
    persist_tokens()


def validate_token(token: str):
    entry = token_db.get(token)
    if not entry:
        return None
    expiry = entry.get("expiry")
    if expiry is None or expiry > int(time.time()):
        return entry
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


def record_scan(token: str, username: str = None):
    """
    Mark that a QR / access link has been opened (scanned).
    """
    entry = token_db.get(token)
    if not entry:
        return
    entry["scan_count"] = int(entry.get("scan_count") or 0) + 1
    entry["last_scan_ts"] = int(time.time())
    users = entry.get("scan_users") or []
    if username and username not in users:
        users.append(username)
        entry["scan_users"] = users
    persist_tokens()


def record_download(token: str, username: str = None):
    """
    Mark that the file for a token has been downloaded.
    """
    entry = token_db.get(token)
    if not entry:
        return
    entry["download_count"] = int(entry.get("download_count") or 0) + 1
    entry["last_download_ts"] = int(time.time())
    users = entry.get("download_users") or []
    if username and username not in users:
        users.append(username)
        entry["download_users"] = users
    persist_tokens()


def update_token_controls(token: str, allowed_users=None, revoked=None) -> bool:
    """
    Update access-control related fields for a token.
    """
    entry = token_db.get(token)
    if not entry:
        return False
    if allowed_users is not None:
        entry["allowed_users"] = allowed_users
    if revoked is not None:
        entry["revoked"] = bool(revoked)
    persist_tokens()
    return True


def list_tokens_for_user(username: str):
    """
    Return a list of (token, metadata) for a given owner username.
    """
    if not username:
        return []
    return [
        {"token": tok, **meta}
        for tok, meta in token_db.items()
        if meta.get("owner") == username
    ]


def generate_qr_for_file(token: str, base_url: str = None):
    if base_url is None:
        raise ValueError("base_url must be provided")

    if "token=" not in base_url:
        if "?" in base_url:
            secure_url = f"{base_url}&token={token}"
        else:
            secure_url = f"{base_url}?token={token}"
    else:
        secure_url = base_url

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(secure_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    qr_filename = f"{token}_qr.png"
    img_path = os.path.join(QR_FOLDER, qr_filename)
    img.save(img_path)
    return img_path, secure_url
