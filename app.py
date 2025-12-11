# app.py
from flask import Flask, render_template, request, session, redirect, url_for, send_file, send_from_directory, jsonify
import os, hashlib, time, base64
from io import BytesIO
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from qr_generator import generate_secure_token, save_token, validate_token, generate_qr_for_file, QR_FOLDER, get_aes_key_for_token, pbkdf2_verify

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# Folders
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

# FIXED — now always uses your live backend domain
BACKEND_URL = os.environ.get(
    "BACKEND_URL",
    "https://organisational-blanch-danbrown-1358c46a.koyeb.app"
)

# --- AES helpers (CBC) ---
def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]

def encrypt_file_with_key(infile: str, outfile: str, key: bytes):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(infile, "rb") as f:
        plaintext = pad(f.read())
    ciphertext = cipher.encrypt(plaintext)
    with open(outfile, "wb") as f:
        f.write(iv + ciphertext)

def decrypt_file_bytes_with_key(infile: str, key: bytes) -> bytes:
    with open(infile, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext)

def file_checksum_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def file_checksum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            h.update(block)
    return h.hexdigest()

# ---------- Routes ----------

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files or "password" not in request.form:
        return render_template("index.html", error="Missing file or password")
    f = request.files["file"]
    password = request.form.get("password", "")
    if f.filename == "":
        return render_template("index.html", error="No selected file")

    filename = secure_filename(f.filename)
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    encrypted_path = original_path + ".enc"

    # save original, compute checksum, encrypt with random AES key, remove original
    f.save(original_path)
    checksum = file_checksum(original_path)

    aes_key = os.urandom(32)  # 256-bit
    encrypt_file_with_key(original_path, encrypted_path, aes_key)
    os.remove(original_path)

    # token & save
    token = generate_secure_token()
    save_token(token, encrypted_path, password, expiry_seconds=3600)

    # generate QR using your live domain
    access_url = f"{BACKEND_URL}/access?token={token}"
    qr_img_path, secure_url = generate_qr_for_file(token, base_url=access_url)
    qr_filename = os.path.basename(qr_img_path)
    qr_image_url = url_for("serve_qr", filename=qr_filename, _external=True)

    return render_template("index.html",
                           file_name=filename,
                           checksum=checksum,
                           qr_path=qr_image_url,
                           access_url=secure_url)

@app.route("/qr_codes/<filename>")
def serve_qr(filename):
    return send_from_directory(QR_FOLDER, filename)

@app.route("/access", methods=["GET", "POST"])
def access():
    token = request.args.get("token") or request.form.get("token")
    if not token:
        return render_template("access_password.html", error="No token provided.", token=None)
    info = validate_token(token)
    if not info:
        return render_template("access_password.html", error="Invalid or expired token.", token=token)

    if request.method == "GET":
        return render_template("access_password.html", token=token)

    password = request.form.get("password", "")
    stored_hash = info.get("password_hash")
    if stored_hash:
        ok = pbkdf2_verify(password, stored_hash)
        if not ok:
            return render_template("access_password.html", token=token, error="Incorrect password")

    session[f"current_token"] = token
    session[f"verified_{token}"] = False
    return redirect(url_for("access_verify", token=token))

@app.route("/access/verify", methods=["GET", "POST"])
def access_verify():
    token = request.args.get("token") or session.get("current_token") or request.form.get("token")
    if not token:
        return "No token provided", 400
    info = validate_token(token)
    if not info:
        return "Invalid or expired token", 404

    encrypted_path = info.get("file_name")
    aes_key = get_aes_key_for_token(token)
    if not aes_key:
        return "Encryption key missing", 500

    try:
        decrypted_bytes = decrypt_file_bytes_with_key(encrypted_path, aes_key)
        expected_checksum = file_checksum_bytes(decrypted_bytes)
    except Exception:
        expected_checksum = None

    if request.method == "POST":
        entered = request.form.get("userChecksum", "").strip()
        ok = (entered.lower() == (expected_checksum or "").lower())
        session[f"verified_{token}"] = bool(ok)
        return jsonify({"success": bool(ok)})

    return render_template("access_verify.html",
                           token=token,
                           file_name=os.path.basename(encrypted_path).replace(".enc", ""),
                           checksum=expected_checksum)

@app.route("/download/<token>", methods=["GET"])
def download(token):
    if not session.get(f"verified_{token}", False):
        return "Checksum not verified. Download denied.", 403

    info = validate_token(token)
    if not info:
        return "Invalid or expired token", 404

    aes_key = get_aes_key_for_token(token)
    if not aes_key:
        return "Encryption key missing", 500

    encrypted_path = info.get("file_name")
    try:
        decrypted_bytes = decrypt_file_bytes_with_key(encrypted_path, aes_key)
    except Exception:
        return "Decryption failed.", 500

    original_name = os.path.basename(encrypted_path).replace(".enc", "")
    return send_file(BytesIO(decrypted_bytes), download_name=original_name, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
