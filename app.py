from flask import Flask, render_template, request, session, redirect, url_for, send_file, send_from_directory, jsonify
import os
import re
import hashlib
from io import BytesIO
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from qr_generator import (
    generate_secure_token,
    save_token,
    validate_token,
    generate_qr_for_file,
    QR_FOLDER,
    get_aes_key_for_token,
    pbkdf2_verify,
    create_user,
    authenticate_user,
    update_user_password,
    record_scan,
    record_download,
    list_tokens_for_user,
    update_token_controls,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# Folders
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

# Base URL used inside QR links; default to your Koyeb deployment, overridable via BACKEND_URL env
BACKEND_URL = os.environ.get(
    "BACKEND_URL",
    "https://organisational-blanch-danbrown-1358c46a.koyeb.app",
)


def current_user():
    return session.get("username")


def validate_password_strength(password: str):
    """
    Enforce basic password complexity:
    - at least 10 characters
    - at least one uppercase letter
    - at least one digit
    - at least one special character
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^\w\s]", password):
        return False, "Password must contain at least one special character."
    return True, None


def ensure_token_access(info, user: str):
    """
    Enforce per-token access control:
    - deny if revoked
    - if allowed_users is non-empty, only owner or allowed users may proceed
    """
    if not user:
        return False, "You must be logged in to access this file."
    if info.get("revoked"):
        return False, "This QR/link has been revoked by the sender."
    allowed = info.get("allowed_users") or []
    owner = info.get("owner")
    if allowed and (user not in allowed) and (user != owner):
        return False, "You are not authorized to access this file."
    return True, None


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
    return render_template("index.html", user=current_user())

@app.route("/upload", methods=["POST"])
def upload():
    if not current_user():
        return redirect(url_for("login", next=url_for("index")))

    if "file" not in request.files or "password" not in request.form:
        return render_template("index.html", error="Missing file or password", user=current_user())
    f = request.files["file"]
    password = request.form.get("password", "")
    if f.filename == "":
        return render_template("index.html", error="No selected file", user=current_user())

    ok, msg = validate_password_strength(password)
    if not ok:
        return render_template("index.html", error=f"Weak file password: {msg}", user=current_user())

    filename = secure_filename(f.filename)
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    encrypted_path = original_path + ".enc"

    # Save original file and compute checksum
    f.save(original_path)
    checksum = file_checksum(original_path)

    # Encrypt file with AES key
    aes_key = os.urandom(32)
    encrypt_file_with_key(original_path, encrypted_path, aes_key)
    os.remove(original_path)

    # Save token with the same AES key
    token = generate_secure_token()
    save_token(
        token,
        encrypted_path,
        password,
        expiry_seconds=3600,
        aes_key=aes_key,
        owner=current_user(),
    )

    # Generate QR
    access_url = f"{BACKEND_URL}/access?token={token}"
    qr_img_path, secure_url = generate_qr_for_file(token, base_url=access_url)
    qr_filename = os.path.basename(qr_img_path)
    qr_image_url = url_for("serve_qr", filename=qr_filename, _external=True)

    return render_template(
        "index.html",
        file_name=filename,
        checksum=checksum,
        qr_path=qr_image_url,
        access_url=secure_url,
        user=current_user(),
    )

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
    user = current_user()
    if not user:
        # force login before revealing anything about the file
        return redirect(url_for("login", next=request.url))
    ok, msg = ensure_token_access(info, user)
    if not ok:
        return render_template("access_password.html", error=msg, token=token)

    if request.method == "GET":
        # Count a scan when the access page is successfully opened
        record_scan(token, username=user)
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
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.url))
    ok, msg = ensure_token_access(info, user)
    if not ok:
        return msg, 403

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
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.url))
    ok, msg = ensure_token_access(info, user)
    if not ok:
        return msg, 403

    aes_key = get_aes_key_for_token(token)
    if not aes_key:
        return "Encryption key missing", 500

    encrypted_path = info.get("file_name")
    try:
        decrypted_bytes = decrypt_file_bytes_with_key(encrypted_path, aes_key)
    except Exception:
        return "Decryption failed.", 500

    original_name = os.path.basename(encrypted_path).replace(".enc", "")
    # record successful download
    record_download(token, username=user)
    return send_file(BytesIO(decrypted_bytes), download_name=original_name, as_attachment=True)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            return render_template("register.html", error="Username and password are required.")
        ok, msg = validate_password_strength(password)
        if not ok:
            return render_template("register.html", error=f"Weak password: {msg}")
        created = create_user(username, password)
        if not created:
            return render_template("register.html", error="User already exists or invalid data.")
        session["username"] = username
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next") or url_for("dashboard")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if authenticate_user(username, password):
            session["username"] = username
            return redirect(next_url)
        return render_template("login.html", error="Invalid username or password.", next=next_url)
    return render_template("login.html", next=next_url)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=url_for("dashboard")))
    tokens = list_tokens_for_user(user)
    return render_template("dashboard.html", user=user, tokens=tokens)


@app.route("/account", methods=["GET", "POST"])
def account():
    user = current_user()
    if not user:
        return redirect(url_for("login", next=url_for("account")))
    message = None
    error = None
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        if not authenticate_user(user, current_pw):
            error = "Current password is incorrect."
        else:
            ok, msg = validate_password_strength(new_pw)
            if not ok:
                error = f"Weak password: {msg}"
            else:
                if update_user_password(user, new_pw):
                    message = "Password updated successfully."
                else:
                    error = "Failed to update password. Please try again."
    return render_template("account.html", user=user, message=message, error=error)


@app.route("/dashboard/update/<token>", methods=["POST"])
def dashboard_update(token):
    user = current_user()
    if not user:
        return redirect(url_for("login", next=url_for("dashboard")))
    info = validate_token(token)
    # Even if token is expired, don't allow editing / accessing
    if not info or info.get("owner") != user:
        return "Not allowed", 403
    raw_allowed = request.form.get("allowed_users", "")
    allowed_users = [u.strip() for u in raw_allowed.split(",") if u.strip()]
    revoked = bool(request.form.get("revoked"))
    update_token_controls(token, allowed_users=allowed_users, revoked=revoked)
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
