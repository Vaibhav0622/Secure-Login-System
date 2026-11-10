import os
import re
import io
import base64
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, flash, g
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import qrcode

app = Flask(__name__)
# Cryptographically strong 256-bit secret key for signing session cookies
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Hardened Session Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Prevents XSS from reading session cookie via JS
    SESSION_COOKIE_SAMESITE="Lax",  # Mitigates CSRF attacks
    SESSION_COOKIE_SECURE=False,    # Set to True in production with HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

DB_PATH = "auth_system.db"

# Configure Argon2id (OWASP recommended parameters)
ph = PasswordHasher(
    time_cost=3,       # 3 iterations
    memory_cost=65536, # 64 MB RAM
    parallelism=4,     # 4 parallel threads
    hash_len=32,
    salt_len=16
)

# ---------------------------------------------------------------------------
# DATABASE SETUP & PARAMETERIZED HELPERS
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                is_2fa_enabled INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

# ---------------------------------------------------------------------------
# SECURITY VALIDATORS & MIDDLEWARE
# ---------------------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,24}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;/~`]", password):
        return False, "Password must include at least one special character."
    return True, ""

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def verify_csrf():
    token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        return False
    return True

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access the dashboard.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def make_qr_base64(uri: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

# ---------------------------------------------------------------------------
# EMBEDDED HTML + CSS TEMPLATE (No external /templates folder needed)
# ---------------------------------------------------------------------------
HTML_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureAuth Localhost</title>
    <style>
        :root {
            --bg: #0b0f19;
            --card: #111827;
            --border: #1f2937;
            --text: #f3f4f6;
            --muted: #9ca3af;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --code-bg: #030712;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
        body {
            background: radial-gradient(circle at top, #1e293b 0%, var(--bg) 70%);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .container {
            width: 100%;
            max-width: 460px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 32px;
            box-shadow: 0 20px 45px rgba(0, 0, 0, 0.55);
        }
        .container.wide { max-width: 680px; }
        .badge {
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            padding: 4px 10px;
            border-radius: 999px;
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            margin-bottom: 12px;
        }
        h1 { font-size: 22px; font-weight: 700; margin-bottom: 6px; }
        p.sub { color: var(--muted); font-size: 14px; margin-bottom: 22px; line-height: 1.5; }
        .alert {
            padding: 12px 14px;
            border-radius: 8px;
            font-size: 13.5px;
            margin-bottom: 18px;
            border: 1px solid transparent;
        }
        .alert-error { background: rgba(239, 68, 68, 0.12); border-color: rgba(239, 68, 68, 0.35); color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.35); color: #6ee7b7; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #d1d5db; }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%;
            padding: 11px 14px;
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 14px;
            outline: none;
            transition: border-color 0.15s;
        }
        input:focus { border-color: var(--primary); }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 16px 0 20px;
            padding: 12px;
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        .checkbox-group input { width: 16px; height: 16px; accent-color: var(--primary); }
        .checkbox-group label { margin: 0; font-weight: 500; cursor: pointer; }
        button.btn {
            width: 100%;
            padding: 12px;
            background: var(--primary);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s;
        }
        button.btn:hover { background: var(--primary-hover); }
        button.btn-danger { background: var(--danger); }
        button.btn-danger:hover { background: #dc2626; }
        .footer-link {
            text-align: center;
            margin-top: 18px;
            font-size: 13.5px;
            color: var(--muted);
        }
        .footer-link a { color: #60a5fa; text-decoration: none; font-weight: 600; }
        .footer-link a:hover { text-decoration: underline; }
        .code-box {
            background: var(--code-bg);
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 8px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            color: #93c5fd;
            word-break: break-all;
            margin-bottom: 16px;
        }
        .qr-wrap {
            background: #fff;
            padding: 12px;
            border-radius: 10px;
            display: inline-block;
            margin: 10px auto 16px;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 18px;
        }
        .meta-item {
            background: var(--code-bg);
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 8px;
        }
        .meta-item span { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; }
        .meta-item strong { font-size: 14px; color: var(--text); }
    </style>
</head>
<body>
    <div class="container {{ 'wide' if page == 'dashboard' else '' }}">
        <span class="badge">Argon2id + SQLite Parameterized + TOTP 2FA</span>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, msg in messages %}
                    <div class="alert alert-{{ category }}">{{ msg }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% if page == 'login' %}
            <h1>Sign In</h1>
            <p class="sub">Authenticate with your credentials. Protected against SQLi and brute-force attacks.</p>
            <form method="POST" action="{{ url_for('login') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required autocomplete="username" placeholder="e.g. vaibhav_sec">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required autocomplete="current-password" placeholder="••••••••">
                </div>
                <button type="submit" class="btn">Continue</button>
            </form>
            <div class="footer-link">
                Don't have an account? <a href="{{ url_for('register') }}">Create Account</a>
            </div>

        {% elif page == 'register' %}
            <h1>Create Secure Account</h1>
            <p class="sub">Passwords are salted & hashed with Argon2id (64 MB memory cost).</p>
            <form method="POST" action="{{ url_for('register') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label>Username (3–24 alphanumeric/underscore)</label>
                    <input type="text" name="username" required placeholder="vaibhav_sec">
                </div>
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" name="email" required placeholder="you@example.com">
                </div>
                <div class="form-group">
                    <label>Password (8+ chars, upper, lower, digit, symbol)</label>
                    <input type="password" name="password" required placeholder="StrongP@ssw0rd!">
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="enable_2fa" name="enable_2fa" value="1">
                    <label for="enable_2fa">Enable Two-Factor Authentication (TOTP 2FA)</label>
                </div>
                <button type="submit" class="btn">Register Account</button>
            </form>
            <div class="footer-link">
                Already registered? <a href="{{ url_for('login') }}">Sign In</a>
            </div>

        {% elif page == '2fa_setup' %}
            <h1>Configure 2FA Authenticator</h1>
            <p class="sub">Scan the QR code below with Google Authenticator, Authy, or enter the Base32 secret manually.</p>
            <div style="text-align: center;">
                <div class="qr-wrap">
                    <img src="data:image/png;base64,{{ qr_b64 }}" alt="TOTP QR Code">
                </div>
            </div>
            <label>Manual Setup Key (Base32)</label>
            <div class="code-box">{{ totp_secret }}</div>
            <label>Live Server TOTP Code (For Localhost Testing)</label>
            <div class="code-box" style="color: #6ee7b7;">Current valid 6-digit OTP: <strong>{{ current_otp }}</strong></div>
            <form method="POST" action="{{ url_for('verify_2fa') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label>Enter 6-Digit Verification Code</label>
                    <input type="text" name="otp_code" pattern="\\d{6}" maxlength="6" required placeholder="123456">
                </div>
                <button type="submit" class="btn">Verify & Complete Login</button>
            </form>

        {% elif page == '2fa_verify' %}
            <h1>Two-Factor Verification</h1>
            <p class="sub">Enter the 6-digit TOTP code from your authenticator app.</p>
            <label>Localhost Testing Helper (Current Server OTP)</label>
            <div class="code-box" style="color: #6ee7b7;">Current valid 6-digit OTP: <strong>{{ current_otp }}</strong></div>
            <form method="POST" action="{{ url_for('verify_2fa') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label>6-Digit Authenticator Code</label>
                    <input type="text" name="otp_code" pattern="\\d{6}" maxlength="6" required autofocus placeholder="123456">
                </div>
                <button type="submit" class="btn">Verify OTP</button>
            </form>
            <div class="footer-link">
                <a href="{{ url_for('logout') }}">Cancel and return to Login</a>
            </div>

        {% elif page == 'dashboard' %}
            <h1>Authenticated Session Dashboard</h1>
            <p class="sub">Your session is active and protected by an HttpOnly signed cookie.</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <span>Username</span>
                    <strong>{{ user['username'] }}</strong>
                </div>
                <div class="meta-item">
                    <span>Email</span>
                    <strong>{{ user['email'] }}</strong>
                </div>
                <div class="meta-item">
                    <span>2FA Status</span>
                    <strong style="color: {{ '#10b981' if user['is_2fa_enabled'] else '#f59e0b' }}">
                        {{ 'Enabled (RFC 6238 TOTP)' if user['is_2fa_enabled'] else 'Disabled' }}
                    </strong>
                </div>
                <div class="meta-item">
                    <span>Account Created</span>
                    <strong>{{ user['created_at'] }}</strong>
                </div>
            </div>
            <label>Stored Argon2id Password Hash (From SQLite DB)</label>
            <div class="code-box">{{ user['password_hash'] }}</div>
            <label>Active Session Token (Server-Side Nonce)</label>
            <div class="code-box">{{ session_nonce }}</div>
            <form method="POST" action="{{ url_for('logout') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button type="submit" class="btn btn-danger">Destroy Session & Log Out</button>
            </form>
        {% endif %}
    </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# APPLICATION ROUTES
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not verify_csrf():
            flash("Invalid CSRF token.", "error")
            return redirect(url_for("register"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        enable_2fa = 1 if request.form.get("enable_2fa") == "1" else 0

        # 1. Input Validation
        if not USERNAME_REGEX.match(username):
            flash("Username must be 3-24 characters (letters, numbers, underscores only).", "error")
            return redirect(url_for("register"))

        if not EMAIL_REGEX.match(email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))

        valid_pw, pw_msg = validate_password_strength(password)
        if not valid_pw:
            flash(pw_msg, "error")
            return redirect(url_for("register"))

        # 2. Argon2id Password Hashing
        password_hash = ph.hash(password)
        totp_secret = pyotp.random_base32() if enable_2fa else None

        # 3. Parameterized SQL Insert (100% immune to SQL Injection)
        db = get_db()
        try:
            cursor = db.execute(
                """
                INSERT INTO users (username, email, password_hash, totp_secret, is_2fa_enabled)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, email, password_hash, totp_secret, enable_2fa)
            )
            db.commit()
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")
            return redirect(url_for("register"))

        if enable_2fa:
            session["pending_2fa_user_id"] = user_id
            session["is_2fa_setup"] = True
            return redirect(url_for("verify_2fa"))

        flash("Account registered! You can now sign in.", "success")
        return redirect(url_for("login"))

    return render_template_string(HTML_LAYOUT, page="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not verify_csrf():
            flash("Invalid CSRF token.", "error")
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        # Parameterized query prevents ' OR 1=1 -- SQL injection payloads
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user:
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        # Brute-force lockout check
        if user["failed_attempts"] >= 5:
            flash("Account locked due to 5 failed login attempts.", "error")
            return redirect(url_for("login"))

        # Verify Argon2id hash
        try:
            ph.verify(user["password_hash"], password)
        except VerifyMismatchError:
            db.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                (user["id"],)
            )
            db.commit()
            remaining = max(0, 4 - user["failed_attempts"])
            flash(f"Invalid credentials. {remaining} attempts remaining before lockout.", "error")
            return redirect(url_for("login"))

        # Reset failed attempts and check if rehash is needed
        db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
        if ph.check_needs_rehash(user["password_hash"]):
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (ph.hash(password), user["id"])
            )
        db.commit()

        # Check if 2FA is enabled
        if user["is_2fa_enabled"]:
            session["pending_2fa_user_id"] = user["id"]
            session["is_2fa_setup"] = False
            return redirect(url_for("verify_2fa"))

        # Establish authenticated session
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["session_nonce"] = secrets.token_hex(24)
        flash("Signed in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template_string(HTML_LAYOUT, page="login")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
    if not user or not user["totp_secret"]:
        return redirect(url_for("login"))

    totp = pyotp.TOTP(user["totp_secret"])

    if request.method == "POST":
        if not verify_csrf():
            flash("Invalid CSRF token.", "error")
            return redirect(url_for("verify_2fa"))

        otp_code = request.form.get("otp_code", "").strip()
        if totp.verify(otp_code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["session_nonce"] = secrets.token_hex(24)
            flash("2FA verification complete!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired 6-digit OTP code.", "error")

    if session.get("is_2fa_setup"):
        uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureAuthLocal")
        qr_b64 = make_qr_base64(uri)
        return render_template_string(
            HTML_LAYOUT,
            page="2fa_setup",
            qr_b64=qr_b64,
            totp_secret=user["totp_secret"],
            current_otp=totp.now()
        )

    return render_template_string(
        HTML_LAYOUT,
        page="2fa_verify",
        current_otp=totp.now()
    )

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    return render_template_string(
        HTML_LAYOUT,
        page="dashboard",
        user=user,
        session_nonce=session.get("session_nonce", "")
    )

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("Session terminated securely.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    print("[*] Starting Secure Login Server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)