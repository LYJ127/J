import os
import time
import secrets
import hashlib
from functools import wraps
from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # 有 HTTPS 证书后可设为 True
)

# ============================================================
# 密码以 werkzeug 的 pbkdf2:sha256 哈希存储，不再明文
# 原始密码对照（仅用于说明，实际存储的是哈希值）：
#   admin  -> admin123
#   alice  -> alice2025
# ============================================================
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ---------- CSRF 保护 ----------
def generate_csrf_token():
    token = secrets.token_hex(16)
    session["csrf_token"] = token
    return token


def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token")
            if not token or token != session.get("csrf_token"):
                abort(403, description="CSRF 验证失败，请刷新页面重试")
        return f(*args, **kwargs)

    return decorated


@app.context_processor
def inject_csrf():
    """所有模板自动注入 csrf_token（仅生成一次，避免与路由中显式传参冲突）"""
    token = generate_csrf_token()
    return dict(csrf_token=token)


# ---------- 登录频率限制 ----------
LOGIN_ATTEMPTS = {}  # IP -> [timestamp, ...]


def is_rate_limited(ip, max_attempts=5, window=60):
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    # 清除超出时间窗口的记录
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < window]
    if len(LOGIN_ATTEMPTS[ip]) >= max_attempts:
        return True
    LOGIN_ATTEMPTS[ip].append(now)
    return False


# 从模板显示的数据中移除敏感字段
SAFE_FIELDS = ["username", "role", "email", "phone", "balance"]


def safe_user_info(user):
    """返回不包含密码字段的用户信息"""
    return {k: v for k, v in user.items() if k in SAFE_FIELDS}


# ---------- 路由 ----------
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@csrf_required
def login():
    if request.method == "POST":
        # 频率限制
        client_ip = request.remote_addr or "unknown"
        if is_rate_limited(client_ip):
            return render_template(
                "login.html",
                error="登录尝试过于频繁，请 60 秒后再试",
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            session.permanent = True
            return render_template("index.html", user=safe_user_info(user))
        else:
            return render_template(
                "login.html",
                error="用户名或密码错误",
            )

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
