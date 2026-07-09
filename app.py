import os
import time
import secrets
import hashlib
import uuid
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, session, abort, flash, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

UPLOAD_FOLDER = os.path.join("static", "uploads")

# 允许的图片文件扩展名
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'}
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 头像文件最大 2MB


def allowed_file(filename):
    """检查文件扩展名是否在允许列表中"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================
# 内存用户字典（登录使用）
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

# ---------- SQLite 初始化 ----------
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) "
              "VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) "
              "VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()


# ---------- 登录检查装饰器 ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            flash("请先登录")
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


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
    token = generate_csrf_token()
    return dict(csrf_token=token)


# ---------- 登录频率限制 ----------
LOGIN_ATTEMPTS = {}


def is_rate_limited(ip, max_attempts=5, window=60):
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < window]
    if len(LOGIN_ATTEMPTS[ip]) >= max_attempts:
        return True
    LOGIN_ATTEMPTS[ip].append(now)
    return False


SAFE_FIELDS = ["username", "role", "email", "phone", "balance"]


def safe_user_info(user):
    return {k: v for k, v in user.items() if k in SAFE_FIELDS}


# ========== 路由 ==========

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    search_results = None
    keyword = request.args.get("keyword", "")

    if username and username in USERS:
        user_info = safe_user_info(USERS[username])

    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        like_pattern = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SEARCH] keyword={keyword} — 使用参数化查询")
        try:
            c.execute(sql, (like_pattern, like_pattern))
            search_results = c.fetchall()
        except Exception as e:
            print(f"[SEARCH ERROR] {e}")
        finally:
            conn.close()

    return render_template(
        "index.html",
        user=user_info,
        search_results=search_results,
        keyword=keyword,
    )


@app.route("/login", methods=["GET", "POST"])
@csrf_required
def login():
    if request.method == "POST":
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


@app.route("/register", methods=["GET", "POST"])
@csrf_required
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[REGISTER] username={username} — 使用参数化查询")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            flash("注册成功，请登录")
            return redirect("/login")
        except Exception as e:
            print(f"[REGISTER ERROR] {e}")
            return render_template("register.html", error=f"注册失败：{e}")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择一个文件")

        # 1. 检查文件扩展名
        if not allowed_file(file.filename):
            return render_template("upload.html", error="仅支持上传图片文件（jpg、jpeg、png、gif、webp、bmp）")

        # 2. 使用 secure_filename 清除路径穿越字符，并用 UUID 重命名防止文件名冲突
        ext = file.filename.rsplit('.', 1)[1].lower()
        safe_name = secure_filename(file.filename)
        # 若 secure_filename 处理后无扩展名（如纯中文），手动拼接
        if '.' not in safe_name:
            safe_name = f"{uuid.uuid4().hex}.{ext}"
        else:
            name_part = safe_name.rsplit('.', 1)[0]
            safe_name = f"{uuid.uuid4().hex}.{ext}"

        save_path = os.path.join(UPLOAD_FOLDER, safe_name)
        file.save(save_path)

        # 3. 验证文件内容是否为有效图片（使用 Pillow）
        try:
            img = Image.open(save_path)
            img.verify()  # 验证文件头是否为有效图片格式
        except Exception:
            os.remove(save_path)  # 非图片文件立即删除
            return render_template("upload.html", error="文件内容不是有效图片，请上传正确的图片文件")

        # 4. 检查文件实际大小（超过 2MB 提示）
        actual_size = os.path.getsize(save_path)
        if actual_size > MAX_AVATAR_SIZE:
            os.remove(save_path)
            return render_template("upload.html", error="图片文件过大，请上传 2MB 以内的图片")

        file_url = url_for("static", filename=f"uploads/{safe_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_name)

    return render_template("upload.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)
