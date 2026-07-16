import os
import time
import secrets
import hashlib
import uuid
import sqlite3
import urllib.request
import urllib.error
import urllib.parse
import socket
import ipaddress
import subprocess
import platform
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
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'}
MAX_AVATAR_SIZE = 2 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================
# 用户数据（含 id，登录+个人中心共用）
# ============================================================
USERS = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "id": 2,
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# 通过 id 快速查找用户
USER_BY_ID = {v["id"]: v for v in USERS.values()}

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


SAFE_FIELDS = ["id", "username", "role", "email", "phone", "balance"]

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
        try:
            c.execute(sql, (like_pattern, like_pattern))
            search_results = c.fetchall()
        except Exception as e:
            print(f"[SEARCH ERROR] {e}")
        finally:
            conn.close()

    return render_template("index.html", user=user_info, search_results=search_results, keyword=keyword)


# ---------- URL 抓取 ----------
def is_internal_ip(host):
    """检查主机名解析后的 IP 是否为内网地址"""
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # 无法解析，后续 urlopen 会报错

    for addr in addrs:
        ip_str = addr[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return True
        except ValueError:
            continue
    return False


@app.route("/fetch-url", methods=["POST"])
@login_required
def fetch_url():
    target_url = request.form.get("url", "").strip()
    if not target_url:
        flash("请输入 URL")
        return redirect("/")

    # 1. 校验协议：只允许 http 和 https
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        flash("仅支持 http 和 https 协议的 URL")
        return redirect("/")

    # 2. 校验目标主机：不允许内网地址
    host = parsed.hostname
    if not host:
        flash("无效的 URL")
        return redirect("/")

    if is_internal_ip(host):
        flash("不允许访问内网地址")
        return redirect("/")

    fetch_result = None
    try:
        req = urllib.request.Request(target_url)
        resp = urllib.request.urlopen(req, timeout=10)
        status_code = resp.status
        raw = resp.read()
        content_type = resp.headers.get("Content-Type", "")
        try:
            content = raw.decode("utf-8")[:5000]
        except UnicodeDecodeError:
            content = raw.decode("latin-1")[:5000]
        fetch_result = {
            "url": target_url,
            "status_code": status_code,
            "content_type": content_type,
            "content": content,
        }
    except urllib.error.HTTPError as e:
        fetch_result = {
            "url": target_url,
            "status_code": e.code,
            "content_type": "",
            "content": f"HTTP 错误：{e.code} {e.reason}",
        }
    except Exception as e:
        fetch_result = {
            "url": target_url,
            "status_code": 0,
            "content_type": "",
            "content": f"请求失败：{str(e)}",
        }

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])

    return render_template("index.html", user=user_info, fetch_result=fetch_result)


@app.route("/login", methods=["GET", "POST"])
@csrf_required
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        if is_rate_limited(client_ip):
            return render_template("login.html", error="登录尝试过于频繁，请 60 秒后再试")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            session.permanent = True
            return render_template("index.html", user=safe_user_info(user))
        else:
            return render_template("login.html", error="用户名或密码错误")

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

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            flash("注册成功，请登录")
            return redirect("/login")
        except Exception as e:
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

        if not allowed_file(file.filename):
            return render_template("upload.html", error="仅支持上传图片文件（jpg、jpeg、png、gif、webp、bmp）")

        ext = file.filename.rsplit('.', 1)[1].lower()
        safe_name = f"{uuid.uuid4().hex}.{ext}"
        save_path = os.path.join(UPLOAD_FOLDER, safe_name)
        file.save(save_path)

        try:
            img = Image.open(save_path)
            img.verify()
        except Exception:
            os.remove(save_path)
            return render_template("upload.html", error="文件内容不是有效图片，请上传正确的图片文件")

        actual_size = os.path.getsize(save_path)
        if actual_size > MAX_AVATAR_SIZE:
            os.remove(save_path)
            return render_template("upload.html", error="图片文件过大，请上传 2MB 以内的图片")

        file_url = url_for("static", filename=f"uploads/{safe_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_name)

    return render_template("upload.html")


# ---------- 个人中心 ----------
@app.route("/profile")
@login_required
def profile():
    username = session.get("username")
    user = USERS.get(username)
    if not user:
        flash("用户不存在")
        return redirect("/")
    return render_template("profile.html", user=user)


# ---------- 充值 ----------
@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    username = session.get("username")
    user = USERS.get(username)
    if not user:
        flash("用户不存在")
        return redirect("/")

    amount = request.form.get("amount", type=float)

    # 检查金额是否为正数
    if amount is None or amount <= 0:
        flash("充值金额必须大于 0")
        return redirect("/profile")

    # 修改余额
    user["balance"] = user["balance"] + amount
    flash(f"充值成功，当前余额：{user['balance']}")
    return redirect("/profile")


# ---------- 修改密码 ----------
@app.route("/change-password", methods=["POST"])
@login_required
@csrf_required
def change_password():
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")

    if username in USERS:
        USERS[username]["password"] = generate_password_hash(new_password)
        flash(f"用户 {username} 的密码已修改")
    else:
        flash("用户不存在")

    return redirect("/profile")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


# ---------- 动态页面加载 ----------
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return render_template("index.html", page_content="请输入页面名称")

    # 使用 abspath + realpath 规范化路径，确保文件位于 pages/ 目录内
    requested_path = os.path.join(PAGES_DIR, name)
    real_path = os.path.realpath(requested_path)

    # 检查规范化后的路径是否以 pages 目录路径开头，防止路径穿越
    if not real_path.startswith(PAGES_DIR):
        content = "页面不存在"
    else:
        if os.path.exists(real_path):
            with open(real_path, encoding="utf-8") as f:
                content = f.read()
        else:
            # 尝试加 .html 后缀
            real_path_html = real_path + ".html"
            if os.path.exists(real_path_html):
                with open(real_path_html, encoding="utf-8") as f:
                    content = f.read()
            else:
                content = "页面不存在"

    # 获取首页需要的其他数据
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])

    return render_template("index.html", user=user_info, page_content=content)


# ---------- Ping 网络诊断 ----------
@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if not ip:
            return render_template("ping.html", error="请输入 IP 地址")

        # 使用 f-string 拼接系统命令，shell=True 执行
        command = f"ping -c 3 {ip}"
        try:
            output = subprocess.check_output(command, shell=True, timeout=30, stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            result = e.output.decode("utf-8", errors="replace") if e.output else f"命令执行失败：{e}"
        except subprocess.TimeoutExpired:
            result = "请求超时"
        except Exception as e:
            result = f"执行错误：{str(e)}"

        return render_template("ping.html", result=result, ip=ip)

    return render_template("ping.html")


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)
