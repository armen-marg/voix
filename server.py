from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import hashlib
import os
import re
import secrets
import dns.resolver
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env file

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "voix-secret-key-2024"
socketio = SocketIO(app, cors_allowed_origins="*")

DB = "voix.db"

# ══════════════════════════════════════
# Database
# ══════════════════════════════════════

def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            email    TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            color    TEXT    NOT NULL DEFAULT '#5b9fff',
            token    TEXT    UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            name          TEXT PRIMARY KEY,
            password_hash TEXT,
            created_by    INTEGER,
            archived      INTEGER NOT NULL DEFAULT 0,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            room       TEXT    NOT NULL,
            author     TEXT    NOT NULL,
            text       TEXT    NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Migration: add columns if they don't exist (for existing databases)
    for col, definition in [
        ("created_by", "INTEGER"),
        ("archived",   "INTEGER NOT NULL DEFAULT 0"),
    ]:
        try:
            cur.execute(f"ALTER TABLE rooms ADD COLUMN {col} {definition}")
        except Exception:
            pass

    con.commit()
    con.close()

def hash_password(password):
    # SHA-256 + salt (using built-in Python PBKDF2 instead of bcrypt)
    salt = "voix_salt_2024"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()

init_db()

# ══════════════════════════════════════
# Online users
# ══════════════════════════════════════

rooms_users = {}  # { room_name: [ {id, name, color} ] }

# ══════════════════════════════════════
# Email validation via DNS (MX records)
# ══════════════════════════════════════

def validate_email_format(email):
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_email_dns(email):
    """
    Check that the email domain actually exists
    and has MX or A records (meaning it can receive mail).
    """
    try:
        domain = email.split("@")[1].lower()

        # First check MX records
        try:
            mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
            if mx_records:
                return True, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        # If no MX — check A record (fallback)
        try:
            a_records = dns.resolver.resolve(domain, "A", lifetime=5)
            if a_records:
                return True, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        return False, f"Domain '{domain}' does not exist or cannot receive mail"

    except Exception as e:
        return False, f"Domain check error: {str(e)}"

# ══════════════════════════════════════
# Token-based authentication
# ══════════════════════════════════════

def get_user_by_token(token):
    if not token:
        return None
    con = get_db()
    user = con.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    con.close()
    return user

# ══════════════════════════════════════
# HTTP routes — main
# ══════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

# ══════════════════════════════════════
# Registration
# ══════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
def register():
    data     = request.json
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "").strip()
    color    = (data.get("color")    or "#5b9fff").strip()

    # Field validation
    if not username:
        return jsonify({"error": "Enter a username"}), 400
    if len(username) < 2:
        return jsonify({"error": "Username too short (minimum 2 characters)"}), 400
    if len(username) > 32:
        return jsonify({"error": "Username too long (maximum 32 characters)"}), 400

    if not email:
        return jsonify({"error": "Enter an email"}), 400
    if not validate_email_format(email):
        return jsonify({"error": "Invalid email format"}), 400

    if not password:
        return jsonify({"error": "Enter a password"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password too short (minimum 6 characters)"}), 400

    # DNS check
    dns_ok, dns_error = validate_email_dns(email)
    if not dns_ok:
        return jsonify({"error": dns_error or "Email does not exist"}), 400

    con = get_db()

    # Check uniqueness
    if con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        con.close()
        return jsonify({"error": "Username already taken"}), 400
    if con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        con.close()
        return jsonify({"error": "This email is already registered"}), 400

    # Create user
    pw_hash = hash_password(password)
    token   = secrets.token_hex(32)

    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, email, password, color, token) VALUES (?,?,?,?,?)",
        (username, email, pw_hash, color, token)
    )
    user_id = cur.lastrowid
    con.commit()

    user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    con.close()

    return jsonify({
        "ok":         True,
        "token":      token,
        "user": {
            "id":         user["id"],
            "username":   user["username"],
            "email":      user["email"],
            "color":      user["color"],
            "created_at": user["created_at"],
        }
    })

# ══════════════════════════════════════
# Login
# ══════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.json
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"error": "Enter email and password"}), 400

    con = get_db()
    user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if not user or user["password"] != hash_password(password):
        con.close()
        return jsonify({"error": "Invalid email or password"}), 401

    # Update token on each login
    token = secrets.token_hex(32)
    con.execute("UPDATE users SET token=? WHERE id=?", (token, user["id"]))
    con.commit()
    con.close()

    return jsonify({
        "ok":    True,
        "token": token,
        "user": {
            "id":         user["id"],
            "username":   user["username"],
            "email":      user["email"],
            "color":      user["color"],
            "created_at": user["created_at"],
        }
    })

# ══════════════════════════════════════
# Token check (auto-login)
# ══════════════════════════════════════

@app.route("/api/auth/me", methods=["POST"])
def auth_me():
    data  = request.json
    token = (data.get("token") or "").strip()
    user  = get_user_by_token(token)
    if not user:
        return jsonify({"error": "Invalid token"}), 401
    return jsonify({
        "ok":  True,
        "user": {
            "id":         user["id"],
            "username":   user["username"],
            "email":      user["email"],
            "color":      user["color"],
            "created_at": user["created_at"],
        }
    })

# ══════════════════════════════════════
# DNS email check (for real-time validation)
# ══════════════════════════════════════

@app.route("/api/auth/check-email", methods=["POST"])
def check_email():
    data  = request.json
    email = (data.get("email") or "").strip().lower()

    if not validate_email_format(email):
        return jsonify({"ok": False, "error": "Invalid email format"})

    # Check if email is taken
    con = get_db()
    taken = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    con.close()
    if taken:
        return jsonify({"ok": False, "error": "Email already registered"})

    # DNS check
    dns_ok, dns_error = validate_email_dns(email)
    if not dns_ok:
        return jsonify({"ok": False, "error": dns_error or "Email does not exist"})

    return jsonify({"ok": True})

# ══════════════════════════════════════
# Rooms
# ══════════════════════════════════════

@app.route("/api/rooms", methods=["GET"])
def get_rooms():
    con  = get_db()
    rows = con.execute("""
        SELECT r.name,
               r.created_by,
               r.archived,
               u.username as creator_name,
               (SELECT m2.text FROM messages m2 WHERE m2.room = r.name ORDER BY m2.id DESC LIMIT 1) as last_msg,
               (SELECT m3.created_at FROM messages m3 WHERE m3.room = r.name ORDER BY m3.id DESC LIMIT 1) as last_at
        FROM rooms r
        LEFT JOIN users u ON u.id = r.created_by
        ORDER BY COALESCE(last_at, r.created_at) DESC
    """).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/rooms/create", methods=["POST"])
def create_room():
    data     = request.json
    name     = (data.get("name")     or "").strip()
    password = (data.get("password") or "").strip()
    token    = (data.get("token")    or "").strip()

    if not name:
        return jsonify({"error": "Enter a room name"}), 400

    # Get creator by token
    user = get_user_by_token(token)
    creator_id = user["id"] if user else None

    con      = get_db()
    existing = con.execute("SELECT name FROM rooms WHERE name=?", (name,)).fetchone()
    if existing:
        con.close()
        return jsonify({"error": "Room already exists"}), 400

    pw_hash = hash_password(password) if password else ""
    con.execute(
        "INSERT INTO rooms (name, password_hash, created_by) VALUES (?,?,?)",
        (name, pw_hash, creator_id)
    )
    con.commit()
    con.close()
    return jsonify({"ok": True, "name": name})

# ── Delete room ──

@app.route("/api/rooms/delete", methods=["POST"])
def delete_room():
    data  = request.json
    name  = (data.get("name")  or "").strip()
    token = (data.get("token") or "").strip()

    user = get_user_by_token(token)
    if not user:
        return jsonify({"error": "Access denied"}), 401

    con  = get_db()
    room = con.execute("SELECT * FROM rooms WHERE name=?", (name,)).fetchone()
    if not room:
        con.close()
        return jsonify({"error": "Room not found"}), 404
    if room["created_by"] != user["id"]:
        con.close()
        return jsonify({"error": "Only the creator can delete the room"}), 403

    con.execute("DELETE FROM messages WHERE room=?", (name,))
    con.execute("DELETE FROM rooms WHERE name=?", (name,))
    con.commit()
    con.close()
    return jsonify({"ok": True})

# ── Archive / Unarchive room ──

@app.route("/api/rooms/archive", methods=["POST"])
def archive_room():
    data    = request.json
    name    = (data.get("name")    or "").strip()
    token   = (data.get("token")   or "").strip()
    archive = data.get("archive", True)   # True = archive, False = restore

    user = get_user_by_token(token)
    if not user:
        return jsonify({"error": "Access denied"}), 401

    con  = get_db()
    room = con.execute("SELECT * FROM rooms WHERE name=?", (name,)).fetchone()
    if not room:
        con.close()
        return jsonify({"error": "Room not found"}), 404
    if room["created_by"] != user["id"]:
        con.close()
        return jsonify({"error": "Only the creator can archive the room"}), 403

    con.execute("UPDATE rooms SET archived=? WHERE name=?", (1 if archive else 0, name))
    con.commit()
    con.close()
    return jsonify({"ok": True})

@app.route("/api/rooms/join", methods=["POST"])
def join_room_api():
    data     = request.json
    name     = (data.get("name")     or "").strip()
    password = (data.get("password") or "").strip()

    con  = get_db()
    room = con.execute("SELECT * FROM rooms WHERE name=?", (name,)).fetchone()
    if not room:
        con.close()
        return jsonify({"error": "Room not found"}), 404
    if room["password_hash"] and room["password_hash"] != hash_password(password):
        con.close()
        return jsonify({"error": "Wrong password"}), 403

    msgs = con.execute(
        "SELECT author, text, created_at FROM messages WHERE room=? ORDER BY id ASC",
        (name,)
    ).fetchall()
    con.close()
    return jsonify({"ok": True, "history": [dict(m) for m in msgs]})

@app.route("/api/turn")
def turn_credentials():
    import urllib.request, json as _json
    try:
        metered_user = os.environ.get("METERED_USERNAME", "")
        metered_key  = os.environ.get("METERED_API_KEY", "")
        url = f"https://{metered_user}.metered.live/api/v1/turn/credentials?apiKey={metered_key}"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = _json.loads(r.read())
        return jsonify(data)
    except Exception:
        return jsonify([{"urls": "stun:stun.l.google.com:19302"}])

# ══════════════════════════════════════
# Socket.IO
# ══════════════════════════════════════

@socketio.on("join")
def on_join(data):
    room  = data.get("room")
    name  = data.get("name", "Anon")
    color = data.get("color", "#5b9fff")
    sid   = request.sid
    join_room(room)
    if room not in rooms_users:
        rooms_users[room] = []
    rooms_users[room] = [u for u in rooms_users[room] if u["id"] != sid]
    rooms_users[room].append({"id": sid, "name": name, "color": color})
    emit("users", {"room": room, "users": rooms_users[room]}, to=room)

@socketio.on("leave")
def on_leave(data):
    room = data.get("room")
    sid  = request.sid
    leave_room(room)
    if room in rooms_users:
        rooms_users[room] = [u for u in rooms_users[room] if u["id"] != sid]
        emit("users", {"room": room, "users": rooms_users[room]}, to=room)

@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    for room, users in list(rooms_users.items()):
        if any(u["id"] == sid for u in users):
            rooms_users[room] = [u for u in users if u["id"] != sid]
            emit("users", {"room": room, "users": rooms_users[room]}, to=room)

@socketio.on("message")
def on_message(data):
    room = data.get("room")
    name = data.get("name", "Anon")
    text = data.get("text", "")
    if not text or not room:
        return
    con = get_db()
    con.execute("INSERT INTO messages (room, author, text) VALUES (?,?,?)", (room, name, text))
    con.commit()
    con.close()
    emit("message", {
        "id":    data.get("id"),
        "name":  name,
        "color": data.get("color", "#5b9fff"),
        "text":  text,
        "room":  room,
    }, to=room)

@socketio.on("typing")
def on_typing(data):
    emit("typing", data, to=data.get("room"), include_self=False)

@socketio.on("speaking")
def on_speaking(data):
    emit("speaking", data, to=data.get("room"), include_self=False)

@socketio.on("offer")
def on_offer(data):
    emit("offer", data, to=data.get("to"))

@socketio.on("answer")
def on_answer(data):
    emit("answer", data, to=data.get("to"))

@socketio.on("ice")
def on_ice(data):
    emit("ice", data, to=data.get("to"))

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8080, debug=True)