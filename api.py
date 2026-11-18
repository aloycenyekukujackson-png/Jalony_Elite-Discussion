#!/usr/bin/env python3
"""JALONY_ELITE DISCUSSION API.

Hakuna dependency za nje: inaendeshwa kwa Python 3.9+ tu.
    python3 api.py                     # PORT=8000, DB_PATH=jalony.db
    PORT=8080 DB_PATH=/data/jalony.db python3 api.py

Endpoints (zote ni JSON; zinazohitaji login zinatumia "Authorization: Bearer <token>"):
    GET  /api/health
    POST /api/register     {name,email,mobile,reg_no,password}   -> {token,user}
    POST /api/login        {login,password}  (login = email au reg_no) -> {token,user}
    POST /api/logout                                              -> {ok}
    GET  /api/me                                                  -> {user}
    GET  /api/students                                            -> [{name,reg_no}]
    POST /api/results      {quiz_title,score,total,questions,answers,taken_at} -> {id}
    GET  /api/results                                             -> [matokeo yako]
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DB_PATH = os.environ.get("DB_PATH", "jalony.db")
PORT = int(os.environ.get("PORT", "8000"))
TOKEN_DAYS = 30
PBKDF2_ITER = 200_000
LOCK = threading.Lock()  # SQLite: ombi moja kwa wakati mmoja, salama na rahisi

SCHEMA = """
create table if not exists users(
  id integer primary key autoincrement,
  name text not null,
  email text not null unique,
  mobile text not null,
  reg_no text not null unique,
  pw_salt text not null,
  pw_hash text not null,
  created_at integer not null
);
create table if not exists sessions(
  token_hash text primary key,
  user_id integer not null references users(id) on delete cascade,
  expires_at integer not null
);
create table if not exists quiz_results(
  id integer primary key autoincrement,
  user_id integer not null references users(id) on delete cascade,
  name text not null,
  quiz_title text not null,
  score integer not null,
  total integer not null,
  questions text not null,
  answers text not null,
  taken_at integer not null
);
create index if not exists quiz_results_user_idx on quiz_results(user_id, taken_at desc);
"""


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def now_ms():
    return int(datetime.now().timestamp() * 1000)


def iso(ms):
    return datetime.fromtimestamp(ms / 1000).astimezone().isoformat()


def db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITER)
    return salt.hex(), h.hex()


def check_pw(pw, salt_hex, hash_hex):
    _, h = hash_pw(pw, bytes.fromhex(salt_hex))
    return secrets.compare_digest(h, hash_hex)


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def issue_token(c, uid):
    tok = secrets.token_urlsafe(32)
    c.execute("insert into sessions(token_hash,user_id,expires_at) values(?,?,?)",
              (sha(tok), uid, now_ms() + TOKEN_DAYS * 86_400_000))
    return tok


def current_user(c, header):
    if not header or not header.startswith("Bearer "):
        raise ApiError(401, "login required")
    tok = header[7:].strip()
    u = c.execute(
        "select u.* from sessions s join users u on u.id = s.user_id "
        "where s.token_hash = ? and s.expires_at > ?",
        (sha(tok), now_ms())).fetchone()
    if not u:
        raise ApiError(401, "login required")
    return u, tok


def pub(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"],
            "mobile": u["mobile"], "reg_no": u["reg_no"]}


def register(b, c):
    name = str(b.get("name", "")).strip()[:120]
    email = str(b.get("email", "")).strip().lower()[:200]
    mobile = str(b.get("mobile", "")).strip()[:30]
    reg = str(b.get("reg_no", "")).strip().upper()[:40]
    pw = str(b.get("password", ""))
    if not all([name, email, mobile, reg, pw]):
        raise ApiError(400, "missing fields")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ApiError(400, "invalid email")
    if len(pw) < 6:
        raise ApiError(400, "password must be at least 6 characters")
    if c.execute("select 1 from users where email = ? or reg_no = ?", (email, reg)).fetchone():
        raise ApiError(409, "email or reg_no already registered")
    salt, hh = hash_pw(pw)
    cur = c.execute(
        "insert into users(name,email,mobile,reg_no,pw_salt,pw_hash,created_at) values(?,?,?,?,?,?,?)",
        (name, email, mobile, reg, salt, hh, now_ms()))
    uid = cur.lastrowid
    u = c.execute("select * from users where id = ?", (uid,)).fetchone()
    return 201, {"token": issue_token(c, uid), "user": pub(u)}


def login(b, c):
    key = str(b.get("login", "")).strip()
    pw = str(b.get("password", ""))
    if not key or not pw:
        raise ApiError(400, "missing fields")
    if "@" in key:
        u = c.execute("select * from users where email = ?", (key.lower(),)).fetchone()
    else:
        u = c.execute("select * from users where reg_no = ?", (key.upper(),)).fetchone()
    if not u or not check_pw(pw, u["pw_salt"], u["pw_hash"]):
        raise ApiError(401, "wrong credentials")
    return 200, {"token": issue_token(c, u["id"]), "user": pub(u)}


def parse_taken(v):
    if v is None or v == "":
        return now_ms()
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        raise ApiError(400, "bad taken_at")


def post_result(b, c, u):
    try:
        score, total = int(b["score"]), int(b["total"])
    except (KeyError, TypeError, ValueError):
        raise ApiError(400, "score and total are required")
    if total <= 0 or score < 0 or score > total:
        raise ApiError(400, "invalid score")
    title = str(b.get("quiz_title", "Quiz"))[:200]
    qs = b.get("questions", [])
    ans = b.get("answers", {})
    if not isinstance(qs, list) or not isinstance(ans, dict):
        raise ApiError(400, "questions must be a list, answers an object")
    cur = c.execute(
        "insert into quiz_results(user_id,name,quiz_title,score,total,questions,answers,taken_at) "
        "values(?,?,?,?,?,?,?,?)",
        (u["id"], u["name"], title, score, total, json.dumps(qs, ensure_ascii=False),
         json.dumps(ans, ensure_ascii=False), parse_taken(b.get("taken_at"))))
    return 201, {"id": cur.lastrowid}


def list_results(c, u):
    rows = c.execute("select * from quiz_results where user_id = ? order by taken_at desc", (u["id"],)).fetchall()
    return 200, [{"id": r["id"], "name": r["name"], "quiz_title": r["quiz_title"],
                  "score": r["score"], "total": r["total"],
                  "questions": json.loads(r["questions"]), "answers": json.loads(r["answers"]),
                  "taken_at": iso(r["taken_at"])} for r in rows]


def dispatch(h, c, method, path):
    if method == "GET" and path == "/api/health":
        return 200, {"ok": True}
    if method == "POST" and path == "/api/register":
        return register(h.read_json(), c)
    if method == "POST" and path == "/api/login":
        return login(h.read_json(), c)
    if method == "POST" and path == "/api/logout":
        u, tok = current_user(c, h.headers.get("Authorization"))
        c.execute("delete from sessions where token_hash = ?", (sha(tok),))
        return 200, {"ok": True}
    if method == "GET" and path == "/api/me":
        u, _ = current_user(c, h.headers.get("Authorization"))
        return 200, {"user": pub(u)}
    if method == "GET" and path == "/api/students":
        current_user(c, h.headers.get("Authorization"))
        rows = c.execute("select name, reg_no from users order by name").fetchall()
        return 200, [{"name": r["name"], "reg_no": r["reg_no"]} for r in rows]
    if method == "POST" and path == "/api/results":
        u, _ = current_user(c, h.headers.get("Authorization"))
        return post_result(h.read_json(), c, u)
    if method == "GET" and path == "/api/results":
        u, _ = current_user(c, h.headers.get("Authorization"))
        return list_results(c, u)
    raise ApiError(404, "not found")


class Handler(BaseHTTPRequestHandler):
    server_version = "JalonyAPI/1.0"

    def log_message(self, *args):
        pass

    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2_000_000:
            raise ApiError(413, "payload too large")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise ApiError(400, "invalid json")
        if not isinstance(data, dict):
            raise ApiError(400, "expected a JSON object")
        return data

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.end_headers()

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            with LOCK:
                c = db()
                try:
                    code, obj = dispatch(self, c, method, path)
                    c.commit()
                finally:
                    c.close()
            self.send_json(code, obj)
        except ApiError as e:
            self.send_json(e.code, {"error": e.msg})
        except Exception:
            self.send_json(500, {"error": "server error"})


def init_db():
    c = db()
    c.executescript(SCHEMA)
    c.commit()
    c.close()


if __name__ == "__main__":
    init_db()
    print(f"JALONY API inaendelea kwenye port {PORT} (db: {DB_PATH})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
