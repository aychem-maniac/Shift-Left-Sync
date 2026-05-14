import sqlite3, secrets, hashlib, os
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "data/sls.db")

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'user',
                status        TEXT    NOT NULL DEFAULT 'pending',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
                approved_at   TEXT,
                approved_by   INTEGER REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token      TEXT    NOT NULL UNIQUE,
                created_at TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
                expires_at TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id      TEXT    NOT NULL UNIQUE,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                target      TEXT    NOT NULL,
                strength    TEXT    NOT NULL DEFAULT 'medium',
                status      TEXT    NOT NULL DEFAULT 'queued',
                progress    INTEGER NOT NULL DEFAULT 0,
                phase       TEXT    DEFAULT '대기 중',
                started_at  TEXT,
                finished_at TEXT,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS reports (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id           TEXT    NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                report_type      TEXT    NOT NULL,
                filename         TEXT    NOT NULL,
                total_count      INTEGER DEFAULT 0,
                confirmed_count  INTEGER DEFAULT 0,
                unverified_count INTEGER DEFAULT 0,
                high_count       INTEGER DEFAULT 0,
                medium_count     INTEGER DEFAULT 0,
                created_at       TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
            );
        """)
        conn.execute(
            "INSERT OR IGNORE INTO users (username,email,password_hash,role,status) VALUES (?,?,?,?,?)",
            ("admin", "admin@sls.local", hash_pw("admin1234"), "admin", "approved")
        )

def hash_pw(password):
    salt = "sls-static-salt-2026"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()

def verify_pw(password, hashed):
    return hash_pw(password) == hashed

def create_user(username, email, password):
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username,email,password_hash) VALUES (?,?,?)",
                (username, email, hash_pw(password))
            )
        return get_user_by_username(username)
    except sqlite3.IntegrityError:
        return None

def get_user_by_username(username):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None

def get_all_users():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

def update_user_status(user_id, status, approved_by=None):
    with get_conn() as conn:
        if status == "approved":
            conn.execute(
                "UPDATE users SET status=?,approved_at=datetime('now','localtime'),approved_by=? WHERE id=?",
                (status, approved_by, user_id)
            )
        else:
            conn.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))

def update_user_role(user_id, role):
    with get_conn() as conn:
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

def create_session(user_id):
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id,token,expires_at) VALUES (?,?,?)",
            (user_id, token, expires)
        )
    return token

def get_session_user(token):
    if not token:
        return None
    with get_conn() as conn:
        row = conn.execute("""
            SELECT u.* FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=? AND s.expires_at > datetime('now','localtime')
        """, (token,)).fetchone()
        return dict(row) if row else None

def delete_session(token):
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))

def create_job(job_id, user_id, target, strength):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_jobs (job_id,user_id,target,strength,started_at) VALUES (?,?,?,?,datetime('now','localtime'))",
            (job_id, user_id, target, strength)
        )
    return get_job(job_id)

def get_job(job_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            return None
        job = dict(row)
        job["reports"] = get_job_reports(job_id)
        return job

def update_job(job_id, **kwargs):
    if not kwargs:
        return
    sets = ", ".join(k + "=?" for k in kwargs)
    with get_conn() as conn:
        conn.execute("UPDATE scan_jobs SET " + sets + " WHERE job_id=?",
                     (*kwargs.values(), job_id))

def get_user_jobs(user_id):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_jobs WHERE user_id=? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        jobs = [dict(r) for r in rows]
        for j in jobs:
            j["reports"] = get_job_reports(j["job_id"])
        return jobs

def get_all_jobs():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT j.*, u.username FROM scan_jobs j
            JOIN users u ON u.id=j.user_id
            ORDER BY j.created_at DESC
        """).fetchall()
        jobs = [dict(r) for r in rows]
        for j in jobs:
            j["reports"] = get_job_reports(j["job_id"])
        return jobs

def save_report(job_id, report_type, filename, counts=None):
    c = counts or {}
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO reports (job_id,report_type,filename,total_count,confirmed_count,unverified_count,high_count,medium_count) VALUES (?,?,?,?,?,?,?,?)",
            (job_id, report_type, filename,
             c.get("total",0), c.get("confirmed",0),
             c.get("unverified",0), c.get("high",0), c.get("medium",0))
        )

def get_job_reports(job_id):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE job_id=? ORDER BY id", (job_id,)
        ).fetchall()
        return [dict(r) for r in rows]
