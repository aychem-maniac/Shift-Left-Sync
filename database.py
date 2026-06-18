import sqlite3, secrets, hashlib, os
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "data/sls.db")

@contextmanager
# SQLite 연결을 열고 트랜잭션 commit/rollback/close를 공통 처리한다.
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

# 필요한 DB 디렉터리와 테이블/인덱스를 생성하고 기본 관리자 계정을 보장한다.
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
            CREATE TABLE IF NOT EXISTS verify_tokens (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id      TEXT    NOT NULL UNIQUE REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                token       TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'pending',
                method      TEXT,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
                verified_at TEXT
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
            CREATE TABLE IF NOT EXISTS verified_targets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT    NOT NULL UNIQUE,
                user_id     INTEGER REFERENCES users(id),
                verified_at TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
                expires_at  TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                source         TEXT    NOT NULL DEFAULT 'waf',
                event_type     TEXT    NOT NULL DEFAULT 'rule_match',
                severity       TEXT    NOT NULL DEFAULT 'low',
                action         TEXT    NOT NULL DEFAULT 'detect',
                ip             TEXT,
                method         TEXT,
                path           TEXT,
                payload_sample TEXT,
                reason         TEXT,
                rule_id        TEXT,
                status_code    INTEGER,
                event_id       TEXT UNIQUE,
                raw_json       TEXT,
                created_at     TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS waf_ip_blocklist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL UNIQUE,
                reason      TEXT,
                source      TEXT    NOT NULL DEFAULT 'manual',
                created_by  INTEGER REFERENCES users(id),
                created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_security_events_created
                ON security_events(created_at);
            CREATE INDEX IF NOT EXISTS idx_security_events_filters
                ON security_events(source, severity, action);
            CREATE INDEX IF NOT EXISTS idx_waf_ip_blocklist_created
                ON waf_ip_blocklist(created_at);
        """)
        conn.execute(
            "INSERT OR IGNORE INTO users (username,email,password_hash,role,status) VALUES (?,?,?,?,?)",
            ("admin", "admin@sls.local", hash_pw("admin1234"), "admin", "approved")
        )

# 비밀번호를 고정 salt 기반 PBKDF2 해시로 변환한다.
def hash_pw(password):
    salt = "sls-static-salt-2026"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()

# 입력 비밀번호가 저장된 해시와 일치하는지 확인한다.
def verify_pw(password, hashed):
    return hash_pw(password) == hashed

# 신규 사용자를 pending 상태로 생성하고 생성된 사용자 정보를 반환한다.
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

# username으로 사용자 1명을 조회한다.
def get_user_by_username(username):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

# user_id로 사용자 1명을 조회한다.
def get_user_by_id(user_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None

# 거절 상태를 제외한 전체 사용자 목록을 최신순으로 조회한다.
def get_all_users():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM users WHERE status != 'rejected' ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

# 사용자 승인 상태를 변경하고 승인 시 승인 시간/승인자도 기록한다.
def update_user_status(user_id, status, approved_by=None):
    with get_conn() as conn:
        if status == "approved":
            conn.execute(
                "UPDATE users SET status=?,approved_at=datetime('now','localtime'),approved_by=? WHERE id=?",
                (status, approved_by, user_id)
            )
        else:
            conn.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))

# 사용자의 역할을 admin/user 값으로 변경한다.
def update_user_role(user_id, role):
    with get_conn() as conn:
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

# 사용자를 삭제한다. 연결된 세션/스캔/리포트는 외래키 CASCADE로 함께 정리된다.
def delete_user(user_id):
    with get_conn() as conn:
        # 세션, 스캔잡, 리포트는 CASCADE로 자동 삭제
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))

# 로그인 세션 토큰을 생성하고 24시간 만료 시각과 함께 저장한다.
def create_session(user_id):
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id,token,expires_at) VALUES (?,?,?)",
            (user_id, token, expires)
        )
    return token

# 세션 토큰이 유효하면 연결된 사용자 정보를 반환한다.
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

# 로그아웃 시 세션 토큰을 삭제한다.
def delete_session(token):
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))

# 새 스캔 작업을 생성하고 생성된 작업 정보를 반환한다.
def create_job(job_id, user_id, target, strength):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_jobs (job_id,user_id,target,strength,started_at) VALUES (?,?,?,?,datetime('now','localtime'))",
            (job_id, user_id, target, strength)
        )
    return get_job(job_id)

# job_id로 스캔 작업 1건과 연결된 리포트 목록을 조회한다.
def get_job(job_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            return None
        job = dict(row)
        job["reports"] = get_job_reports(job_id)
        return job

# 전달된 필드만 골라 스캔 작업 상태/진행률/단계 등을 갱신한다.
def update_job(job_id, **kwargs):
    if not kwargs:
        return
    sets = ", ".join(k + "=?" for k in kwargs)
    with get_conn() as conn:
        conn.execute("UPDATE scan_jobs SET " + sets + " WHERE job_id=?",
                     (*kwargs.values(), job_id))

# 특정 사용자의 스캔 작업 목록과 각 작업의 리포트를 최신순으로 조회한다.
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

# 관리자 화면용으로 전체 스캔 작업과 요청자 username, 리포트 목록을 조회한다.
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

# 스캔 결과 리포트 파일 정보와 취약점 집계 값을 저장한다.
def save_report(job_id, report_type, filename, counts=None):
    c = counts or {}
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO reports (job_id,report_type,filename,total_count,confirmed_count,unverified_count,high_count,medium_count) VALUES (?,?,?,?,?,?,?,?)",
            (job_id, report_type, filename,
             c.get("total",0), c.get("confirmed",0),
             c.get("unverified",0), c.get("high",0), c.get("medium",0))
        )

# 특정 스캔 작업에 연결된 리포트 목록을 조회한다.
def get_job_reports(job_id):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE job_id=? ORDER BY id", (job_id,)
        ).fetchall()
        return [dict(r) for r in rows]


# WAF/SOAR 보안 이벤트 1건을 security_events 테이블에 저장한다.
# event_id가 같으면 INSERT OR IGNORE로 중복 적재를 막는다.
# WAF/SOAR 보안 이벤트 1건을 저장하고 event_id 기준 중복 적재를 막는다.
def log_security_event(
    source="waf",
    event_type="rule_match",
    severity="low",
    action="detect",
    ip=None,
    method=None,
    path=None,
    payload_sample=None,
    reason=None,
    rule_id=None,
    status_code=None,
    event_id=None,
    raw_json=None,
):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO security_events
            (source,event_type,severity,action,ip,method,path,payload_sample,
             reason,rule_id,status_code,event_id,raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                source,
                event_type,
                severity,
                action,
                ip,
                method,
                path,
                payload_sample,
                reason,
                rule_id,
                status_code,
                event_id,
                raw_json,
            ),
        )
        return cur.rowcount > 0


# 관리자 화면과 API에서 사용할 보안 이벤트 목록을 조회한다.
# view=detect는 실제 탐지 중심, view=context는 SOAR 대응/요약 로그 중심으로 나눈다.
# 관리자 화면/API에서 사용할 보안 이벤트 목록을 필터와 탭 기준으로 조회한다.
def get_security_events(source=None, severity=None, action=None, limit=100, view="detect"):
    where = []
    params = []
    # 기본 탭은 실제 탐지 중심으로 보여주고, SOAR 대응/CRS 요약 룰은 보조 탭으로 분리한다.
    if view == "context":
        where.append("(source=? OR event_type=?)")
        params.extend(["soar", "anomaly_summary"])
    else:
        where.append("(source!=? AND event_type!=?)")
        params.extend(["soar", "anomaly_summary"])
    if source:
        where.append("source=?")
        params.append(source)
    if severity:
        where.append("severity=?")
        params.append(severity)
    if action:
        where.append("action=?")
        params.append(action)

    sql = "SELECT * FROM security_events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


# 보안 이벤트 화면 상단 카드에 표시할 집계 값을 계산한다.
# 보안 이벤트 화면 상단 카드에 표시할 전체/위험도/동작별 집계 값을 계산한다.
def get_security_event_stats():
    def grouped(conn, field):
        rows = conn.execute(
            f"SELECT {field} AS name, COUNT(*) AS count FROM security_events GROUP BY {field}"
        ).fetchall()
        return {r["name"]: r["count"] for r in rows}

    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS count FROM security_events").fetchone()["count"]
        high_critical = conn.execute(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity IN ('high','critical')"
        ).fetchone()["count"]
        return {
            "total": total,
            "high_critical": high_critical,
            "by_source": grouped(conn, "source"),
            "by_severity": grouped(conn, "severity"),
            "by_action": grouped(conn, "action"),
            "waf_detect": conn.execute(
                "SELECT COUNT(*) AS count FROM security_events WHERE source='waf' AND action='detect'"
            ).fetchone()["count"],
            "waf_block": conn.execute(
                "SELECT COUNT(*) AS count FROM security_events WHERE source='waf' AND action='block'"
            ).fetchone()["count"],
        }


# security_events 테이블이 과도하게 커지지 않도록 최신 N건만 남기고 정리한다.
def add_waf_block_ip(ip, reason=None, source="manual", created_by=None):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO waf_ip_blocklist (ip, reason, source, created_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                reason=excluded.reason,
                source=excluded.source,
                created_by=excluded.created_by,
                created_at=datetime('now','localtime')
            """,
            (ip, reason, source, created_by),
        )
    return get_waf_block_ip(ip)


def remove_waf_block_ip(ip):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM waf_ip_blocklist WHERE ip=?", (ip,))
        return cur.rowcount > 0


def get_waf_block_ip(ip):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM waf_ip_blocklist WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None


def get_waf_blocklist():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM waf_ip_blocklist ORDER BY created_at DESC, id DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def is_waf_blocked_ip(ip):
    return get_waf_block_ip(ip) is not None


def prune_security_events(keep_latest=5000):
    with get_conn() as conn:
        conn.execute(
            """
            DELETE FROM security_events
            WHERE id NOT IN (
                SELECT id FROM security_events ORDER BY created_at DESC, id DESC LIMIT ?
            )
            """,
            (keep_latest,),
        )


# ── 소유권 인증 ──────────────────────────────────────────────
# 스캔 대상 소유권 검증에 사용할 토큰을 작업별로 생성/갱신한다.
def create_verify_token(job_id, token, target):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO verify_tokens (job_id,token,target) VALUES (?,?,?)",
            (job_id, token, target)
        )

# job_id에 연결된 소유권 검증 토큰 정보를 조회한다.
def get_verify_token(job_id):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM verify_tokens WHERE job_id=?", (job_id,)
        ).fetchone()
        return dict(row) if row else None

# 소유권 검증 상태와 검증 방법을 갱신하고 검증 시각을 기록한다.
def update_verify_status(job_id, status, method=None):
    with get_conn() as conn:
        conn.execute(
            "UPDATE verify_tokens SET status=?, method=?, verified_at=datetime('now','localtime') WHERE job_id=?",
            (status, method, job_id)
        )

# ── 소유권 인증 캐시 (24시간) ────────────────────────────────────

# 24시간 내 유효한 소유권 검증 캐시가 있는지 조회한다.
def get_verified_target(target: str) -> dict | None:
    """24시간 이내 유효한 소유권 인증 기록 조회. 없거나 만료 시 None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM verified_targets "
            "WHERE target=? AND expires_at > datetime('now','localtime')",
            (target,)
        ).fetchone()
        return dict(row) if row else None


# 소유권 검증 성공 대상을 24시간 유효 캐시로 저장하거나 갱신한다.
def upsert_verified_target(target: str, user_id: int) -> None:
    """소유권 인증 성공 시 24시간 캐시 저장 (동일 타겟이면 갱신)."""
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO verified_targets (target, user_id, verified_at, expires_at)
               VALUES (?, ?, datetime('now','localtime'),
                       datetime('now','localtime','+24 hours'))
               ON CONFLICT(target) DO UPDATE SET
                   user_id     = excluded.user_id,
                   verified_at = excluded.verified_at,
                   expires_at  = excluded.expires_at""",
            (target, user_id)
        )
