from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Query, Request, Form
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel
import uuid, os, asyncio
from datetime import datetime
from database import (
    init_db, create_user, get_user_by_username,
    get_all_users, update_user_status, update_user_role,
    create_session, get_session_user, delete_session,
    create_job, get_job, update_job, get_user_jobs, get_all_jobs,
    save_report, verify_pw
)

app = FastAPI(title="Shift-Left-Sync")
scan_lock = asyncio.Lock()
API_KEY   = os.getenv("API_KEY", "sls-secret-2026")

@app.on_event("startup")
async def startup():
    init_db()

# ── CSS ─────────────────────────────────────────────────────
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e0e0e0;min-height:100vh}
a{color:#64b5f6;text-decoration:none}
.header{background:linear-gradient(135deg,#1a1f2e,#2d3561);padding:18px 32px;
  border-bottom:1px solid #2d3561;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:20px;color:#64b5f6}
.header-right{display:flex;gap:10px;align-items:center}
.user-badge{font-size:12px;color:#aaa;padding:4px 10px;background:#1a1f2e;
  border:1px solid #2d3561;border-radius:6px}
.container{max-width:1000px;margin:28px auto;padding:0 20px}
.card{background:#1a1f2e;border:1px solid #2d3561;border-radius:12px;padding:22px;margin-bottom:16px}
.card h2{font-size:15px;color:#64b5f6;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #2d3561}
label{font-size:12px;color:#888;display:block;margin-bottom:4px}
input[type=text],input[type=password],input[type=email],select{
  width:100%;background:#0f1117;border:1px solid #2d3561;color:#e0e0e0;
  padding:9px 13px;border-radius:8px;font-size:13px;outline:none;margin-bottom:12px}
input:focus,select:focus{border-color:#64b5f6}
.btn{background:#1565c0;color:white;border:none;padding:9px 20px;
  border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;transition:.2s}
.btn:hover{background:#1976d2}
.btn-sm{background:#2d3561;color:#ccc;padding:5px 12px;border-radius:6px;
  border:none;cursor:pointer;font-size:12px}
.btn-sm:hover{background:#3d4571}
.btn-danger{background:#7f1d1d;color:#fca5a5}
.btn-danger:hover{background:#991b1b}
.btn-success{background:#14532d;color:#86efac}
.btn-success:hover{background:#166534}
.btn-warn{background:#78350f;color:#fcd34d}
.btn-warn:hover{background:#92400e}
.badge{display:inline-block;font-size:11px;font-weight:bold;padding:2px 9px;border-radius:10px}
.pending{background:#333;color:#aaa}
.queued{background:#2a2a1a;color:#ffd54f}
.running{background:#1a3a5c;color:#64b5f6}
.done{background:#1a3a2a;color:#66bb6a}
.error{background:#3a1a1a;color:#ef5350}
.approved{background:#14532d;color:#86efac}
.rejected{background:#7f1d1d;color:#fca5a5}
.admin-role{background:#312e81;color:#a5b4fc}
.user-role{background:#1e3a5f;color:#93c5fd}
.progress-wrap{background:#0f1117;border-radius:6px;overflow:hidden;height:7px;margin:7px 0}
.progress-bar{height:100%;background:linear-gradient(90deg,#1565c0,#64b5f6);transition:width .5s;border-radius:6px}
.job-card{background:#0f1117;border:1px solid #2d3561;border-radius:8px;padding:12px 16px;margin-bottom:10px}
.job-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px}
.job-id{font-family:monospace;font-size:12px;color:#64b5f6}
.report-link{font-size:11px;background:#1a3a5c;color:#64b5f6;padding:2px 8px;
  border-radius:4px;margin-right:4px;text-decoration:none}
.report-link:hover{background:#1976d2;color:white}
.info-box{background:#1a2a3a;border:1px solid #2d4a6a;border-radius:8px;
  padding:10px 14px;margin-bottom:12px;font-size:12px;color:#90caf9}
.err-box{background:#2d1010;border:1px solid #7f1d1d;border-radius:8px;
  padding:10px 14px;margin-bottom:12px;font-size:12px;color:#fca5a5}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#0f1117;color:#888;padding:8px 12px;text-align:left;border-bottom:1px solid #2d3561}
td{padding:8px 12px;border-bottom:1px solid #1a2a3a;vertical-align:middle}
tr:hover td{background:#111827}
.tab{display:flex;gap:0;margin-bottom:16px;border-bottom:1px solid #2d3561}
.tab-btn{background:none;border:none;color:#888;padding:8px 18px;cursor:pointer;
  font-size:13px;border-bottom:2px solid transparent;transition:.2s}
.tab-btn.active{color:#64b5f6;border-bottom-color:#64b5f6}
"""

# ── JS (f-string 완전 분리) ──────────────────────────────────
DASHBOARD_JS = """
<script>
var pollTimers = {};

function labelOf(f) {
  if (f.indexOf('simple') >= 0)       return '📄 간편';
  if (f.indexOf('report.html') >= 0)  return '🔧 전문가';
  if (f.indexOf('full.json') >= 0)    return '📦 JSON';
  if (f.indexOf('confirmed') >= 0)    return '✅ 확정';
  if (f.indexOf('unverified') >= 0)   return '⚠️ 수동검토';
  if (f.indexOf('false_positive') >= 0) return '❌ 오탐';
  if (f.indexOf('full.csv') >= 0)     return '📊 전체CSV';
  return '📄';
}

function buildReportLinks(reports, job_id) {
  return (reports || []).map(function(r) {
    return '<a class="report-link" href="/report/' + r.filename +
           '?job=' + job_id + '" target="_blank">' + labelOf(r.filename) + '</a>';
  }).join('');
}

function updateJobEl(el, j) {
  var pct      = j.progress || 0;
  var isActive = j.status === 'running' || j.status === 'queued';
  var progress = isActive
    ? '<div class="progress-wrap"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
      '<div style="font-size:11px;color:#64b5f6">' + (j.phase || '') + '</div>'
    : '';
  var reports = buildReportLinks(j.reports, j.job_id);
  el.innerHTML =
    '<div class="job-header">' +
      '<span class="job-id">Job: ' + j.job_id + '</span>' +
      '<span class="badge ' + j.status + '">' + j.status + (isActive ? ' ' + pct + '%' : '') + '</span>' +
    '</div>' +
    '<div style="font-size:12px;color:#888;margin-bottom:4px">' +
      '🎯 ' + j.target + ' &nbsp;|&nbsp; 강도: ' + j.strength +
      ' &nbsp;|&nbsp; ' + (j.created_at || '').slice(0, 16) +
    '</div>' +
    progress +
    '<div style="margin-top:6px">' + reports + '</div>';
}

function prependJob(j) {
  var div = document.createElement('div');
  div.id = 'job-' + j.job_id;
  div.className = 'job-card';
  updateJobEl(div, j);
  var container = document.getElementById('jobs');
  container.insertBefore(div, container.firstChild);
}

async function startScan() {
  var target   = document.getElementById('target').value.trim();
  var strength = document.getElementById('strength').value;
  if (!target) { alert('URL을 입력하세요'); return; }
  document.getElementById('scan-msg').textContent = '스캔 요청 중...';
  try {
    var res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target, strength: strength })
    });
    if (res.status === 401) { location.href = '/'; return; }
    var data = await res.json();
    document.getElementById('scan-msg').textContent = '✅ 요청됨 — Job: ' + data.job_id;
    prependJob(data);
    pollJob(data.job_id);
  } catch(e) {
    document.getElementById('scan-msg').textContent = '❌ 실패: ' + e.message;
  }
}

async function pollJob(job_id) {
  if (pollTimers[job_id]) return;
  pollTimers[job_id] = setInterval(async function() {
    var res = await fetch('/api/scan/' + job_id);
    if (!res.ok) return;
    var j = await res.json();
    var el = document.getElementById('job-' + job_id);
    if (el) updateJobEl(el, j);
    if (j.status === 'done' || j.status === 'error') {
      clearInterval(pollTimers[job_id]);
      delete pollTimers[job_id];
    }
  }, 4000);
}

// 페이지 로드 시 진행 중 잡 자동 폴링 재개
document.querySelectorAll('.job-card').forEach(function(el) {
  var id    = el.id.replace('job-', '');
  var badge = el.querySelector('.badge');
  if (badge && (badge.classList.contains('running') || badge.classList.contains('queued'))) {
    pollJob(id);
  }
});
</script>
"""

LOGIN_JS = """
<script>
function showTab(t) {
  document.getElementById('pane-login').style.display = t === 'login' ? 'block' : 'none';
  document.getElementById('pane-reg').style.display   = t === 'reg'   ? 'block' : 'none';
  document.getElementById('tab-login').className = 'tab-btn' + (t === 'login' ? ' active' : '');
  document.getElementById('tab-reg').className   = 'tab-btn' + (t === 'reg'   ? ' active' : '');
}
</script>
"""

# ── 공통 헬퍼 ───────────────────────────────────────────────
def _report_label(filename):
    if "simple"         in filename: return "📄 간편"
    if "report.html"    in filename: return "🔧 전문가"
    if "full.json"      in filename: return "📦 JSON"
    if "confirmed"      in filename: return "✅ 확정"
    if "unverified"     in filename: return "⚠️ 수동검토"
    if "false_positive" in filename: return "❌ 오탐"
    if "full.csv"       in filename: return "📊 전체CSV"
    return "📄"

def _report_type(filename):
    if "simple"         in filename: return "simple_html"
    if "report.html"    in filename: return "expert_html"
    if "confirmed"      in filename: return "csv_confirmed"
    if "unverified"     in filename: return "csv_unverified"
    if "false_positive" in filename: return "csv_fp"
    if "full.csv"       in filename: return "csv_full"
    if "full.json"      in filename: return "json_full"
    return "other"

def _current_user(request):
    token = request.cookies.get("sls_session")
    return get_session_user(token) if token else None

def _page(title, body, user=None, extra_js=""):
    admin_btn = ""
    if user and user.get("role") == "admin":
        admin_btn = '<a href="/admin" class="btn btn-warn" style="font-size:12px;padding:6px 14px">⚙️ 관리자</a>'
    logout_btn = '<a href="/auth/logout" class="btn-sm">로그아웃</a>' if user else ""
    icon = "👑" if user and user.get("role") == "admin" else "👤"
    user_badge = ('<span class="user-badge">' + icon + " " + user["username"] + "</span>") if user else ""
    return (
        "<!DOCTYPE html><html lang='ko'><head><meta charset='UTF-8'>"
        "<title>" + title + " — Shift-Left-Sync</title>"
        "<style>" + CSS + "</style></head><body>"
        "<div class='header'>"
        "<h1>🛡️ Shift-Left-Sync</h1>"
        "<div class='header-right'>" + user_badge + admin_btn + logout_btn + "</div>"
        "</div>"
        "<div class='container'>" + body + "</div>"
        + extra_js +
        "</body></html>"
    )

# ═══════════════════════════════════════════════════════════
# 1. 메인 — 로그인 / 회원가입
# ═══════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: str = ""):
    u = _current_user(request)
    if u and u.get("status") == "approved":
        return RedirectResponse("/dashboard")

    err  = ('<div class="err-box">'  + msg + "</div>") if msg else ""
    info = ""
    if u and u.get("status") == "pending":
        info = '<div class="info-box">⏳ 계정이 관리자 승인 대기 중입니다. 승인 후 로그인 가능합니다.</div>'

    show_reg = "true" if msg and ("이미" in msg or "회원가입" in msg) else "false"

    body = (
        err + info +
        "<div class='card' style='max-width:420px;margin:60px auto'>"
        "<div class='tab'>"
        "<button class='tab-btn active' id='tab-login' onclick=\"showTab('login')\">🔐 로그인</button>"
        "<button class='tab-btn' id='tab-reg' onclick=\"showTab('reg')\">📝 회원가입</button>"
        "</div>"
        "<div id='pane-login'>"
        "<form method='post' action='/auth/login'>"
        "<label>아이디</label>"
        "<input type='text' name='username' placeholder='username' required>"
        "<label>비밀번호</label>"
        "<input type='password' name='password' placeholder='password' required>"
        "<button class='btn' style='width:100%'>로그인</button>"
        "</form></div>"
        "<div id='pane-reg' style='display:none'>"
        "<form method='post' action='/auth/register'>"
        "<label>아이디</label>"
        "<input type='text' name='username' placeholder='username (영문/숫자)' required>"
        "<label>이메일</label>"
        "<input type='email' name='email' placeholder='email@example.com' required>"
        "<label>비밀번호</label>"
        "<input type='password' name='password' placeholder='8자 이상' required>"
        "<button class='btn' style='width:100%;background:#14532d'>회원가입 신청</button>"
        "</form>"
        "<p style='font-size:11px;color:#666;margin-top:10px'>※ 회원가입 후 관리자 승인이 필요합니다.</p>"
        "</div></div>"
    )
    extra = LOGIN_JS + "<script>if(" + show_reg + "){showTab('reg');}</script>"
    return HTMLResponse(_page("로그인", body, extra_js=extra))


# ═══════════════════════════════════════════════════════════
# 인증 엔드포인트
# ═══════════════════════════════════════════════════════════
@app.post("/auth/login")
async def login(request: Request,
                username: str = Form(...),
                password: str = Form(...)):
    u = get_user_by_username(username)
    if not u or not verify_pw(password, u["password_hash"]):
        return RedirectResponse("/?msg=아이디 또는 비밀번호가 틀렸습니다", status_code=302)
    if u["status"] == "pending":
        return RedirectResponse("/?msg=관리자 승인 대기 중인 계정입니다", status_code=302)
    if u["status"] == "rejected":
        return RedirectResponse("/?msg=승인이 거부된 계정입니다", status_code=302)
    token = create_session(u["id"])
    resp  = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("sls_session", token, httponly=True, max_age=86400)
    return resp

@app.post("/auth/register")
async def register(username: str = Form(...),
                   email:    str = Form(...),
                   password: str = Form(...)):
    if len(password) < 8:
        return RedirectResponse("/?msg=비밀번호는 8자 이상이어야 합니다", status_code=302)
    u = create_user(username, email, password)
    if not u:
        return RedirectResponse("/?msg=이미 사용 중인 아이디 또는 이메일입니다", status_code=302)
    return RedirectResponse("/?msg=회원가입 완료! 관리자 승인 후 로그인 가능합니다", status_code=302)

@app.get("/auth/logout")
async def logout(request: Request):
    token = request.cookies.get("sls_session")
    if token:
        delete_session(token)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("sls_session")
    return resp


# ═══════════════════════════════════════════════════════════
# 2. 유저 대시보드
# ═══════════════════════════════════════════════════════════
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    u = _current_user(request)
    if not u or u.get("status") != "approved":
        return RedirectResponse("/")

    jobs = get_user_jobs(u["id"])
    job_cards = ""
    for j in jobs:
        reports_html = "".join(
            '<a class="report-link" href="/report/' + r["filename"] +
            '?job=' + j["job_id"] + '" target="_blank">' + _report_label(r["filename"]) + "</a>"
            for r in j.get("reports", [])
        )
        pct      = j.get("progress", 0)
        is_active = j["status"] in ("queued", "running")
        progress_html = (
            '<div class="progress-wrap"><div class="progress-bar" style="width:' + str(pct) + '%"></div></div>'
            '<div style="font-size:11px;color:#64b5f6">' + str(j.get("phase", "")) + "</div>"
        ) if is_active else ""
        status_label = j["status"] + (" " + str(pct) + "%" if is_active else "")
        job_cards += (
            '<div class="job-card" id="job-' + j["job_id"] + '">'
            '<div class="job-header">'
            '<span class="job-id">Job: ' + j["job_id"] + "</span>"
            '<span class="badge ' + j["status"] + '">' + status_label + "</span>"
            "</div>"
            '<div style="font-size:12px;color:#888;margin-bottom:4px">'
            "🎯 " + j["target"] + " &nbsp;|&nbsp; 강도: " + j["strength"] +
            " &nbsp;|&nbsp; " + str(j.get("created_at", ""))[:16] +
            "</div>" + progress_html +
            '<div style="margin-top:6px">' + reports_html + "</div>"
            "</div>"
        )

    if not job_cards:
        job_cards = '<div style="color:#555;font-size:13px;padding:20px 0">아직 스캔 기록이 없습니다.</div>'

    body = (
        "<div class='card'>"
        "<h2>🔍 새 스캔</h2>"
        "<div class='info-box'>⚠️ 스캔은 순차 처리됩니다. 진행 중 스캔이 있으면 대기 상태가 됩니다.</div>"
        "<div style='display:flex;gap:8px;margin-bottom:10px'>"
        "<input type='text' id='target' placeholder='http://example.com' style='margin:0'>"
        "<select id='strength' style='margin:0;width:220px'>"
        "<option value='low'>🔵 low — 빠른 점검</option>"
        "<option value='medium' selected>🟠 medium — 표준 점검</option>"
        "<option value='high'>🔴 high — 심화 점검</option>"
        "</select>"
        "<button class='btn' onclick='startScan()'>▶ 시작</button>"
        "</div>"
        "<div id='scan-msg' style='font-size:12px;color:#888;min-height:16px'></div>"
        "</div>"
        "<div class='card'>"
        "<h2>📋 내 스캔 기록</h2>"
        "<div id='jobs'>" + job_cards + "</div>"
        "</div>"
    )
    return HTMLResponse(_page("대시보드", body, user=u, extra_js=DASHBOARD_JS))


# ═══════════════════════════════════════════════════════════
# 3. 관리자 대시보드
# ═══════════════════════════════════════════════════════════
@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    u = _current_user(request)
    if not u or u.get("role") != "admin":
        return RedirectResponse("/")

    users = get_all_users()
    jobs  = get_all_jobs()

    user_rows = ""
    for usr in users:
        role_cls  = "admin-role" if usr["role"] == "admin" else "user-role"
        role_badge = '<span class="badge ' + role_cls + '">' + usr["role"] + "</span>"
        stat_badge = '<span class="badge ' + usr["status"] + '">' + usr["status"] + "</span>"
        action = ""
        if usr["id"] != u["id"]:
            uid = str(usr["id"])
            if usr["status"] == "pending":
                action = (
                    "<form method='post' action='/admin/users/" + uid + "/approve' style='display:inline'>"
                    "<button class='btn-sm btn-success'>✅ 승인</button></form>"
                    "<form method='post' action='/admin/users/" + uid + "/reject' style='display:inline;margin-left:4px'>"
                    "<button class='btn-sm btn-danger'>❌ 반려</button></form>"
                )
            elif usr["status"] == "approved":
                action = (
                    "<form method='post' action='/admin/users/" + uid + "/reject' style='display:inline'>"
                    "<button class='btn-sm btn-danger'>🚫 비활성화</button></form>"
                )
            elif usr["status"] == "rejected":
                action = (
                    "<form method='post' action='/admin/users/" + uid + "/approve' style='display:inline'>"
                    "<button class='btn-sm btn-success'>♻️ 재승인</button></form>"
                )
            toggle = "user" if usr["role"] == "admin" else "admin"
            rlabel = "👤 일반으로" if usr["role"] == "admin" else "👑 관리자로"
            action += (
                "<form method='post' action='/admin/users/" + uid + "/role?role=" + toggle +
                "' style='display:inline;margin-left:4px'>"
                "<button class='btn-sm btn-warn'>" + rlabel + "</button></form>"
            )
        user_rows += (
            "<tr>"
            "<td>" + str(usr["id"]) + "</td>"
            "<td><strong>" + usr["username"] + "</strong></td>"
            "<td style='color:#888'>" + usr["email"] + "</td>"
            "<td>" + role_badge + "</td>"
            "<td>" + stat_badge + "</td>"
            "<td style='color:#555'>" + str(usr.get("created_at", ""))[:16] + "</td>"
            "<td>" + action + "</td>"
            "</tr>"
        )

    job_rows = ""
    for j in jobs:
        rpt = next((r for r in j.get("reports", []) if r["total_count"] > 0), None)
        counts = (str(rpt["total_count"]) + "건 / 확정 " + str(rpt["confirmed_count"]) + "건") if rpt else "-"
        job_rows += (
            "<tr>"
            "<td style='font-family:monospace;font-size:11px'>" + j["job_id"] + "</td>"
            "<td>" + str(j.get("username", "?")) + "</td>"
            "<td style='word-break:break-all'>" + j["target"] + "</td>"
            "<td><span class='badge " + j["status"] + "'>" + j["status"] + "</span></td>"
            "<td>" + counts + "</td>"
            "<td style='color:#555'>" + str(j.get("created_at", ""))[:16] + "</td>"
            "</tr>"
        )

    pending_cnt = sum(1 for x in users if x["status"] == "pending")
    pending_notice = (
        '<div class="err-box" style="margin-bottom:16px">⏳ 승인 대기 계정 ' +
        str(pending_cnt) + "개가 있습니다.</div>"
    ) if pending_cnt else ""

    no_user = "<tr><td colspan='7' style='color:#555;text-align:center'>없음</td></tr>"
    no_job  = "<tr><td colspan='6' style='color:#555;text-align:center'>없음</td></tr>"

    body = (
        pending_notice +
        "<div class='card'>"
        "<h2>👥 유저 관리 <span style='font-size:12px;color:#555;font-weight:normal'>(" + str(len(users)) + "명)</span></h2>"
        "<div style='overflow-x:auto'><table>"
        "<tr><th>ID</th><th>아이디</th><th>이메일</th><th>권한</th><th>상태</th><th>가입일</th><th>액션</th></tr>"
        + (user_rows or no_user) +
        "</table></div></div>"
        "<div class='card'>"
        "<h2>📊 전체 스캔 기록 <span style='font-size:12px;color:#555;font-weight:normal'>(" + str(len(jobs)) + "건)</span></h2>"
        "<div style='overflow-x:auto'><table>"
        "<tr><th>Job ID</th><th>유저</th><th>타겟</th><th>상태</th><th>탐지</th><th>시작일</th></tr>"
        + (job_rows or no_job) +
        "</table></div></div>"
    )
    return HTMLResponse(_page("관리자 대시보드", body, user=u))


# ═══════════════════════════════════════════════════════════
# 관리자 액션
# ═══════════════════════════════════════════════════════════
@app.post("/admin/users/{user_id}/approve")
async def approve_user(user_id: int, request: Request):
    u = _current_user(request)
    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)
    update_user_status(user_id, "approved", approved_by=u["id"])
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/users/{user_id}/reject")
async def reject_user(user_id: int, request: Request):
    u = _current_user(request)
    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)
    update_user_status(user_id, "rejected")
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/users/{user_id}/role")
async def change_role(user_id: int, request: Request, role: str = Query(...)):
    u = _current_user(request)
    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)
    if role in ("admin", "user"):
        update_user_role(user_id, role)
    return RedirectResponse("/admin", status_code=302)


# ═══════════════════════════════════════════════════════════
# 스캔 API
# ═══════════════════════════════════════════════════════════
class ScanRequest(BaseModel):
    target:   str
    strength: str = "medium"

@app.post("/api/scan")
async def api_start_scan(req: ScanRequest, bg: BackgroundTasks, request: Request):
    u = _current_user(request)
    if not u or u.get("status") != "approved":
        raise HTTPException(status_code=401, detail="로그인 필요")
    job_id = str(uuid.uuid4())[:8]
    job = create_job(job_id, u["id"], req.target, req.strength)
    bg.add_task(_run_scan, job_id, req.target, req.strength)
    return job

@app.get("/api/scan/{job_id}")
async def api_get_scan(job_id: str, request: Request):
    u = _current_user(request)
    if not u:
        raise HTTPException(status_code=401)
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404)
    return job

@app.get("/report/{filename}")
async def download_report(filename: str, request: Request,
                          x_api_key: str = Header(None),
                          key: str = Query(None)):
    u = _current_user(request)
    if not u and (x_api_key or key) != API_KEY:
        raise HTTPException(status_code=401)
    path = "results/reports/" + filename
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    if filename.endswith(".html"):
        media = "text/html"
    elif filename.endswith(".json"):
        media = "application/json"
    else:
        media = "text/csv"
    return FileResponse(path, media_type=media, filename=filename)

@app.get("/health")
async def health():
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════
# 스캔 실행 (백그라운드)
# ═══════════════════════════════════════════════════════════
async def _run_scan(job_id: str, target: str, strength: str):
    update_job(job_id, status="queued", phase="대기 중 (이전 스캔 완료 후 시작)")
    async with scan_lock:
        update_job(job_id, status="running", progress=0, phase="스캔 시작")
        def cb(phase, pct):
            update_job(job_id, phase=phase, progress=pct)
        try:
            try:
                from sls_scanner.core.pipeline import run_pipeline_with_cb
                run_pipeline_with_cb(target=target, strength=strength, cb=cb)
            except ImportError:
                from sls_scanner.core.pipeline import run_pipeline
                cb("스캔 진행 중...", 50)
                run_pipeline(target=target, strength=strength)
        except Exception as e:
            update_job(job_id, status="error",
                       phase="오류: " + str(e)[:80],
                       finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return

        reports_dir = "results/reports"
        safe = target.replace("http://","").replace("https://","") \
                     .replace("/","_").replace(":","_").lstrip("_")
        try:
            files = sorted(
                [f for f in os.listdir(reports_dir) if f.startswith(safe)],
                key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)),
                reverse=True
            )[:7]
            for f in files:
                save_report(job_id, _report_type(f), f)
        except Exception:
            pass

        update_job(job_id, status="done", progress=100, phase="완료",
                   finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
