from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Query, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import uuid
import os
import json
import asyncio
from datetime import datetime

# ── SSE / 취소 전역 상태 ─────────────────────────────────────────
_job_sse_queues: dict[str, asyncio.Queue] = {}   # job_id → Queue
_main_loop: asyncio.AbstractEventLoop | None = None

from database import (
    init_db,
    create_user,
    get_user_by_username,
    get_all_users,
    update_user_status,
    update_user_role,
    create_session,
    get_session_user,
    delete_session,
    create_job,
    get_job,
    update_job,
    get_user_jobs,
    get_all_jobs,
    save_report,
    verify_pw,
    delete_user,
    create_verify_token,
    get_verify_token,
    update_verify_status,
)

app = FastAPI(title="Shift-Left-Sync")

# static/style.css, static/app.js 연결
app.mount("/static", StaticFiles(directory="static"), name="static")

# templates/index.html, features.html, reports.html, guide.html 연결
templates = Jinja2Templates(directory="templates")

scan_lock = asyncio.Lock()
API_KEY = os.getenv("API_KEY", "sls-secret-2026")


@app.on_event("startup")
async def startup():
    global _main_loop
    _main_loop = asyncio.get_event_loop()
    init_db()
    # 이전 서버 다운으로 running/queued 상태 남은 잡 정리
    from database import get_conn
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status='error', phase='서버 재시작으로 스캔 중단됨', "
            "finished_at=datetime('now','localtime') "
            "WHERE status IN ('running','queued')"
        )

@app.on_event("shutdown")
async def shutdown():
    # 서버 종료 시 진행 중인 스캔 error 처리
    from database import get_conn
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status='error', phase='서버 종료로 스캔 중단됨', "
            "finished_at=datetime('now','localtime') "
            "WHERE status IN ('running','queued')"
        )


# ─────────────────────────────────────────────
# 기존 대시보드 / 관리자 페이지용 CSS
# 로그인 랜딩 페이지는 static/style.css 사용
# ─────────────────────────────────────────────
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
"""


DASHBOARD_JS = """
<script>
var sseConnections = {};   // job_id → EventSource
var pollTimers     = {};   // 폴백용

// ── SSE 연결 ──────────────────────────────────────────────────
function connectSSE(job_id) {
  if (sseConnections[job_id]) return;

  var es = new EventSource('/api/scan/' + job_id + '/events');
  sseConnections[job_id] = es;

  es.onmessage = function(e) {
    var ev  = JSON.parse(e.data);
    var el  = document.getElementById('job-' + job_id);
    if (!el) return;

    if (ev.type === 'ping') return;

    if (ev.type === 'progress') {
      updateJobProgress(el, job_id, ev.phase, ev.progress);
    } else if (ev.type === 'done') {
      es.close(); delete sseConnections[job_id];
      fetchAndUpdate(job_id);   // 최종 리포트 링크 포함해서 갱신
    } else if (ev.type === 'cancelled' || ev.type === 'error') {
      es.close(); delete sseConnections[job_id];
      fetchAndUpdate(job_id);
    }
  };

  es.onerror = function() {
    es.close(); delete sseConnections[job_id];
    // SSE 실패 시 폴링으로 폴백
    pollJob(job_id);
  };
}

function updateJobProgress(el, job_id, phase, pct) {
  var pb = el.querySelector('.progress-bar');
  var pt = el.querySelector('.phase-text');
  var bd = el.querySelector('.badge');
  if (pb) pb.style.width = pct + '%';
  if (pt) pt.textContent = phase;
  if (bd) { bd.textContent = 'running ' + pct + '%'; bd.className = 'badge running'; }
}

async function fetchAndUpdate(job_id) {
  try {
    var res = await fetch('/api/scan/' + job_id);
    if (!res.ok) return;
    var j   = await res.json();
    var el  = document.getElementById('job-' + job_id);
    if (el) updateJobEl(el, j);
  } catch(e) {}
}

// ── 취소 버튼 ─────────────────────────────────────────────────
async function cancelScan(job_id) {
  if (!confirm('스캔을 취소하시겠습니까?\\n현재 단계가 완료된 후 중단됩니다.')) return;
  var btn = document.getElementById('cancel-btn-' + job_id);
  if (btn) { btn.disabled = true; btn.textContent = '취소 요청 중...'; }
  try {
    var res  = await fetch('/api/scan/' + job_id + '/cancel', { method: 'POST' });
    var data = await res.json();
    if (btn) btn.textContent = data.cancelled ? '⏹ 취소 요청됨' : data.message;
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = '⏹ 취소'; }
  }
}

// ── 소유권 인증 UI ─────────────────────────────────────────────
function showVerify(j) {
  var el = document.getElementById('job-' + j.job_id);
  if (!el) return;
  var token   = j.token || '';
  var jobId   = j.job_id || '';
  var target  = j.target || '';
  var wkUrl   = target.replace(/[/]+$/, '') + '/.well-known/sls-verify.txt';
  var metaTag = '<meta name="sls-verify" content="' + token + '">';

  el.innerHTML = '';

  var hdr = document.createElement('div');
  hdr.className = 'job-header';
  hdr.innerHTML = '<span class="job-id">Job: ' + jobId + '</span>'
    + '<span class="status-badge status-pending">소유권 인증 필요</span>';
  el.appendChild(hdr);

  var tgt = document.createElement('div');
  tgt.style.cssText = 'font-size:12px;color:#888;margin:6px 0 10px';
  tgt.textContent = '🎯 ' + target;
  el.appendChild(tgt);

  var box = document.createElement('div');
  box.style.cssText = 'background:var(--bg-2,#1a2a1a);border:1px solid #2d4a2d;border-radius:8px;padding:14px;font-size:12px;margin-bottom:10px';

  var title = document.createElement('div');
  title.style.cssText = 'color:#86efac;font-weight:bold;margin-bottom:12px';
  title.textContent = '🔐 소유권 인증 방법 (둘 중 하나 선택)';
  box.appendChild(title);

  var m1 = document.createElement('div');
  m1.style.cssText = 'margin-bottom:14px';
  m1.innerHTML = '<div style="color:#aaa;margin-bottom:4px;font-weight:500">방법 1 — 파일 업로드 (범용)</div>'
    + '<div style="font-size:11px;color:#666;margin-bottom:3px">업로드 경로: ' + wkUrl + '</div>'
    + '<div style="background:#0f1117;padding:7px 10px;border-radius:4px;font-family:monospace;color:#64b5f6;word-break:break-all">' + token + '</div>'
    + '<div style="color:#555;font-size:11px;margin-top:3px">위 파일을 만들고 토큰을 내용으로 저장 후 확인 버튼을 누르세요.</div>';
  box.appendChild(m1);

  var m2 = document.createElement('div');
  m2.innerHTML = '<div style="color:#aaa;margin-bottom:4px;font-weight:500">방법 2 — 메타태그 삽입 (웹앱 전용)</div>'
    + '<div style="background:#0f1117;padding:7px 10px;border-radius:4px;font-family:monospace;color:#64b5f6;word-break:break-all">' + metaTag.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>'
    + '<div style="color:#555;font-size:11px;margin-top:3px">홈페이지 &lt;head&gt; 안에 추가 후 확인 버튼을 누르세요.</div>';
  box.appendChild(m2);
  el.appendChild(box);

  var row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:8px;align-items:center';

  var btn = document.createElement('button');
  btn.className = 'btn btn-primary';
  btn.id = 'vbtn-' + jobId;
  btn.textContent = '✅ 소유권 확인';
  btn.onclick = function() { doVerify(jobId); };

  var msg = document.createElement('span');
  msg.id = 'vmsg-' + jobId;
  msg.style.cssText = 'font-size:12px;color:#888';

  row.appendChild(btn);
  row.appendChild(msg);
  el.appendChild(row);
}

async function doVerify(job_id) {
  var btn = document.getElementById('vbtn-' + job_id);
  var msg = document.getElementById('vmsg-' + job_id);
  if (btn) btn.disabled = true;
  if (msg) msg.textContent = '확인 중...';
  try {
    var res  = await fetch('/api/scan/' + job_id + '/verify', { method: 'POST' });
    var data = await res.json();
    if (data.verified) {
      if (msg) { msg.textContent = '✅ ' + data.message; msg.style.color = '#86efac'; }
      connectSSE(job_id);
    } else {
      if (msg) { msg.textContent = '❌ ' + data.message; msg.style.color = '#fca5a5'; }
      if (btn) btn.disabled = false;
    }
  } catch(e) {
    if (msg) msg.textContent = '오류: ' + e.message;
    if (btn) btn.disabled = false;
  }
}

// ── 리포트 링크 ───────────────────────────────────────────────
function labelOf(f) {
  if (f.indexOf('simple') >= 0)         return '📄 간편';
  if (f.indexOf('report.html') >= 0)    return '🔧 전문가';
  if (f.indexOf('full.json') >= 0)      return '📦 JSON';
  if (f.indexOf('confirmed') >= 0)      return '✅ 확정';
  if (f.indexOf('unverified') >= 0)     return '⚠️ 수동검토';
  if (f.indexOf('false_positive') >= 0) return '❌ 오탐';
  if (f.indexOf('full.csv') >= 0)       return '📊 전체CSV';
  return '📄';
}

function buildReportLinks(reports, job_id) {
  return (reports || []).map(function(r) {
    var isHtml = r.filename.indexOf('.html') >= 0;
    var href   = isHtml ? '/view/' + r.filename : '/report/' + r.filename;
    return '<a class="report-link" href="' + href + '">' + labelOf(r.filename) + '</a>';
  }).join('');
}

// ── 잡 카드 렌더링 ────────────────────────────────────────────
function updateJobEl(el, j) {
  var pct      = j.progress || 0;
  var isActive = j.status === 'running' || j.status === 'queued';
  var isCancellable = isActive;

  var progress = isActive
    ? '<div class="progress-wrap"><div class="progress-bar phase-bar" id="pb-' + j.job_id + '" style="width:' + pct + '%"></div></div>'
      + '<div class="phase-text" style="font-size:11px;color:#64b5f6">' + (j.phase || '') + '</div>'
    : (j.phase ? '<div style="font-size:11px;color:#888;margin-top:4px">' + j.phase + '</div>' : '');

  var cancelBtn = isCancellable
    ? '<button id="cancel-btn-' + j.job_id + '" class="btn btn-danger" style="font-size:11px;padding:3px 10px;margin-left:8px" '
      + 'onclick="cancelScan(\'' + j.job_id + '\')">⏹ 취소</button>'
    : '';

  var reports = buildReportLinks(j.reports, j.job_id);

  el.innerHTML =
    '<div class="job-header" style="display:flex;align-items:center;flex-wrap:wrap;gap:6px">' +
      '<span class="job-id">Job: ' + j.job_id + '</span>' +
      '<span class="badge ' + j.status + '">' + j.status + (isActive ? ' ' + pct + '%' : '') + '</span>' +
      cancelBtn +
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

// ── 스캔 시작 ─────────────────────────────────────────────────
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
    if (data.status === 'pending_verify') {
      showVerify(data);
    } else {
      connectSSE(data.job_id);
    }
  } catch(e) {
    document.getElementById('scan-msg').textContent = '❌ 실패: ' + e.message;
  }
}

// ── 폴링 폴백 ─────────────────────────────────────────────────
async function pollJob(job_id) {
  if (pollTimers[job_id]) return;
  pollTimers[job_id] = setInterval(async function() {
    var res = await fetch('/api/scan/' + job_id);
    if (!res.ok) return;
    var j  = await res.json();
    var el = document.getElementById('job-' + job_id);
    if (el) updateJobEl(el, j);
    if (j.status === 'done' || j.status === 'error' || j.status === 'cancelled') {
      clearInterval(pollTimers[job_id]);
      delete pollTimers[job_id];
    }
  }, 4000);
}

// ── 페이지 로드 시 진행 중인 잡 SSE 재연결 ──────────────────
document.querySelectorAll('.job-card').forEach(function(el) {
  var id    = el.id.replace('job-', '');
  var badge = el.querySelector('.badge');
  if (badge && (badge.classList.contains('running') || badge.classList.contains('queued'))) {
    connectSSE(id);
  }
});
</script>
"""



# ─────────────────────────────────────────────
# 공통 헬퍼
# ─────────────────────────────────────────────
def _report_label(filename):
    if "simple" in filename:
        return "📄 간편"
    if "report.html" in filename:
        return "🔧 전문가"
    if "full.json" in filename:
        return "📦 JSON"
    if "confirmed" in filename:
        return "✅ 확정"
    if "unverified" in filename:
        return "⚠️ 수동검토"
    if "false_positive" in filename:
        return "❌ 오탐"
    if "full.csv" in filename:
        return "📊 전체CSV"
    return "📄"


def _report_type(filename):
    if "simple" in filename:
        return "simple_html"
    if "report.html" in filename:
        return "expert_html"
    if "confirmed" in filename:
        return "csv_confirmed"
    if "unverified" in filename:
        return "csv_unverified"
    if "false_positive" in filename:
        return "csv_fp"
    if "full.csv" in filename:
        return "csv_full"
    if "full.json" in filename:
        return "json_full"
    return "other"


def _current_user(request):
    token = request.cookies.get("sls_session")
    return get_session_user(token) if token else None


STATUS_LABELS = {
    "pending": "승인 대기",
    "approved": "승인됨",
    "rejected": "거절됨",
    "queued": "대기 중",
    "running": "진행 중",
    "done": "완료",
    "error": "실패",
}

STATUS_CLASSES = {
    "pending": "badge-pending",
    "approved": "badge-active",
    "rejected": "badge-suspended",
    "queued": "badge-pending",
    "running": "badge-in-progress",
    "done": "badge-completed",
    "error": "badge-failed",
}

REPORT_TYPE_LABELS = {
    "simple_html": "간편 HTML",
    "expert_html": "전문가 HTML",
    "html": "HTML",
    "json": "JSON",
    "json_full": "JSON",
    "csv": "CSV",
    "csv_full": "전체 CSV",
    "csv_confirmed": "확정 CSV",
    "csv_unverified": "수동검토 CSV",
    "csv_fp": "오탐 CSV",
    "summary": "요약",
    "other": "리포트",
}


def _status_label(status):
    return STATUS_LABELS.get(status, status)


def _status_class(status):
    return STATUS_CLASSES.get(status, "badge-default")


def _fmt_datetime(value):
    if not value:
        return "-"
    return str(value).replace("T", " ")[:16]


def _report_type_label(report_type):
    if not report_type:
        return "리포트"
    return REPORT_TYPE_LABELS.get(report_type, str(report_type).upper())


def _require_admin(request):
    user = _current_user(request)
    if not user or user.get("role") != "admin":
        return None
    return user


def _admin_stats(users, jobs):
    today = datetime.now().strftime("%Y-%m-%d")
    pending_count = sum(1 for user in users if user.get("status") == "pending")
    running_count = sum(1 for job in jobs if job.get("status") in ("queued", "running"))
    today_scan_count = sum(
        1 for job in jobs if str(job.get("created_at", "")).startswith(today)
    )
    report_count = sum(len(job.get("reports", [])) for job in jobs)
    return [
        {"title": "전체 사용자", "value": f"{len(users):,}"},
        {"title": "오늘 스캔", "value": f"{today_scan_count:,}"},
        {"title": "승인 대기", "value": f"{pending_count:,}"},
        {"title": "진행 중 스캔", "value": f"{running_count:,}"},
        {"title": "리포트 파일", "value": f"{report_count:,}"},
    ]


def _history_logs(jobs):
    return [
        {
            "date": _fmt_datetime(job.get("created_at")),
            "user_id": job.get("username", "-"),
            "action": f"스캔 요청: {job.get('target', '-')}",
        }
        for job in jobs
    ]


def _admin_template(request, template_name, active_menu, user, **context):
    base_context = {
        "request": request,
        "active_menu": active_menu,
        "current_user": user,
        "status_class": _status_class,
        "status_label": _status_label,
        "fmt_datetime": _fmt_datetime,
        "report_type_label": _report_type_label,
    }
    base_context.update(context)
    return templates.TemplateResponse(template_name, base_context)


def _page(title, body, user=None, extra_js=""):
    admin_btn = ""

    if user and user.get("role") == "admin":
        admin_btn = '<a href="/admin" class="btn btn-warn" style="font-size:12px;padding:6px 14px">⚙️ 관리자</a>'

    logout_btn = '<a href="/auth/logout" class="btn-sm">로그아웃</a>' if user else ""
    icon = "👑" if user and user.get("role") == "admin" else "👤"
    user_badge = (
        '<span class="user-badge">' + icon + " " + user["username"] + "</span>"
        if user else ""
    )

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
# 1. 랜딩 / 로그인 / 회원가입 페이지
# ═══════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: str = ""):
    u = _current_user(request)

    if u and u.get("status") == "approved":
        return RedirectResponse("/dashboard")

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "msg": msg,
            "user": u,
        },
    )


@app.get("/features", response_class=HTMLResponse)
async def features_page(request: Request):
    return templates.TemplateResponse(
        "features.html",
        {"request": request},
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    return templates.TemplateResponse(
        "reports.html",
        {"request": request},
    )


@app.get("/guide", response_class=HTMLResponse)
async def guide_page(request: Request):
    return templates.TemplateResponse(
        "guide.html",
        {"request": request},
    )


# ═══════════════════════════════════════════════════════════
# 2. 인증 엔드포인트
# ═══════════════════════════════════════════════════════════
@app.post("/auth/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    u = get_user_by_username(username)

    if not u or not verify_pw(password, u["password_hash"]):
        return RedirectResponse("/?msg=아이디 또는 비밀번호가 틀렸습니다", status_code=302)

    if u["status"] == "pending":
        return RedirectResponse("/?msg=관리자 승인 대기 중인 계정입니다", status_code=302)

    if u["status"] == "rejected":
        return RedirectResponse("/?msg=승인이 거부된 계정입니다", status_code=302)

    token = create_session(u["id"])

    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("sls_session", token, httponly=True, max_age=86400)

    return resp


@app.post("/auth/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    import re as _re

    # 아이디 검증
    if len(username) < 3 or len(username) > 20:
        return RedirectResponse("/?tab=reg&msg=아이디는 3~20자 사이여야 합니다", status_code=302)
    if not _re.match(r"^[a-zA-Z0-9_]+$", username):
        return RedirectResponse("/?tab=reg&msg=아이디는 영문·숫자·밑줄(_)만 사용할 수 있습니다", status_code=302)

    # 이메일 검증
    if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return RedirectResponse("/?tab=reg&msg=올바른 이메일 형식이 아닙니다", status_code=302)

    # 비밀번호 검증
    if len(password) < 8:
        return RedirectResponse("/?tab=reg&msg=비밀번호는 8자 이상이어야 합니다", status_code=302)
    if not _re.search(r"[A-Za-z]", password) or not _re.search(r"[0-9]", password):
        return RedirectResponse("/?tab=reg&msg=비밀번호는 영문과 숫자를 모두 포함해야 합니다", status_code=302)

    u = create_user(username, email, password)
    if not u:
        return RedirectResponse("/?tab=reg&msg=이미 사용 중인 아이디 또는 이메일입니다", status_code=302)

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
# 3. 유저 대시보드
# ═══════════════════════════════════════════════════════════
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    u = _current_user(request)

    if not u or u.get("status") != "approved":
        return RedirectResponse("/")

    jobs = get_user_jobs(u["id"])

    stats = {
        "total": len(jobs),
        "pending_verify": sum(1 for j in jobs if j.get("status") == "pending_verify"),
        "queued": sum(1 for j in jobs if j.get("status") == "queued"),
        "running": sum(1 for j in jobs if j.get("status") == "running"),
        "done": sum(1 for j in jobs if j.get("status") == "done"),
        "error": sum(1 for j in jobs if j.get("status") == "error"),
    }

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": u,
            "jobs": jobs,
            "stats": stats,
            "dashboard_js": DASHBOARD_JS,
            "report_label": _report_label,
        },
    )

# ═══════════════════════════════════════════════════════════
# 4. 관리자 대시보드
# ═══════════════════════════════════════════════════════════
@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard_v2(request: Request):
    u = _require_admin(request)

    if not u:
        return RedirectResponse("/")

    users = get_all_users()
    jobs = get_all_jobs()
    pending_users = [user for user in users if user.get("status") == "pending"]

    return _admin_template(
        request,
        "admin/home.html",
        "home",
        u,
        stats=_admin_stats(users, jobs),
        recent_scans=jobs[:10],
        pending_users=pending_users,
    )


@app.get("/admin/pending", response_class=HTMLResponse)
async def admin_pending(request: Request):
    u = _require_admin(request)

    if not u:
        return RedirectResponse("/")

    users = get_all_users()
    pending_users = [user for user in users if user.get("status") == "pending"]

    return _admin_template(
        request,
        "admin/pending.html",
        "pending",
        u,
        pending_users=pending_users,
    )


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request):
    u = _require_admin(request)

    if not u:
        return RedirectResponse("/")

    return _admin_template(
        request,
        "admin/users.html",
        "users",
        u,
        users=get_all_users(),
    )


@app.get("/admin/history", response_class=HTMLResponse)
async def admin_history(request: Request):
    u = _require_admin(request)
    if not u:
        return RedirectResponse("/")

    jobs = get_all_jobs()

    # jobs를 JSON 직렬화 (Jinja2 템플릿에서 JS로 직접 주입)
    import json as _json
    jobs_json = _json.dumps(jobs, ensure_ascii=False, default=str)

    return _admin_template(
        request,
        "admin/history.html",
        "history",
        u,
        jobs_json=jobs_json,
    )


@app.post("/admin/users/{user_id}/approve")
async def approve_user(user_id: int, request: Request):
    u = _current_user(request)

    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)

    update_user_status(user_id, "approved", approved_by=u["id"])
    ref = request.headers.get("referer", "/admin/pending")
    return RedirectResponse(ref if "/admin" in ref else "/admin/pending", status_code=302)


@app.post("/admin/users/{user_id}/reject")
async def reject_user(user_id: int, request: Request):
    u = _current_user(request)
    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)
    # 거절 = 즉시 삭제
    delete_user(user_id)
    ref = request.headers.get("referer", "/admin/pending")
    return RedirectResponse(ref if "/admin" in ref else "/admin/pending", status_code=302)

@app.post("/admin/users/{user_id}/delete")
async def delete_user_endpoint(user_id: int, request: Request):
    u = _current_user(request)
    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)
    if u["id"] == user_id:
        return RedirectResponse("/admin/users", status_code=302)
    delete_user(user_id)
    ref = request.headers.get("referer", "/admin/users")
    return RedirectResponse(ref if "/admin" in ref else "/admin/users", status_code=302)


@app.post("/admin/users/{user_id}/role")
async def change_role(user_id: int, request: Request, role: str = Query(...)):
    u = _current_user(request)

    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)

    if role in ("admin", "user"):
        update_user_role(user_id, role)
    return RedirectResponse("/admin/users", status_code=302)


# ═══════════════════════════════════════════════════════════
# 6. 스캔 API
# ═══════════════════════════════════════════════════════════
class ScanRequest(BaseModel):
    target: str
    strength: str = "medium"


@app.post("/api/scan")
async def api_start_scan(req: ScanRequest, request: Request):
    u = _current_user(request)
    if not u or u.get("status") != "approved":
        raise HTTPException(status_code=401, detail="로그인 필요")

    import secrets as _sec
    job_id = str(uuid.uuid4())[:8]
    token  = "SLS-VERIFY-" + _sec.token_hex(8).upper()

    job = create_job(job_id, u["id"], req.target, req.strength)
    create_verify_token(job_id, token, req.target)
    update_job(job_id, status="pending_verify", phase="소유권 인증 대기 중")

    result = dict(job)
    result["token"]  = token
    result["status"] = "pending_verify"
    result["phase"]  = "소유권 인증 대기 중"
    return result


@app.post("/api/scan/{job_id}/verify")
async def api_verify_ownership(job_id: str, bg: BackgroundTasks, request: Request):
    u = _current_user(request)
    if not u:
        raise HTTPException(status_code=401)

    vt = get_verify_token(job_id)
    if not vt:
        raise HTTPException(status_code=404, detail="인증 정보 없음")
    if vt["status"] == "verified":
        return {"verified": True, "message": "이미 인증된 잡입니다"}

    target = vt["target"]
    token  = vt["token"]

    import httpx
    file_url = target.rstrip("/") + "/.well-known/sls-verify.txt"
    meta_url = target.rstrip("/") + "/"

    verified = False
    method   = None

    try:
        async with httpx.AsyncClient(timeout=8, verify=False,
                                     follow_redirects=True) as client:
            try:
                r = await client.get(file_url)
                if r.status_code == 200 and token in r.text:
                    verified = True
                    method   = "file"
            except Exception:
                pass

            if not verified:
                try:
                    r = await client.get(meta_url)
                    if r.status_code == 200 and token in r.text:
                        verified = True
                        method   = "meta"
                except Exception:
                    pass
    except Exception as e:
        return {"verified": False, "message": "연결 오류: " + str(e)[:60]}

    if verified:
        update_verify_status(job_id, "verified", method)
        update_job(job_id, status="queued", phase="소유권 인증 완료 — 스캔 대기 중")
        job = get_job(job_id)
        bg.add_task(_run_scan, job_id, target, job.get("strength", "medium"))
        return {"verified": True, "method": method,
                "message": "소유권 인증 완료! 스캔을 시작합니다."}
    else:
        update_verify_status(job_id, "failed")
        return {"verified": False,
                "message": "토큰을 찾을 수 없습니다. 파일 또는 메타태그를 확인하세요."}


@app.get("/api/scan/{job_id}")
async def api_get_scan(job_id: str, request: Request):
    u = _current_user(request)

    if not u:
        raise HTTPException(status_code=401)

    job = get_job(job_id)

    if not job:
        raise HTTPException(status_code=404)

    return job


@app.get("/api/scan/{job_id}/events")
async def api_scan_events(job_id: str, request: Request):
    """SSE 스트림 - 스캔 진행 상황 실시간 전송"""
    u = _current_user(request)
    if not u:
        raise HTTPException(status_code=401)

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404)

    # 이미 완료된 잡은 즉시 done 이벤트 반환
    if job.get("status") in ("done", "error", "cancelled"):
        async def _immediate():
            data = json.dumps({
                "type": job.get("status"),
                "phase": job.get("phase", ""),
                "progress": job.get("progress", 0),
            })
            yield f"data: {data}\n\n"
        return StreamingResponse(_immediate(), media_type="text/event-stream")

    # 진행 중 잡 — 큐 생성 후 스트리밍
    queue: asyncio.Queue = asyncio.Queue()
    _job_sse_queues[job_id] = queue

    async def _generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("type") in ("done", "error", "cancelled"):
                        break
                except asyncio.TimeoutError:
                    # keepalive ping
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        finally:
            _job_sse_queues.pop(job_id, None)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # nginx 버퍼링 비활성화
        },
    )


@app.post("/api/scan/{job_id}/cancel")
async def api_cancel_scan(job_id: str, request: Request):
    """실행 중인 스캔 취소 요청"""
    u = _current_user(request)
    if not u:
        raise HTTPException(status_code=401)

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404)

    status = job.get("status", "")
    if status in ("done", "error", "cancelled"):
        return {"cancelled": False, "message": f"이미 종료된 잡입니다 (상태: {status})"}

    # 파이프라인에 취소 신호 전달
    from sls_scanner.core.pipeline import request_cancel as _pipeline_cancel
    _pipeline_cancel(job_id)
    update_job(job_id, phase="취소 요청됨 — 현재 단계 완료 후 중단")

    return {"cancelled": True, "message": "취소 요청을 전달했습니다. 현재 단계 완료 후 중단됩니다."}


@app.get("/view/{filename}", response_class=HTMLResponse)
async def view_report(filename: str, request: Request):
    u = _current_user(request)
    if not u:
        return RedirectResponse("/")
    fpath = "results/reports/" + filename
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404)

    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
        report_html = f.read()

    is_simple   = "simple" in filename
    report_type = "📄 간편 리포트" if is_simple else "🔧 전문가 리포트"
    pair_filename = (
        filename.replace("_report_simple.html", "_report.html")
        if is_simple else
        filename.replace("_report.html", "_report_simple.html")
    )
    pair_label  = "🔧 전문가 리포트" if is_simple else "📄 간편 리포트"
    pair_exists = os.path.exists("results/reports/" + pair_filename)
    icon        = "👑" if u.get("role") == "admin" else "👤"

    admin_btn = (
        '<a href="/admin" class="sls-ng" style="background:#78350f;color:#fcd34d">⚙️ 관리자</a>'
        if u.get("role") == "admin" else ""
    )
    pair_btn = (
        '<a href="/view/' + pair_filename + '" class="sls-ng">' + pair_label + '</a>'
        if pair_exists else ""
    )

    nav_css = """<style id="sls-nav-css">
#sls-nav{position:fixed;top:0;left:0;right:0;z-index:99999;
  background:linear-gradient(135deg,#1a1f2e,#2d3561);
  padding:8px 20px;display:flex;align-items:center;
  justify-content:space-between;gap:12px;
  border-bottom:2px solid #2d3561;
  box-shadow:0 2px 12px rgba(0,0,0,.5);
  font-family:'Segoe UI',Arial,sans-serif;min-height:44px}
#sls-nav .sls-nl{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
#sls-nav .sls-nr{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
#sls-nav a{font-size:12px;text-decoration:none;padding:5px 14px;
  border-radius:7px;white-space:nowrap;display:inline-block}
#sls-nav .sls-nb{background:#1565c0;color:white}
#sls-nav .sls-nb:hover{background:#1976d2}
#sls-nav .sls-nd{background:#14532d;color:#86efac}
#sls-nav .sls-nd:hover{background:#166534}
#sls-nav .sls-ng{background:#2d3561;color:#ccc}
#sls-nav .sls-ng:hover{background:#3d4571;color:white}
#sls-nav .sls-nt{font-size:13px;color:#64b5f6;font-weight:bold}
#sls-nav .sls-nu{font-size:11px;color:#aaa;padding:4px 10px;
  background:#0f1117;border:1px solid #2d3561;border-radius:6px}
body{margin-top:48px!important}
</style>"""

    nav_html = (
        '<div id="sls-nav">'
        '<div class="sls-nl">'
        '<a href="/dashboard" class="sls-nb">← 대시보드</a>'
        '<span class="sls-nt">' + report_type + '</span>'
        '</div>'
        '<div class="sls-nr">'
        + pair_btn
        + '<a href="/report/' + filename + '" download="' + filename + '" class="sls-nd">⬇ 다운로드</a>'
        + '<span class="sls-nu">' + icon + " " + u["username"] + '</span>'
        + admin_btn
        + '<a href="/auth/logout" class="sls-ng">로그아웃</a>'
        + '</div></div>'
    )

    import re as _re
    body_match = _re.search(r'<body[^>]*>', report_html, _re.IGNORECASE)
    if body_match:
        pos = body_match.end()
        report_html = report_html[:pos] + nav_css + nav_html + report_html[pos:]
    else:
        report_html = nav_css + nav_html + report_html

    return HTMLResponse(report_html)


@app.get("/report/{filename}")
async def download_report(
    filename: str,
    request: Request,
    x_api_key: str = Header(None),
    key: str = Query(None),
):
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
# 7. 스캔 실행 백그라운드 작업
# ═══════════════════════════════════════════════════════════
async def _run_scan(job_id: str, target: str, strength: str):
    update_job(job_id, status="queued", phase="대기 중 (이전 스캔 완료 후 시작)")

    def _push(event: dict):
        """스레드에서 안전하게 SSE 큐에 이벤트 전송"""
        if job_id in _job_sse_queues and _main_loop:
            _main_loop.call_soon_threadsafe(
                _job_sse_queues[job_id].put_nowait, event
            )

    async with scan_lock:
        update_job(job_id, status="running", progress=0, phase="스캔 시작")
        _push({"type": "progress", "phase": "스캔 시작", "progress": 0})

        def cb(phase: str, pct: int):
            if pct == -1:   # 취소 신호
                _push({"type": "cancelled", "phase": phase, "progress": 0})
                return
            update_job(job_id, phase=phase, progress=pct)
            _push({"type": "progress", "phase": phase, "progress": pct})

        try:
            from sls_scanner.core.pipeline import run_pipeline_with_cb, ScanCancelledError
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: run_pipeline_with_cb(
                        target=target, strength=strength, cb=cb, job_id=job_id
                    )
                )
            except ScanCancelledError as ce:
                update_job(
                    job_id,
                    status="cancelled",
                    phase=str(ce)[:80],
                    finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
                _push({"type": "cancelled", "phase": "사용자가 취소했습니다", "progress": 0})
                return

        except Exception as e:
            update_job(
                job_id,
                status="error",
                phase="오류: " + str(e)[:80],
                finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            _push({"type": "error", "phase": str(e)[:80], "progress": 0})
            return

        reports_dir = "results/reports"

        safe = (
            target.replace("http://", "")
            .replace("https://", "")
            .replace("/", "_")
            .replace(":", "_")
            .lstrip("_")
        )

        try:
            files = sorted(
                [f for f in os.listdir(reports_dir) if f.startswith(safe)],
                key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)),
                reverse=True,
            )[:7]

            for f in files:
                save_report(job_id, _report_type(f), f)

        except Exception:
            pass

        update_job(
            job_id,
            status="done",
            progress=100,
            phase="완료",
            finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        _push({"type": "done", "phase": "완료", "progress": 100})
