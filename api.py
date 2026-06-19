from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Query, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import uuid
import os
import json
import asyncio
from datetime import datetime, timedelta

from sls_scanner.services.scanner_service import (
    run_scan_job,
    cancel_scan_job,
    ScanCancelledError,
)

# ── SSE / 취소 전역 상태 ─────────────────────────────────────────
_job_sse_queues: dict[str, asyncio.Queue] = {}   # job_id → SSE Queue
_main_loop: asyncio.AbstractEventLoop | None = None

# ── 동시 스캔 제어 ────────────────────────────────────────────────
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
# Python 3.10+ 에서는 이벤트루프 없이 생성 가능
# startup 데코레이터 누락 등 예외상황 방어용 안전망
_scan_semaphore: asyncio.Semaphore | None = None
_pending_jobs:   list[str] = []
_active_jobs:    list[str] = []

# ── #12 봇 블랙리스트 ─────────────────────────────────────────────
import time
import collections
import fnmatch
from datetime import timedelta

_ip_blacklist:  dict[str, dict] = {}   # ip → {reason, blocked_at, auto}
_request_log:   collections.deque = collections.deque(maxlen=5000)  # 최근 요청 이력

# 봇 탐지 규칙
_BOT_PATHS = {
    "/mcp", "/sse", "/mcp-sse", "/.env", "/.git/config",
    "/config.json", "/AGENTS.md", "/metrics",
    "/nmaplowercheck", "/Trinity.txt", "/HNAP1", "/evox/about",
    "/.well-known/security.txt",
}
_BOT_METHODS   = {"CONNECT"}           # 프록시 악용
_BOT_RATE_LIMIT = 80                   # 60초 내 N 요청 초과 시 차단
_BOT_RATE_WINDOW = 60                  # 초
_BOT_AUTO_THRESHOLD = 3                # 탐지 횟수 → 자동 차단
_ip_strike: dict[str, int] = {}        # ip → 누적 탐지 횟수

# 요청 IP가 현재 블랙리스트에 있는지 확인한다.
def _is_blacklisted(ip: str) -> tuple[bool, str]:
    entry = _ip_blacklist.get(ip)
    if not entry:
        return False, ""
    return True, entry.get("reason", "블랙리스트")

# 특정 IP를 수동/자동 블랙리스트에 등록한다.
def _add_blacklist(ip: str, reason: str, auto: bool = True):
    _ip_blacklist[ip] = {
        "reason":     reason,
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "auto":       auto,
    }
    print(f"  [BLACKLIST] {ip} 차단 — {reason}")

# 요청 경로/메서드/빈도를 분석해 봇성 요청이면 strike를 누적하고 임계치 초과 시 차단한다.
def _analyze_request(ip: str, method: str, path: str):
    """요청 패턴 분석 → 봇 탐지 시 strike 누적 → 임계값 초과 시 자동 차단"""
    if ip in _ip_blacklist:
        return

    # 내부/사설 IP는 절대 블랙리스트 대상 아님 (Nmap, Docker 브리지 등)
    import ipaddress as _ip_mod
    try:
        _addr = _ip_mod.ip_address(ip)
        if _addr.is_private or _addr.is_loopback or _addr.is_link_local:
            return
    except ValueError:
        pass

    # 인증된 사용자 경로는 rate-limit 대상에서 제외
    SAFE_PREFIXES = ("/api/scan", "/api/blacklist", "/dashboard",
                     "/admin", "/auth", "/static", "/view", "/report")
    if any(path.startswith(p) for p in SAFE_PREFIXES):
        return

    strike = False
    reason = ""

    # 민감 경로 탐색
    for bot_path in _BOT_PATHS:
        if path == bot_path or path.startswith(bot_path):
            strike = True
            reason = f"민감 경로 탐색: {path}"
            break

    # 프록시 악용
    if not strike and method in _BOT_METHODS:
        strike = True
        reason = f"프록시 악용 시도: {method}"

    # Rate-limit 체크 (안전 경로 제외 후)
    if not strike:
        now = time.time()
        recent = [r for r in _request_log
                  if r["ip"] == ip and now - r["ts"] < _BOT_RATE_WINDOW]
        if len(recent) > _BOT_RATE_LIMIT:
            strike = True
            reason = f"과다 요청: {len(recent)}건/{_BOT_RATE_WINDOW}s"

    if strike:
        _ip_strike[ip] = _ip_strike.get(ip, 0) + 1
        if _ip_strike[ip] >= _BOT_AUTO_THRESHOLD:
            _add_blacklist(ip, reason, auto=True)
            _ip_strike.pop(ip, None)

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
    get_verified_target,
    upsert_verified_target,
    get_security_events,
    get_security_event_stats,
    add_waf_block_ip,
    remove_waf_block_ip,
    get_waf_blocklist,
)
from waf_audit_parser import ingest_waf_audit_log
from waf_blocklist import normalize_ip, sync_waf_blocklist, write_blocklist_rules
app = FastAPI(title="Shift-Left-Sync")

# static/style.css, static/app.js 연결
app.mount("/static", StaticFiles(directory="static"), name="static")

# templates/index.html, features.html, reports.html, guide.html 연결
templates = Jinja2Templates(directory="templates")

API_KEY = os.getenv("API_KEY", "sls-secret-2026")


@app.middleware("http")
# 모든 HTTP 요청에 대해 블랙리스트 차단과 봇성 요청 분석을 수행한다.
async def bot_blacklist_middleware(request: Request, call_next):
    if os.getenv("APP_BOT_GUARD_ENABLED", "true").lower() in {"0", "false", "no", "off"}:
        return await call_next(request)

    import time as _time
    ip  = request.client.host if request.client else "unknown"
    path   = request.url.path
    method = request.method

    # 블랙리스트 차단
    blocked, reason = _is_blacklisted(ip)
    if blocked:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"detail": f"Forbidden: {reason}"})

    # 요청 이력 기록
    _request_log.append({"ip": ip, "method": method, "path": path, "ts": _time.time()})

    # 봇 패턴 분석 (비동기로 분리해 응답 지연 없음)
    asyncio.create_task(asyncio.to_thread(_analyze_request, ip, method, path))

    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.on_event("startup")
# 앱 시작 시 DB와 동시 스캔 제어 상태를 초기화하고 미완료 작업을 정리한다.
async def startup():
    global _main_loop, _scan_semaphore
    _main_loop       = asyncio.get_running_loop()
    _scan_semaphore  = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    init_db()
    # 이전 서버 다운으로 running/queued 상태 남은 잡 정리
    from database import get_conn
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status='error', phase='서버 재시작으로 스캔 중단됨', "
            "finished_at=datetime('now','localtime') "
            "WHERE status IN ('running','queued')"
        )
    print(f"[INFO] 동시 스캔 슬롯: {MAX_CONCURRENT_SCANS}개")

@app.on_event("shutdown")
# 앱 종료 시 실행 중이던 스캔 작업을 error 상태로 정리한다.
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
  var initialized = false;

  es.onmessage = function(e) {
    var ev  = JSON.parse(e.data);
    var el  = document.getElementById('job-' + job_id);
    if (!el) return;

    if (ev.type === 'ping') return;

    if (ev.type === 'progress') {
      // 첫 이벤트에서 전체 카드 갱신 → 취소 버튼 표시
      if (!initialized) { initialized = true; fetchAndUpdate(job_id); }
      updateJobProgress(el, job_id, ev.phase, ev.progress);
    } else if (ev.type === 'queued') {
      // 대기 순번 표시
      var pt = el.querySelector('.phase-text');
      var bd = el.querySelector('.badge');
      if (pt) pt.textContent = ev.phase;
      if (bd) { bd.textContent = '대기 ' + ev.queue_position + '/' + ev.queue_total; bd.className = 'badge queued'; }
    } else if (ev.type === 'warning') {
      // 타겟 부하 경고 — 카드 하단에 경고 표시
      var warnEl = document.getElementById('warn-' + job_id);
      if (!warnEl) {
        warnEl = document.createElement('div');
        warnEl.id = 'warn-' + job_id;
        warnEl.style.cssText = 'font-size:11px;color:#fca5a5;margin-top:4px';
        var card = document.getElementById('job-' + job_id);
        if (card) card.appendChild(warnEl);
      }
      warnEl.textContent = ev.phase;
    } else if (ev.type === 'done') {
      es.close(); delete sseConnections[job_id];
      fetchAndUpdate(job_id);
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
    if (res.status === 401) {
      _stopAllPolling();
      location.href = '/?msg=' + encodeURIComponent('세션이 만료되었습니다. 다시 로그인해 주세요.');
      return;
    }
    if (!res.ok) return;
    var j   = await res.json();
    var el  = document.getElementById('job-' + job_id);
    if (el) updateJobEl(el, j);
  } catch(e) {}
}

function _stopAllPolling() {
  Object.keys(pollTimers).forEach(function(id) {
    clearInterval(pollTimers[id]);
    delete pollTimers[id];
  });
  Object.keys(sseConnections).forEach(function(id) {
    sseConnections[id].close();
    delete sseConnections[id];
  });
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
      + 'data-jobid="' + j.job_id + '" onclick="cancelScan(this.dataset.jobid)">⏹ 취소</button>'
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
    if (data.verify_skip) {
      // 관리자 또는 24h 캐시 → 인증 UI 생략하고 바로 SSE 연결
      var skipEl = document.getElementById('job-' + data.job_id);
      if (skipEl) {
        var note = document.createElement('div');
        note.style.cssText = 'font-size:11px;color:#86efac;margin-top:4px';
        note.textContent = '✅ ' + (data.skip_reason || '소유권 인증 면제');
        skipEl.appendChild(note);
      }
      connectSSE(data.job_id);
    } else if (data.status === 'pending_verify') {
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
    if (res.status === 401) {
      clearInterval(pollTimers[job_id]);
      delete pollTimers[job_id];
      _stopAllPolling();
      location.href = '/?msg=' + encodeURIComponent('세션이 만료되었습니다. 다시 로그인해 주세요.');
      return;
    }
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

// ── 탭 포커스 복귀 시 running 잡 상태 재확인 ─────────────────
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState !== 'visible') return;
  document.querySelectorAll('.job-card').forEach(function(el) {
    var id    = el.id.replace('job-', '');
    var badge = el.querySelector('.badge');
    if (badge && (badge.classList.contains('running') || badge.classList.contains('queued'))) {
      fetchAndUpdate(id);
    }
  });
});

// ── 60초마다 running 잡 상태 강제 체크 (SSE 이벤트 소실 복구) ─
setInterval(function() {
  document.querySelectorAll('.job-card').forEach(function(el) {
    var id    = el.id.replace('job-', '');
    var badge = el.querySelector('.badge');
    if (badge && (badge.classList.contains('running') || badge.classList.contains('queued'))) {
      fetchAndUpdate(id);
    }
  });
}, 60000);
</script>
"""



# ─────────────────────────────────────────────
# 공통 헬퍼
# ─────────────────────────────────────────────
# 리포트 파일명 패턴을 관리자/대시보드 화면용 짧은 라벨로 변환한다.
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


# 리포트 파일명 패턴을 다운로드/표시 분기에 사용할 내부 타입으로 변환한다.
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


# 요청 쿠키의 세션 토큰으로 현재 로그인 사용자를 조회한다.
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


# 작업/사용자 상태 코드를 화면에 표시할 라벨로 변환한다.
def _status_label(status):
    return STATUS_LABELS.get(status, status)


# 작업/사용자 상태 코드를 CSS 배지 클래스명으로 변환한다.
def _status_class(status):
    return STATUS_CLASSES.get(status, "badge-default")


# DB/ISO 형식 시간을 관리자 화면에서 쓰는 yyyy-mm-dd hh:mm 형식으로 정리한다.
def _fmt_datetime(value):
    if not value:
        return "-"
    raw = str(value).replace("T", " ")
    try:
        return datetime.fromisoformat(raw).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return raw[:16]


# 리포트 내부 타입을 화면에 표시할 리포트 종류명으로 변환한다.
def _report_type_label(report_type):
    if not report_type:
        return "리포트"
    return REPORT_TYPE_LABELS.get(report_type, str(report_type).upper())


# 현재 요청 사용자가 관리자이면 사용자 정보를 반환하고, 아니면 None을 반환한다.
def _require_admin(request):
    user = _current_user(request)
    if not user or user.get("role") != "admin":
        return None
    return user


# 관리자 대시보드 상단 카드에 표시할 사용자/스캔/리포트 집계를 만든다.
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


# 스캔 작업 목록을 관리자 히스토리 화면용 로그 항목으로 변환한다.
def _history_logs(jobs):
    return [
        {
            "date": _fmt_datetime(job.get("created_at")),
            "user_id": job.get("username", "-"),
            "action": f"스캔 요청: {job.get('target', '-')}",
        }
        for job in jobs
    ]


# 관리자 공통 템플릿 컨텍스트를 구성해 Jinja 템플릿을 렌더링한다.
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


# 레거시 단일 페이지 화면을 공통 HTML 레이아웃으로 감싸서 반환한다.
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
# 로그인/회원가입 첫 화면을 렌더링하고, 승인된 사용자는 대시보드로 보낸다.
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


# 서비스 기능 소개 페이지를 렌더링한다.
@app.get("/features", response_class=HTMLResponse)
async def features_page(request: Request):
    return templates.TemplateResponse(
        "features.html",
        {"request": request},
    )


# 리포트 안내 페이지를 렌더링한다.
@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    return templates.TemplateResponse(
        "reports.html",
        {"request": request},
    )


# 사용 가이드 페이지를 렌더링한다.
@app.get("/guide", response_class=HTMLResponse)
async def guide_page(request: Request):
    return templates.TemplateResponse(
        "guide.html",
        {"request": request},
    )


# ═══════════════════════════════════════════════════════════
# 2. 인증 엔드포인트
# ═══════════════════════════════════════════════════════════
# 로그인 폼을 처리하고 승인된 사용자에게 세션 쿠키를 발급한다.
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


# 회원가입 입력값을 검증하고 승인 대기 상태의 사용자를 생성한다.
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


# 현재 세션을 삭제하고 로그인 화면으로 되돌린다.
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
# 승인된 사용자의 스캔 요청/진행/리포트 목록 대시보드를 렌더링한다.
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    u = _current_user(request)

    if not u or u.get("status") != "approved":
        return RedirectResponse("/")

    jobs = get_user_jobs(u["id"])
    job_cards = ""

    for j in jobs:
        reports_html = "".join(
            '<a class="report-link" href="' +
            ('/view/' + r["filename"] if r["filename"].endswith(".html") else '/report/' + r["filename"]) +
            '">' + _report_label(r["filename"]) + "</a>"
            for r in j.get("reports", [])
        )

        pct = j.get("progress", 0)
        is_active = j["status"] in ("queued", "running")

        progress_html = (
            '<div class="progress-wrap"><div class="progress-bar" style="width:' + str(pct) + '%"></div></div>'
            '<div style="font-size:11px;color:#64b5f6">' + str(j.get("phase", "")) + "</div>"
        ) if is_active else ""

        status_label = j["status"] + (" " + str(pct) + "%" if is_active else "")

        cancel_btn = (
            '<button id="cancel-btn-' + j["job_id"] + '" '
            'class="btn btn-danger" style="font-size:11px;padding:3px 10px;margin-left:8px" '
            'data-jobid="' + j["job_id"] + '" onclick="cancelScan(this.dataset.jobid)">⏹ 취소</button>'
        ) if is_active else ""

        job_cards += (
            '<div class="job-card" id="job-' + j["job_id"] + '">'
            '<div class="job-header" style="display:flex;align-items:center;flex-wrap:wrap;gap:6px">'
            '<span class="job-id">Job: ' + j["job_id"] + "</span>"
            '<span class="badge ' + j["status"] + '">' + status_label + "</span>"
            + cancel_btn +
            "</div>"
            '<div style="font-size:12px;color:#888;margin-bottom:4px">'
            "🎯 " + j["target"] +
            " &nbsp;|&nbsp; 강도: " + j["strength"] +
            " &nbsp;|&nbsp; " + str(j.get("created_at", ""))[:16] +
            "</div>"
            + progress_html +
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
# 4. 관리자 대시보드
# ═══════════════════════════════════════════════════════════
# 관리자 홈 화면에 전체 사용자, 스캔, 승인 대기 현황을 표시한다.
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


# 관리자 승인 대기 사용자 목록 화면을 렌더링한다.
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


# 관리자 사용자 목록/상태 관리 화면을 렌더링한다.
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


# 관리자 스캔 히스토리 화면에 전체 작업 데이터를 전달한다.
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


# 관리자 보안 이벤트 화면을 렌더링하고 WAF/SOAR 이벤트를 탭 기준으로 조회한다.
@app.get("/admin/security", response_class=HTMLResponse)
# 관리자 보안 이벤트 화면을 렌더링한다.
# 진입 시 WAF audit.log를 DB에 동기화하고, view 탭 기준으로 이벤트를 조회한다.
async def admin_security(
    request: Request,
    view: str = Query("detect", max_length=32),
    source: str = Query("", max_length=32),
    severity: str = Query("", max_length=32),
    action: str = Query("", max_length=32),
):
    u = _require_admin(request)
    if not u:
        return RedirectResponse("/")
    # view는 보안 이벤트 화면의 탭 선택값이다. 허용값 외 입력은 기본 탐지 탭으로 돌린다.
    if view not in {"detect", "context"}:
        view = "detect"

    ingest_result = ingest_waf_audit_log()
    events = get_security_events(
        source=source or None,
        severity=severity or None,
        action=action or None,
        view=view,
        limit=100,
    )
    stats = get_security_event_stats()
    blocklist = get_waf_blocklist()
    try:
        rule_sync = write_blocklist_rules()
    except Exception as exc:
        rule_sync = {"error": str(exc)}

    return _admin_template(
        request,
        "admin/security.html",
        "security",
        u,
        events=events,
        stats=stats,
        waf_mode=os.getenv("WAF_RULE_ENGINE", os.getenv("MODSEC_RULE_ENGINE", "DetectionOnly")),
        waf_blocklist=blocklist,
        waf_rule_sync=rule_sync,
        filters={"view": view, "source": source, "severity": severity, "action": action},
        ingest_result=ingest_result,
    )


# 승인 대기 사용자를 승인 상태로 변경한다.
@app.post("/admin/users/{user_id}/approve")
async def approve_user(user_id: int, request: Request):
    u = _current_user(request)

    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)

    update_user_status(user_id, "approved", approved_by=u["id"])
    ref = request.headers.get("referer", "/admin/pending")
    return RedirectResponse(ref if "/admin" in ref else "/admin/pending", status_code=302)


# 승인 대기 사용자를 거절하고 계정을 삭제한다.
@app.post("/admin/users/{user_id}/reject")
async def reject_user(user_id: int, request: Request):
    u = _current_user(request)
    if not u or u["role"] != "admin":
        return RedirectResponse("/", status_code=302)
    # 거절 = 즉시 삭제
    delete_user(user_id)
    ref = request.headers.get("referer", "/admin/pending")
    return RedirectResponse(ref if "/admin" in ref else "/admin/pending", status_code=302)

# 관리자가 특정 사용자를 삭제한다. 자기 자신은 삭제하지 않는다.
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


# 관리자가 특정 사용자의 역할을 admin/user로 변경한다.
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
# 스캔 시작 API에서 받는 대상 URL과 스캔 강도 요청 모델이다.
class ScanRequest(BaseModel):
    target: str
    strength: str = "medium"


# 스캔 작업을 생성하고, 소유권 검증이 면제/캐시된 경우 즉시 큐에 넣는다.
@app.post("/api/scan")
async def api_start_scan(req: ScanRequest, request: Request):
    u = _current_user(request)
    if not u or u.get("status") != "approved":
        raise HTTPException(status_code=401, detail="로그인 필요")

    job_id = str(uuid.uuid4())[:8]
    job    = create_job(job_id, u["id"], req.target, req.strength)

    is_admin   = u.get("role") == "admin"
    cached_ver = get_verified_target(req.target)

    if is_admin or cached_ver:
        # 소유권 인증 스킵 → 즉시 큐 진입
        if is_admin:
            skip_reason = "관리자 권한으로 인증 면제"
        else:
            skip_reason = f"24시간 내 인증됨 (만료: {cached_ver['expires_at'][:16]})"

        update_job(job_id, status="queued", phase=f"{skip_reason} — 슬롯 대기 중")
        _job_sse_queues[job_id] = asyncio.Queue()
        asyncio.create_task(_run_scan_concurrent(job_id, req.target, req.strength))

        result               = dict(job)
        result["status"]     = "queued"
        result["phase"]      = skip_reason
        result["verify_skip"] = True
        result["skip_reason"] = skip_reason
        return result

    # 일반 사용자 + 캐시 없음 → 소유권 인증 필요
    import secrets as _sec
    token = "SLS-VERIFY-" + _sec.token_hex(8).upper()
    create_verify_token(job_id, token, req.target)
    update_job(job_id, status="pending_verify", phase="소유권 인증 대기 중")

    result = dict(job)
    result["token"]       = token
    result["status"]      = "pending_verify"
    result["phase"]       = "소유권 인증 대기 중"
    result["verify_skip"] = False
    return result


# 소유권 검증 토큰을 대상 사이트에서 확인한 뒤 검증 성공 시 스캔을 큐에 넣는다.
@app.post("/api/scan/{job_id}/verify")
async def api_verify_ownership(job_id: str, request: Request):
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
        update_job(job_id, status="queued", phase="소유권 인증 완료 — 슬롯 대기 중")
        job      = get_job(job_id)
        strength = job.get("strength", "medium")

        # 24시간 캐시 저장
        upsert_verified_target(target, u["id"])

        # SSE 큐 미리 생성 (race condition 방지)
        _job_sse_queues[job_id] = asyncio.Queue()
        asyncio.create_task(_run_scan_concurrent(job_id, target, strength))

        return {"verified": True, "method": method,
                "message": "소유권 인증 완료! 스캔을 시작합니다."}
    else:
        update_verify_status(job_id, "failed")
        return {"verified": False,
                "message": "토큰을 찾을 수 없습니다. 파일 또는 메타태그를 확인하세요."}


# 단일 스캔 작업의 현재 상태와 리포트 정보를 조회한다.
@app.get("/api/scan/{job_id}")
async def api_get_scan(job_id: str, request: Request):
    u = _current_user(request)

    if not u:
        raise HTTPException(status_code=401)

    job = get_job(job_id)

    if not job:
        raise HTTPException(status_code=404)

    return job


# 스캔 진행 상태를 브라우저에 SSE로 실시간 전송한다.
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
        # 이미 종료된 작업은 현재 상태를 한 번 보내고 SSE를 닫는다.
        async def _immediate():
            data = json.dumps({
                "type": job.get("status"),
                "phase": job.get("phase", ""),
                "progress": job.get("progress", 0),
            })
            yield f"data: {data}\n\n"
        return StreamingResponse(_immediate(), media_type="text/event-stream")

    # 진행 중 잡 — 큐 생성 후 스트리밍
    # verify 단계에서 미리 생성된 큐가 있으면 재사용
    queue = _job_sse_queues.get(job_id)
    if not queue:
        queue = asyncio.Queue()
        _job_sse_queues[job_id] = queue

    # 진행 중인 작업은 큐 이벤트를 계속 읽어 SSE 스트림으로 전달한다.
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
                    # 안전망: 20초마다 DB에서 실제 상태 확인
                    # (SSE done 이벤트가 소실됐을 경우 복구)
                    job_now = get_job(job_id)
                    if job_now and job_now.get("status") in ("done", "error", "cancelled"):
                        yield f"data: {json.dumps({'type': job_now['status'], 'phase': job_now.get('phase',''), 'progress': job_now.get('progress', 0)})}\n\n"
                        break
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


# 관리자에게 현재 블랙리스트, strike, 최근 요청 기록을 반환한다.
@app.get("/api/blacklist")
async def api_get_blacklist(request: Request):
    u = _current_user(request)
    if not u or u.get("role") != "admin":
        raise HTTPException(status_code=403)
    return {
        "blacklist": [
            {"ip": ip, **info} for ip, info in _ip_blacklist.items()
        ],
        "strikes": dict(_ip_strike),
        "recent_requests": list(_request_log)[-50:],
    }

# 관리자가 특정 IP를 수동으로 블랙리스트에 추가한다.
@app.post("/api/blacklist/{ip}")
async def api_add_blacklist(ip: str, request: Request):
    u = _current_user(request)
    if not u or u.get("role") != "admin":
        raise HTTPException(status_code=403)
    _add_blacklist(ip, reason="관리자 수동 차단", auto=False)
    return {"blocked": True, "ip": ip}

# 관리자가 특정 IP의 블랙리스트와 strike 기록을 해제한다.
@app.delete("/api/blacklist/{ip}")
async def api_remove_blacklist(ip: str, request: Request):
    u = _current_user(request)
    if not u or u.get("role") != "admin":
        raise HTTPException(status_code=403)
    removed = _ip_blacklist.pop(ip, None)
    _ip_strike.pop(ip, None)
    return {"unblocked": True, "ip": ip, "was_blocked": removed is not None}


# 보안 이벤트 목록을 JSON으로 반환하고 화면과 같은 필터 기준을 적용한다.
def _security_redirect(request: Request):
    ref = request.headers.get("referer", "/admin/security")
    return RedirectResponse(ref if "/admin/security" in ref else "/admin/security", status_code=303)


@app.get("/api/waf/blocklist")
async def api_get_waf_blocklist(request: Request):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")
    return {
        "items": get_waf_blocklist(),
        "mode": os.getenv("WAF_RULE_ENGINE", os.getenv("MODSEC_RULE_ENGINE", "DetectionOnly")),
    }


@app.post("/api/waf/blocklist")
async def api_add_waf_blocklist_from_form(
    request: Request,
    ip: str = Form(...),
    reason: str = Form(""),
):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    normalized_ip = normalize_ip(ip)
    add_waf_block_ip(
        normalized_ip,
        reason=reason or "admin manual block",
        source="manual",
        created_by=u.get("id"),
    )
    sync_waf_blocklist(reload=False)
    return _security_redirect(request)


@app.post("/api/waf/blocklist/remove")
async def api_remove_waf_blocklist_from_form(request: Request, ip: str = Form(...)):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    normalized_ip = normalize_ip(ip)
    remove_waf_block_ip(normalized_ip)
    sync_waf_blocklist(reload=False)
    return _security_redirect(request)


@app.post("/api/waf/blocklist/{ip}")
async def api_add_waf_blocklist(ip: str, request: Request):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    normalized_ip = normalize_ip(ip)
    item = add_waf_block_ip(
        normalized_ip,
        reason="admin manual block",
        source="manual",
        created_by=u.get("id"),
    )
    sync_result = sync_waf_blocklist(reload=False)
    return {"blocked": True, "item": item, "sync": sync_result}


@app.delete("/api/waf/blocklist/{ip}")
async def api_remove_waf_blocklist(ip: str, request: Request):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    normalized_ip = normalize_ip(ip)
    removed = remove_waf_block_ip(normalized_ip)
    sync_result = sync_waf_blocklist(reload=False)
    return {"unblocked": True, "ip": normalized_ip, "was_blocked": removed, "sync": sync_result}


@app.post("/api/waf/reload")
async def api_reload_waf(request: Request):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    return {
        "rules": write_blocklist_rules(),
        "reload": {
            "ok": False,
            "skipped": True,
            "message": "WAF reload is handled by the host systemd watcher.",
        },
    }


@app.post("/api/waf/reload/apply")
async def api_reload_waf_from_form(request: Request):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    write_blocklist_rules()
    return _security_redirect(request)


@app.get("/api/security/events")
# 보안 이벤트 목록을 JSON으로 반환한다.
# 화면과 같은 view/source/severity/action 필터를 지원한다.
async def api_security_events(
    request: Request,
    view: str = Query("detect", max_length=32),
    source: str = Query("", max_length=32),
    severity: str = Query("", max_length=32),
    action: str = Query("", max_length=32),
    limit: int = Query(100, ge=1, le=500),
):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")
    # API도 화면과 같은 탭 기준으로 조회할 수 있게 맞춘다.
    if view not in {"detect", "context"}:
        view = "detect"

    ingest_waf_audit_log()
    return {
        "items": get_security_events(
            source=source or None,
            severity=severity or None,
            action=action or None,
            view=view,
            limit=limit,
        )
    }


# 보안 이벤트 통계 카드에 사용할 집계 데이터를 JSON으로 반환한다.
@app.get("/api/security/stats")
# 보안 이벤트 집계 정보를 JSON으로 반환한다.
async def api_security_stats(request: Request):
    u = _require_admin(request)
    if not u:
        raise HTTPException(403, "admin only")

    ingest_waf_audit_log()
    return get_security_event_stats()


# 실행 중이거나 대기 중인 스캔 작업에 취소 신호를 보낸다.
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

    # 스캔 서비스에 취소 신호 전달
    cancel_scan_job(job_id)
    update_job(job_id, phase="취소 요청됨 — 현재 단계 완료 후 중단")

    return {"cancelled": True, "message": "취소 요청을 전달했습니다. 현재 단계 완료 후 중단됩니다."}


# HTML 리포트에 서비스 상단 내비게이션을 삽입해 브라우저에서 보여준다.
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


# 리포트 파일을 다운로드한다. 로그인 또는 API 키 인증을 허용한다.
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


# 서비스 헬스체크용 단순 상태 응답을 반환한다.
@app.get("/health")
async def health():
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════
# 7. 스캔 실행 백그라운드 작업
# ═══════════════════════════════════════════════════════════
# 특정 job_id의 SSE 큐에 진행 이벤트를 안전하게 전달한다.
def _push_sse_for_job(job_id: str, event: dict) -> None:
    """어느 컨텍스트(스레드/코루틴)에서든 안전하게 SSE 이벤트 전송"""
    if job_id in _job_sse_queues and _main_loop:
        _main_loop.call_soon_threadsafe(
            _job_sse_queues[job_id].put_nowait, event
        )


# 대기 중인 모든 작업에 현재 큐 위치와 동시 실행 현황을 알린다.
def _broadcast_queue_status() -> None:
    """대기 중인 모든 잡에게 현재 슬롯 현황 SSE 전송"""
    active  = len(_active_jobs)
    pending = len(_pending_jobs)
    for idx, jid in enumerate(_pending_jobs):
        pos = idx + 1
        _push_sse_for_job(jid, {
            "type":          "queued",
            "phase":         f"슬롯 대기 중 ({pos}/{pending}번째) — 현재 {active}/{MAX_CONCURRENT_SCANS} 실행 중",
            "progress":      0,
            "queue_position": pos,
            "queue_total":   pending,
            "active_count":  active,
            "max_concurrent": MAX_CONCURRENT_SCANS,
        })


# 동시 실행 제한을 적용해 스캔 작업을 대기열에서 실제 실행 상태로 넘긴다.
async def _run_scan_concurrent(job_id: str, target: str, strength: str) -> None:
    """
    세마포어로 동시 실행 수를 제한.
    슬롯이 비면 즉시 스캔 시작, 대기 중에는 SSE로 현황 전송.
    """
    _pending_jobs.append(job_id)
    _broadcast_queue_status()

    async with _scan_semaphore:
        if job_id in _pending_jobs:
            _pending_jobs.remove(job_id)
        _active_jobs.append(job_id)
        _broadcast_queue_status()   # 대기 중 잡들에게 슬롯 현황 갱신

        try:
            await _run_scan(job_id, target, strength)
        finally:
            if job_id in _active_jobs:
                _active_jobs.remove(job_id)
            _broadcast_queue_status()   # 슬롯 해제 → 대기 잡들에게 알림


# scanner_service.run_scan_job을 백그라운드 executor에서 실행하고 진행/완료 상태를 DB와 SSE에 반영한다.
async def _run_scan(job_id: str, target: str, strength: str):
    # scanner_service에서 전달하는 진행률 콜백을 DB 업데이트와 SSE 이벤트로 변환한다.
    def cb(phase: str, pct: int):
        if pct == -1:   # 취소 신호
            _push_sse_for_job(job_id, {"type": "cancelled", "phase": phase, "progress": 0})
            return
        if pct == -2:   # 부하 경고 신호
            _push_sse_for_job(job_id, {"type": "warning", "phase": phase,
                                        "progress": 0, "message": phase})
            return
        update_job(job_id, phase=phase, progress=pct)
        _push_sse_for_job(job_id, {"type": "progress", "phase": phase, "progress": pct})

    update_job(job_id, status="running", progress=0, phase="스캔 시작")
    _push_sse_for_job(job_id, {"type": "progress", "phase": "스캔 시작", "progress": 0})

    try:
        try:
            await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: run_scan_job(
                    job_id=job_id,
                    target=target,
                    strength=strength,
                    progress_cb=cb,
                )
            )
        except ScanCancelledError as ce:
            update_job(
                job_id,
                status="cancelled",
                phase=str(ce)[:80],
                finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            _push_sse_for_job(job_id, {"type": "cancelled", "phase": "사용자가 취소했습니다", "progress": 0})
            return

    except Exception as e:
        update_job(
            job_id,
            status="error",
            phase="오류: " + str(e)[:80],
            finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        _push_sse_for_job(job_id, {"type": "error", "phase": str(e)[:80], "progress": 0})
        return

    # ── 정상 완료 처리 (try/except 밖) ────────────────────────
    # save_report는 pipeline.py의 _save_report_safe에서 이미 저장됨
    # 여기서 중복 저장하면 리포트 링크가 2배로 표시되므로 제거

    update_job(
        job_id,
        status="done",
        progress=100,
        phase="완료",
        finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    _push_sse_for_job(job_id, {"type": "done", "phase": "완료", "progress": 100})
