from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Query
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel
import uuid, os, asyncio
from datetime import datetime

app = FastAPI(title="Shift-Left-Sync API")
jobs: dict = {}
scan_lock = asyncio.Lock()
API_KEY = os.getenv("API_KEY", "sls-secret-2026")

def verify_key(key: str):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# ── 웹 UI ──────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def web_ui():
    return """<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>Shift-Left-Sync 보안 스캐너</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1f2e,#2d3561);padding:24px 40px;border-bottom:1px solid #2d3561}
.header h1{font-size:22px;color:#64b5f6}
.header p{font-size:13px;color:#888;margin-top:4px}
.container{max-width:860px;margin:32px auto;padding:0 20px}
.card{background:#1a1f2e;border:1px solid #2d3561;border-radius:12px;padding:24px;margin-bottom:18px}
.card h2{font-size:15px;color:#64b5f6;margin-bottom:14px}
.input-row{display:flex;gap:8px;margin-bottom:10px}
input[type=text],input[type=password]{flex:1;background:#0f1117;border:1px solid #2d3561;
  color:#e0e0e0;padding:9px 13px;border-radius:8px;font-size:13px;outline:none}
input:focus{border-color:#64b5f6}
select{background:#0f1117;border:1px solid #2d3561;color:#e0e0e0;
  padding:9px 13px;border-radius:8px;font-size:13px}
.btn{background:#1565c0;color:white;border:none;padding:9px 20px;
  border-radius:8px;cursor:pointer;font-size:13px;font-weight:500}
.btn:hover{background:#1976d2}
.btn-sm{background:#2d3561;color:#aaa;padding:5px 12px;border-radius:6px;
  border:none;cursor:pointer;font-size:12px}
.badge{display:inline-block;font-size:11px;font-weight:bold;padding:2px 9px;border-radius:10px}
.pending{background:#333;color:#aaa}
.queued{background:#2a2a1a;color:#ffd54f}
.running{background:#1a3a5c;color:#64b5f6}
.done{background:#1a3a2a;color:#66bb6a}
.error{background:#3a1a1a;color:#ef5350}
.progress-wrap{background:#0f1117;border-radius:6px;overflow:hidden;height:8px;margin:8px 0}
.progress-bar{height:100%;background:linear-gradient(90deg,#1565c0,#64b5f6);
  transition:width .5s ease;border-radius:6px}
.job-card{background:#0f1117;border:1px solid #2d3561;border-radius:8px;
  padding:12px 16px;margin-bottom:10px}
.job-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.job-id{font-family:monospace;font-size:12px;color:#64b5f6}
.target-row{display:flex;align-items:center;gap:8px;padding:5px 0;
  border-top:1px solid #1a2a3a;margin-top:6px;flex-wrap:wrap}
.target-label{font-size:11px;color:#888;min-width:180px;font-family:monospace}
.report-link{font-size:11px;background:#1a3a5c;color:#64b5f6;
  padding:2px 9px;border-radius:4px;text-decoration:none;white-space:nowrap}
.report-link:hover{background:#1976d2;color:white}
#status{font-size:12px;color:#888;margin-top:8px;min-height:18px}
.info-box{background:#1a2a3a;border:1px solid #2d4a6a;border-radius:8px;
  padding:10px 14px;margin-bottom:14px;font-size:12px;color:#90caf9}
</style></head><body>
<div class="header">
  <h1>🛡️ Shift-Left-Sync 보안 스캐너</h1>
  <p>URL을 입력하면 Docker 환경에서 자동으로 보안 취약점을 분석합니다</p>
</div>
<div class="container">
  <div class="card">
    <h2>스캔 설정</h2>
    <div class="info-box">⚠️ 스캔은 순차 처리됩니다. 진행 중인 스캔이 있으면 대기(queued) 상태가 됩니다.</div>
    <div class="input-row">
      <input type="password" id="apikey" placeholder="API Key" value="sls-secret-2026" style="max-width:220px">
    </div>
    <div class="input-row">
      <input type="text" id="target" placeholder="http://example.com">
      <button class="btn-sm" onclick="addTarget()">+ 추가</button>
    </div>
    <div id="target-list"></div>
    <div class="input-row" style="margin-top:12px">
      <select id="strength">
        <option value="low">🔵 low — 빠른 점검 (5~10분)</option>
        <option value="medium" selected>🟠 medium — 표준 점검 (15~30분)</option>
        <option value="high">🔴 high — 심화 점검 (30~60분)</option>
      </select>
      <button class="btn" onclick="startScan()">▶ 스캔 시작</button>
    </div>
    <div id="status"></div>
  </div>
  <div class="card">
    <h2>스캔 결과</h2>
    <div id="jobs"></div>
  </div>
</div>
<script>
let targets = ["http://218.156.141.53:3000"];
let pollTimers = {};

function renderTargets() {
  document.getElementById('target-list').innerHTML = targets.map((t,i) =>
    `<div style="display:flex;gap:8px;margin-bottom:5px">
      <span style="flex:1;font-size:12px;color:#aaa;padding:5px 0">${t}</span>
      <button class="btn-sm" onclick="removeTarget(${i})">✕</button>
    </div>`).join('');
}
function addTarget() {
  const v = document.getElementById('target').value.trim();
  if (v && !targets.includes(v)) { targets.push(v); renderTargets(); }
  document.getElementById('target').value = '';
}
function removeTarget(i) { targets.splice(i,1); renderTargets(); }

function getKey() { return document.getElementById('apikey').value; }

// 리포트 링크: key를 쿼리 파라미터로 전달
function reportUrl(filename) {
  return `/report/${filename}?key=${encodeURIComponent(getKey())}`;
}

function labelOf(f) {
  if (f.includes('simple'))    return '📄 간편';
  if (f.includes('report.html')) return '🔧 전문가';
  if (f.includes('full.json'))   return '📦 JSON';
  if (f.includes('confirmed'))   return '✅ 확정';
  if (f.includes('unverified'))  return '⚠️ 수동검토';
  if (f.includes('false_positive')) return '❌ 오탐';
  if (f.includes('full.csv'))    return '📊 전체CSV';
  return '📄';
}

async function startScan() {
  if (!targets.length) { alert('URL을 입력하세요'); return; }
  document.getElementById('status').textContent = '스캔 요청 중...';
  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json','x-api-key': getKey()},
      body: JSON.stringify({targets, strength: document.getElementById('strength').value})
    });
    if (res.status === 401) { document.getElementById('status').textContent = '❌ API Key 오류'; return; }
    const data = await res.json();
    document.getElementById('status').textContent = `✅ 요청됨 — Job: ${data.job_id}`;
    renderJob(data);
    pollStatus(data.job_id);
  } catch(e) { document.getElementById('status').textContent = '❌ 실패: ' + e.message; }
}

function renderJob(job) {
  const pct = job.progress || 0;
  const isActive = job.status === 'running' || job.status === 'queued';

  // 타겟별 리포트 분류
  const byTarget = {};
  (job.targets || []).forEach(t => { byTarget[t] = []; });
  (job.reports || []).forEach(f => {
    const safe = Object.keys(byTarget).find(t =>
      f.startsWith(t.replace('http://','').replace('https://','')
                    .replace(/[/:]/g,'_').replace(/^_+/,''))
    );
    if (safe) byTarget[safe].push(f);
    else {
      const first = Object.keys(byTarget)[0];
      if (first) byTarget[first].push(f);
    }
  });

  const targetRows = Object.entries(byTarget).map(([t, files]) =>
    files.length ? `<div class="target-row">
      <span class="target-label">${t}</span>
      ${files.map(f => `<a class="report-link" href="${reportUrl(f)}" target="_blank">${labelOf(f)}</a>`).join('')}
    </div>` : ''
  ).join('');

  const html = `
    <div class="job-header">
      <span class="job-id">Job: ${job.job_id}</span>
      <span class="badge ${job.status}">${job.status}${job.status==='running'?' '+pct+'%':''}</span>
    </div>
    <div style="font-size:11px;color:#555">${(job.started_at||'').replace('T',' ').slice(0,19)}</div>
    ${isActive ? `<div class="progress-wrap"><div class="progress-bar" style="width:${pct}%"></div></div>
    <div style="font-size:11px;color:#64b5f6;margin-bottom:4px">${job.phase||'스캔 준비 중...'}</div>` : ''}
    ${targetRows}`;

  let div = document.getElementById('job-'+job.job_id);
  if (!div) {
    div = document.createElement('div');
    div.id = 'job-'+job.job_id;
    div.className = 'job-card';
    document.getElementById('jobs').prepend(div);
  }
  div.innerHTML = html;
}

function pollStatus(job_id) {
  if (pollTimers[job_id]) return;
  pollTimers[job_id] = setInterval(async () => {
    const res = await fetch(`/scan/${job_id}?key=${encodeURIComponent(getKey())}`);
    const data = await res.json();
    renderJob(data);
    if (data.status==='done' || data.status==='error') {
      clearInterval(pollTimers[job_id]); delete pollTimers[job_id];
    }
  }, 4000);
}
renderTargets();
</script>
</body></html>"""

# ── API ───────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    targets: list[str]
    strength: str = "medium"

@app.post("/scan")
async def start_scan(req: ScanRequest, bg: BackgroundTasks,
                     x_api_key: str = Header(None)):
    verify_key(x_api_key)
    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "job_id": job_id, "status": "pending",
        "targets": req.targets, "strength": req.strength,
        "started_at": datetime.now().isoformat(),
        "finished_at": None, "reports": [],
        "progress": 0, "phase": "대기 중",
    }
    bg.add_task(_run_scan, job_id, req.targets, req.strength)
    return jobs[job_id]

@app.get("/scan/{job_id}")
async def get_status(job_id: str,
                     x_api_key: str = Header(None),
                     key: str = Query(None)):
    verify_key(x_api_key or key)
    if job_id not in jobs:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return jobs[job_id]

@app.get("/report/{filename}")
async def download_report(filename: str,
                           x_api_key: str = Header(None),
                           key: str = Query(None)):
    verify_key(x_api_key or key)
    path = f"results/reports/{filename}"
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "Not found"})
    media = "text/html" if filename.endswith(".html") else \
            "application/json" if filename.endswith(".json") else "text/csv"
    return FileResponse(path, media_type=media, filename=filename)

@app.get("/health")
async def health():
    return {"status": "ok"}

# ── 스캔 실행 ─────────────────────────────────────────────────
async def _run_scan(job_id: str, targets: list[str], strength: str):
    jobs[job_id]["status"] = "queued"
    jobs[job_id]["phase"]  = "대기 중 (이전 스캔 완료 후 시작)"

    async with scan_lock:
        jobs[job_id]["status"]   = "running"
        jobs[job_id]["progress"] = 0
        jobs[job_id]["phase"]    = "스캔 시작"

        # 진행률 업데이트를 위해 pipeline에 콜백 전달
        import threading

        def progress_cb(phase: str, pct: int):
            jobs[job_id]["phase"]    = phase
            jobs[job_id]["progress"] = pct

        try:
            from sls_scanner.core.pipeline import run_pipeline_with_cb
            report_files = []
            n = len(targets)
            for i, target in enumerate(targets):
                base_pct = int(i / n * 100)
                def cb(phase, pct, base=base_pct, total=n):
                    progress_cb(phase, base + int(pct / total))
                run_pipeline_with_cb(target=target, strength=strength, cb=cb)
                reports_dir = "results/reports"
                safe = target.replace("http://","").replace("https://","") \
                             .replace("/","_").replace(":","_").lstrip("_")
                files = sorted(
                    [f for f in os.listdir(reports_dir) if f.startswith(safe)],
                    key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)),
                    reverse=True)
                report_files.extend(files[:7])

            jobs[job_id]["status"]      = "done"
            jobs[job_id]["progress"]    = 100
            jobs[job_id]["phase"]       = "완료"
            jobs[job_id]["finished_at"] = datetime.now().isoformat()
            jobs[job_id]["reports"]     = report_files

        except ImportError:
            # run_pipeline_with_cb 없으면 기존 방식으로 폴백
            from sls_scanner.core.pipeline import run_pipeline
            report_files = []
            for i, target in enumerate(targets):
                jobs[job_id]["phase"]    = f"[{i+1}/{len(targets)}] {target} 스캔 중"
                jobs[job_id]["progress"] = int(i / len(targets) * 90)
                run_pipeline(target=target, strength=strength)
                reports_dir = "results/reports"
                safe = target.replace("http://","").replace("https://","") \
                             .replace("/","_").replace(":","_").lstrip("_")
                files = sorted(
                    [f for f in os.listdir(reports_dir) if f.startswith(safe)],
                    key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)),
                    reverse=True)
                report_files.extend(files[:7])
            jobs[job_id]["status"]      = "done"
            jobs[job_id]["progress"]    = 100
            jobs[job_id]["phase"]       = "완료"
            jobs[job_id]["finished_at"] = datetime.now().isoformat()
            jobs[job_id]["reports"]     = report_files

        except Exception as e:
            jobs[job_id]["status"]      = "error"
            jobs[job_id]["phase"]       = f"오류: {str(e)[:80]}"
            jobs[job_id]["finished_at"] = datetime.now().isoformat()
