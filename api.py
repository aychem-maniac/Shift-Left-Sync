# api.py — FastAPI 서버
# 사용자가 URL만 입력하면 스캔이 Docker 내부에서 실행됩니다

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import uuid, os, asyncio
from datetime import datetime

app = FastAPI(title="Shift-Left-Sync API")

# 진행 중인 작업 상태 저장
jobs: dict = {}


class ScanRequest(BaseModel):
    targets: list[str]
    strength: str = "medium"   # low / medium / high


class ScanStatus(BaseModel):
    job_id: str
    status: str                # pending / running / done / error
    targets: list[str]
    started_at: str
    finished_at: str = None
    reports: list[str] = []


@app.post("/scan", response_model=ScanStatus)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """스캔 시작 — 즉시 job_id 반환, 백그라운드에서 실행"""
    job_id = str(uuid.uuid4())[:8]
    now    = datetime.now().isoformat()

    jobs[job_id] = {
        "job_id":      job_id,
        "status":      "pending",
        "targets":     req.targets,
        "strength":    req.strength,
        "started_at":  now,
        "finished_at": None,
        "reports":     [],
    }

    background_tasks.add_task(_run_scan, job_id, req.targets, req.strength)
    return jobs[job_id]


@app.get("/scan/{job_id}", response_model=ScanStatus)
async def get_status(job_id: str):
    """스캔 진행 상태 조회"""
    if job_id not in jobs:
        return JSONResponse(status_code=404, content={"error": "Job not found"})
    return jobs[job_id]


@app.get("/scan/{job_id}/report/{filename}")
async def download_report(job_id: str, filename: str):
    """리포트 파일 다운로드"""
    path = f"results/reports/{filename}"
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "Report not found"})
    return FileResponse(path, filename=filename)


@app.get("/health")
async def health():
    return {"status": "ok"}


async def _run_scan(job_id: str, targets: list[str], strength: str):
    """백그라운드 스캔 실행"""
    jobs[job_id]["status"] = "running"
    try:
        # CLI와 동일하게 pipeline 직접 호출
        from sls_scanner.core.pipeline import run_pipeline
        report_files = []

        for target in targets:
            run_pipeline(target=target, strength=strength)
            # 가장 최근 생성된 리포트 파일 수집
            reports_dir = "results/reports"
            files = sorted(
                [f for f in os.listdir(reports_dir)
                 if f.startswith(target.replace("http://","").replace("https://","")
                                .replace("/","_").replace(":","_"))],
                key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)),
                reverse=True
            )
            report_files.extend(files[:7])  # 타겟당 최대 7개 파일

        jobs[job_id]["status"]      = "done"
        jobs[job_id]["finished_at"] = datetime.now().isoformat()
        jobs[job_id]["reports"]     = report_files

    except Exception as e:
        jobs[job_id]["status"]      = "error"
        jobs[job_id]["finished_at"] = datetime.now().isoformat()
        jobs[job_id]["error"]       = str(e)
