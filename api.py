# api.py — FastAPI 서버
# 사용자가 URL을 입력하면 스캔이 Docker 내부에서 실행됩니다.

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
import uuid
import os
import json
from typing import Optional


app = FastAPI(title="Shift-Left-Sync API")

# 프론트와 백엔드가 같은 서버면 CORS가 꼭 필요하진 않지만,
# 나중에 React/Vite 등 별도 프론트 서버를 쓸 경우를 대비해서 추가합니다.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 실제 운영 시에는 프론트 주소만 허용하는 것이 좋습니다.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 진행 중인 작업 상태 저장
# 주의: 현재는 메모리 저장 방식이라 서버 재시작 시 job 정보가 사라집니다.
jobs: dict = {}


class ScannerOptions(BaseModel):
    header: bool = True
    zap: bool = True
    nmap: bool = True
    sqlmap: bool = False
    static_code: bool = False
    cookie: bool = True


class ScanRequest(BaseModel):
    targets: list[str]
    strength: str = "medium"  # low / medium / high

    # 추가 옵션: 프론트에서 권한 확인 체크박스 값을 보낼 수 있게 함
    permission_confirmed: bool = False

    # 추가 옵션: 나중에 스캐너 선택 체크박스를 붙일 때 사용
    scanners: ScannerOptions = Field(default_factory=ScannerOptions)


class ScanStep(BaseModel):
    key: str
    label: str
    status: str  # waiting / running / done / error


class ScanStatus(BaseModel):
    job_id: str
    status: str  # pending / running / done / error
    targets: list[str]
    strength: str = "medium"
    started_at: str
    finished_at: Optional[str] = None
    reports: list[str] = Field(default_factory=list)

    # 추가 응답 필드
    progress: int = 0
    current_step: Optional[str] = None
    steps: list[ScanStep] = Field(default_factory=list)
    error: Optional[str] = None


def make_default_steps() -> list[dict]:
    return [
        {
            "key": "target_validation",
            "label": "Target Validation",
            "status": "waiting",
        },
        {
            "key": "pipeline_start",
            "label": "Pipeline Start",
            "status": "waiting",
        },
        {
            "key": "scanner_running",
            "label": "Scanner Running",
            "status": "waiting",
        },
        {
            "key": "report_collect",
            "label": "Report Collect",
            "status": "waiting",
        },
        {
            "key": "done",
            "label": "Done",
            "status": "waiting",
        },
    ]


def set_step(job_id: str, key: str, status: str):
    if job_id not in jobs:
        return

    for step in jobs[job_id]["steps"]:
        if step["key"] == key:
            step["status"] = status
            break


def set_job_progress(job_id: str, progress: int, current_step: str):
    if job_id not in jobs:
        return

    jobs[job_id]["progress"] = progress
    jobs[job_id]["current_step"] = current_step


def normalize_target_for_filename(target: str) -> str:
    return (
        target.replace("http://", "")
        .replace("https://", "")
        .replace("/", "_")
        .replace(":", "_")
    )


def collect_latest_reports(target: str, limit: int = 7) -> list[str]:
    reports_dir = "results/reports"

    if not os.path.exists(reports_dir):
        return []

    prefix = normalize_target_for_filename(target)

    files = [
        f
        for f in os.listdir(reports_dir)
        if f.startswith(prefix)
    ]

    files = sorted(
        files,
        key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)),
        reverse=True,
    )

    return files[:limit]


def find_json_reports(report_files: list[str]) -> list[str]:
    return [
        file
        for file in report_files
        if file.lower().endswith(".json")
    ]


def build_summary_from_json_reports(report_files: list[str]) -> dict:
    """
    결과 JSON 파일이 있으면 severity 개수를 요약합니다.
    JSON 구조가 프로젝트마다 다를 수 있으므로 최대한 유연하게 처리합니다.
    """
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    reports_dir = "results/reports"
    json_files = find_json_reports(report_files)

    for filename in json_files:
        path = os.path.join(reports_dir, filename)

        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 가능한 구조 1: {"findings": [...]}
            findings = data.get("findings")

            # 가능한 구조 2: {"alerts": [...]}
            if findings is None:
                findings = data.get("alerts")

            # 가능한 구조 3: 리스트 자체가 findings인 경우
            if findings is None and isinstance(data, list):
                findings = data

            if not isinstance(findings, list):
                continue

            for item in findings:
                severity = (
                    item.get("severity")
                    or item.get("risk")
                    or item.get("riskdesc")
                    or item.get("level")
                    or "unknown"
                )

                severity = str(severity).lower()

                if "critical" in severity:
                    summary["critical"] += 1
                elif "high" in severity:
                    summary["high"] += 1
                elif "medium" in severity:
                    summary["medium"] += 1
                elif "low" in severity:
                    summary["low"] += 1
                elif "info" in severity or "informational" in severity:
                    summary["info"] += 1
                else:
                    summary["unknown"] += 1

        except Exception:
            # JSON 파싱 실패는 전체 API 실패로 처리하지 않음
            continue

    return summary


def build_findings_from_json_reports(report_files: list[str], limit: int = 50) -> list[dict]:
    findings_result = []
    reports_dir = "results/reports"
    json_files = find_json_reports(report_files)

    for filename in json_files:
        path = os.path.join(reports_dir, filename)

        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            findings = data.get("findings")

            if findings is None:
                findings = data.get("alerts")

            if findings is None and isinstance(data, list):
                findings = data

            if not isinstance(findings, list):
                continue

            for item in findings:
                if len(findings_result) >= limit:
                    return findings_result

                findings_result.append(
                    {
                        "name": item.get("name") or item.get("alert") or item.get("title") or "Unknown Finding",
                        "severity": item.get("severity") or item.get("risk") or item.get("riskdesc") or "Unknown",
                        "source": item.get("source") or item.get("scanner") or "Unknown",
                        "owasp_category": item.get("owasp_category") or item.get("owasp") or "-",
                        "description": item.get("description") or item.get("desc") or "",
                    }
                )

        except Exception:
            continue

    return findings_result


@app.post("/scan", response_model=ScanStatus)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    스캔 시작
    - 즉시 job_id 반환
    - 실제 스캔은 백그라운드에서 실행
    """

    # 기본 검증
    if not req.targets:
        return JSONResponse(
            status_code=400,
            content={"error": "targets must not be empty"},
        )

    if req.strength not in ["low", "medium", "high"]:
        return JSONResponse(
            status_code=400,
            content={"error": "strength must be one of: low, medium, high"},
        )

    # 권한 확인을 강제하고 싶으면 아래 주석 해제
    # 지금은 프론트에서만 체크해도 되지만, 백엔드에서도 막는 게 더 안전합니다.
    # if not req.permission_confirmed:
    #     return JSONResponse(
    #         status_code=403,
    #         content={"error": "permission_confirmed is required"},
    #     )

    job_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()

    jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "targets": req.targets,
        "strength": req.strength,
        "started_at": now,
        "finished_at": None,
        "reports": [],
        "progress": 0,
        "current_step": "pending",
        "steps": make_default_steps(),
        "error": None,

        # 지금 당장은 run_pipeline에 직접 반영하지 않더라도
        # 나중에 확장할 수 있도록 저장해 둡니다.
        "permission_confirmed": req.permission_confirmed,
        "scanners": req.scanners.dict(),
    }

    background_tasks.add_task(
        _run_scan,
        job_id,
        req.targets,
        req.strength,
    )

    return jobs[job_id]


@app.get("/scan/{job_id}", response_model=ScanStatus)
async def get_status(job_id: str):
    """스캔 진행 상태 조회"""

    if job_id not in jobs:
        return JSONResponse(
            status_code=404,
            content={"error": "Job not found"},
        )

    return jobs[job_id]


@app.get("/scan/{job_id}/result")
async def get_result(job_id: str):
    """
    스캔 결과 요약 조회
    - reports 목록
    - severity summary
    - findings 일부
    """

    if job_id not in jobs:
        return JSONResponse(
            status_code=404,
            content={"error": "Job not found"},
        )

    job = jobs[job_id]
    reports = job.get("reports", [])

    summary = build_summary_from_json_reports(reports)
    findings = build_findings_from_json_reports(reports)

    return {
        "job_id": job_id,
        "status": job.get("status"),
        "targets": job.get("targets"),
        "strength": job.get("strength"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "reports": reports,
        "summary": summary,
        "findings": findings,
    }


@app.get("/scan/{job_id}/report/{filename}")
async def download_report(job_id: str, filename: str):
    """리포트 파일 다운로드"""

    if job_id not in jobs:
        return JSONResponse(
            status_code=404,
            content={"error": "Job not found"},
        )

    # 경로 조작 방지
    safe_filename = os.path.basename(filename)

    # 해당 job에서 생성된 파일만 다운로드 허용
    if safe_filename not in jobs[job_id].get("reports", []):
        return JSONResponse(
            status_code=403,
            content={"error": "This report file does not belong to the job"},
        )

    path = os.path.join("results/reports", safe_filename)

    if not os.path.exists(path):
        return JSONResponse(
            status_code=404,
            content={"error": "Report not found"},
        )

    return FileResponse(path, filename=safe_filename)


@app.get("/health")
async def health():
    return {"status": "ok"}


async def _run_scan(job_id: str, targets: list[str], strength: str):
    """백그라운드 스캔 실행"""

    jobs[job_id]["status"] = "running"
    set_job_progress(job_id, 5, "scan started")
    set_step(job_id, "target_validation", "running")

    try:
        # Target validation 단계
        for target in targets:
            if not target.startswith("http://") and not target.startswith("https://"):
                raise ValueError(f"Invalid target URL: {target}")

        set_step(job_id, "target_validation", "done")
        set_job_progress(job_id, 15, "pipeline starting")
        set_step(job_id, "pipeline_start", "running")

        # CLI와 동일하게 pipeline 직접 호출
        from sls_scanner.core.pipeline import run_pipeline

        report_files = []

        set_step(job_id, "pipeline_start", "done")
        set_step(job_id, "scanner_running", "running")
        set_job_progress(job_id, 35, "scanner running")

        for idx, target in enumerate(targets):
            # 현재 run_pipeline은 target, strength만 받는 구조로 보임
            # 나중에 scanners 옵션을 반영하려면 pipeline 쪽도 수정해야 함
            run_pipeline(
    			target=target,
    			strength=strength,
    			scanners=jobs[job_id].get("scanners"))

            target_reports = collect_latest_reports(target, limit=7)
            report_files.extend(target_reports)

            # 여러 target일 때 진행률 대략 반영
            partial_progress = 35 + int(((idx + 1) / len(targets)) * 40)
            set_job_progress(job_id, partial_progress, f"scanner finished for {target}")

        set_step(job_id, "scanner_running", "done")
        set_step(job_id, "report_collect", "running")
        set_job_progress(job_id, 85, "collecting reports")

        # 중복 제거
        report_files = list(dict.fromkeys(report_files))

        jobs[job_id]["reports"] = report_files

        set_step(job_id, "report_collect", "done")
        set_step(job_id, "done", "done")

        jobs[job_id]["status"] = "done"
        jobs[job_id]["finished_at"] = datetime.now().isoformat()
        jobs[job_id]["progress"] = 100
        jobs[job_id]["current_step"] = "done"

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["finished_at"] = datetime.now().isoformat()
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["progress"] = 100
        jobs[job_id]["current_step"] = "error"

        # 진행 중이던 step을 error로 표시
        for step in jobs[job_id]["steps"]:
            if step["status"] == "running":
                step["status"] = "error"