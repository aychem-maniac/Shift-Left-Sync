"""
Scanner Service

FastAPI(api.py)가 스캔 파이프라인 구현에 직접 의존하지 않도록 분리한 서비스 계층입니다.

역할:
- api.py는 job_id, 인증, SSE, 응답만 담당
- scanner_service는 실제 스캔 실행 진입점 담당
- core/pipeline.py는 기존 파이프라인 로직 유지
"""

from typing import Callable, Optional

from sls_scanner.core.pipeline import (
    run_pipeline_with_cb,
    request_cancel,
    ScanCancelledError,
)


ProgressCallback = Optional[Callable[[str, int], None]]


def run_scan_job(
    *,
    job_id: str,
    target: str,
    strength: str = "medium",
    progress_cb: ProgressCallback = None,
) -> None:
    """
    단일 스캔 job 실행 진입점.

    현재는 기존 run_pipeline_with_cb를 그대로 호출한다.
    추후 Celery/RQ/worker 구조로 바꿀 때 api.py가 아니라 이 함수만 교체하면 된다.
    """
    run_pipeline_with_cb(
        target=target,
        strength=strength,
        cb=progress_cb,
        job_id=job_id,
    )


def cancel_scan_job(job_id: str) -> None:
    """
    실행 중인 스캔 job 취소 요청.
    """
    request_cancel(job_id)
