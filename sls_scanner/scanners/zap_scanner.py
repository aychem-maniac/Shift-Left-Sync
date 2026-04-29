# sls_scanner/scanners/zap_scanner.py

"""
OWASP ZAP API를 이용한 웹 취약점 스캔 모듈.

이 모듈은 로컬에서 실행 중인 ZAP 프록시에 연결하여
대상 URL에 대해 Spider, Active Scan, Passive Scan을 수행하고
탐지된 Alert 원시 결과를 반환한다.
"""

import time
from typing import Any

from zapv2 import ZAPv2


ZAP_ADDRESS = "127.0.0.1"
ZAP_PORT = "8080"
ZAP_API_KEY = ""

SPIDER_POLL_INTERVAL = 2
ACTIVE_SCAN_POLL_INTERVAL = 5
PASSIVE_SCAN_POLL_INTERVAL = 2

SPIDER_TIMEOUT_SECONDS = 300
ACTIVE_SCAN_TIMEOUT_SECONDS = 900
PASSIVE_SCAN_TIMEOUT_SECONDS = 300


def _create_zap_client() -> ZAPv2:
    """
    로컬에서 실행 중인 OWASP ZAP API 클라이언트를 생성한다.

    Returns:
        ZAPv2: ZAP API 클라이언트 객체
    """
    return ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
            "https": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
        },
    )


def _wait_for_scan_completion(
    *,
    get_status,
    scan_name: str,
    poll_interval: int,
    timeout_seconds: int,
) -> bool:
    """
    ZAP Spider 또는 Active Scan이 완료될 때까지 진행률을 주기적으로 확인한다.

    Args:
        get_status: 현재 진행률을 반환하는 함수
        scan_name (str): 로그에 표시할 스캔 이름
        poll_interval (int): 진행률 확인 주기(초)
        timeout_seconds (int): 최대 대기 시간(초)

    Returns:
        bool: 정상 완료 시 True, 타임아웃 또는 오류 시 False
    """
    start_time = time.time()

    while True:
        try:
            progress = int(get_status())
        except Exception as e:
            print(f"[WARN] ZAP {scan_name} status check failed: {e}")
            return False

        print(f"[INFO] ZAP {scan_name} progress: {progress}%")

        if progress >= 100:
            return True

        if time.time() - start_time > timeout_seconds:
            print(f"[WARN] ZAP {scan_name} timeout after {timeout_seconds}s")
            return False

        time.sleep(poll_interval)


def _wait_for_passive_scan(zap: ZAPv2) -> bool:
    """
    Passive Scan 큐에 남아 있는 레코드가 모두 처리될 때까지 대기한다.

    Args:
        zap (ZAPv2): ZAP API 클라이언트 객체

    Returns:
        bool: 정상 완료 시 True, 타임아웃 또는 오류 시 False
    """
    start_time = time.time()

    while True:
        try:
            remaining = int(zap.pscan.records_to_scan)
        except Exception as e:
            print(f"[WARN] ZAP passive scan status check failed: {e}")
            return False

        print(f"[INFO] ZAP passive records remaining: {remaining}")

        if remaining <= 0:
            return True

        if time.time() - start_time > PASSIVE_SCAN_TIMEOUT_SECONDS:
            print(f"[WARN] ZAP passive scan timeout after {PASSIVE_SCAN_TIMEOUT_SECONDS}s")
            return False

        time.sleep(PASSIVE_SCAN_POLL_INTERVAL)


def run_zap_scan(target: str) -> dict[str, Any]:
    """
    OWASP ZAP을 사용하여 대상 URL을 Spider, Active Scan, Passive Scan 순서로 점검한다.

    ZAP은 Python 패키지만 설치한다고 동작하는 것이 아니라,
    별도의 OWASP ZAP 프로그램이 로컬에서 실행 중이어야 한다.

    Args:
        target (str): 점검 대상 URL

    Returns:
        dict[str, Any]: ZAP 원시 Alert 결과
    """
    print(f"[INFO] ZAP scan started: {target}")

    try:
        zap = _create_zap_client()

        print(f"[INFO] Connected to ZAP version: {zap.core.version}")

        # ZAP이 대상 URL을 사이트 트리에 등록할 수 있도록 먼저 접근한다.
        zap.urlopen(target)
        time.sleep(2)

        print("[INFO] ZAP spider started")
        spider_scan_id = zap.spider.scan(target)

        spider_completed = _wait_for_scan_completion(
            get_status=lambda: zap.spider.status(spider_scan_id),
            scan_name="spider",
            poll_interval=SPIDER_POLL_INTERVAL,
            timeout_seconds=SPIDER_TIMEOUT_SECONDS,
        )

        if spider_completed:
            print("[INFO] ZAP spider completed")
        else:
            print("[WARN] ZAP spider did not complete normally")

        print("[INFO] ZAP active scan started")
        active_scan_id = zap.ascan.scan(target)

        active_completed = _wait_for_scan_completion(
            get_status=lambda: zap.ascan.status(active_scan_id),
            scan_name="active scan",
            poll_interval=ACTIVE_SCAN_POLL_INTERVAL,
            timeout_seconds=ACTIVE_SCAN_TIMEOUT_SECONDS,
        )

        if active_completed:
            print("[INFO] ZAP active scan completed")
        else:
            print("[WARN] ZAP active scan did not complete normally")

        print("[INFO] ZAP passive scan waiting")
        passive_completed = _wait_for_passive_scan(zap)

        if passive_completed:
            print("[INFO] ZAP passive scan completed")
        else:
            print("[WARN] ZAP passive scan did not complete normally")

        alerts = zap.core.alerts(baseurl=target)

        print(f"[INFO] ZAP scan completed: {len(alerts)} alert(s) found")

        return {
            "target": target,
            "raw_alerts": alerts,
        }

    except Exception as e:
        print(f"[ERROR] ZAP scan failed: {e}")

        return {
            "target": target,
            "raw_alerts": [],
        }