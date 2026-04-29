# sls_scanner/scanners/header_scanner.py

"""
HTTP 응답 보안 헤더 점검 모듈.

대상 URL에 HTTP 요청을 보내고, 주요 보안 헤더가 응답에 포함되어 있는지 확인한다.
이 결과는 OWASP Top 10 중 A05 Security Misconfiguration 점검 항목으로 활용된다.
"""

from typing import Any

import requests


REQUEST_TIMEOUT_SECONDS = 5

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
]


def _find_missing_headers(headers: requests.structures.CaseInsensitiveDict) -> list[str]:
    """
    응답 헤더에서 주요 보안 헤더 누락 여부를 확인한다.

    Args:
        headers (CaseInsensitiveDict): requests 응답 헤더 객체

    Returns:
        list[str]: 누락된 보안 헤더 이름 목록
    """
    return [
        header_name
        for header_name in SECURITY_HEADERS
        if header_name not in headers
    ]


def run_header_scan(target: str) -> dict[str, Any]:
    """
    대상 URL의 HTTP 응답 보안 헤더를 점검한다.

    Args:
        target (str): 점검 대상 URL

    Returns:
        dict[str, Any]: 보안 헤더 점검 원시 결과
    """
    print(f"[INFO] Header scan started: {target}")

    try:
        response = requests.get(target, timeout=REQUEST_TIMEOUT_SECONDS)
        missing_headers = _find_missing_headers(response.headers)

        print(f"[INFO] Header scan completed: {len(missing_headers)} missing")

        return {
            "target": target,
            "status_code": response.status_code,
            "checked_headers": SECURITY_HEADERS,
            "missing_headers": missing_headers,
        }

    except requests.RequestException as e:
        print(f"[ERROR] Header scan failed: {e}")

        return {
            "target": target,
            "status_code": None,
            "checked_headers": SECURITY_HEADERS,
            "missing_headers": [],
            "error": str(e),
        }