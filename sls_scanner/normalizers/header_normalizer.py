# sls_scanner/normalizers/header_normalizer.py

"""
HTTP 보안 헤더 점검 결과를 프로젝트 공통 취약점 형식으로 변환하는 모듈.

Header Scanner는 누락된 보안 헤더 목록을 반환한다.
이 모듈은 각 누락 헤더를 개별 finding으로 변환하여 리포트와 위험도 평가에 사용할 수 있게 한다.
"""

from typing import Any

from sls_scanner.normalizers.owasp_normalizer import enrich_findings


HEADER_SEVERITY_MAP = {
    "Content-Security-Policy": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Frame-Options": "Low",
    "X-Content-Type-Options": "Low",
}

DEFAULT_HEADER_SEVERITY = "Low"
SECURE_HEADERS_REFERENCE = "https://owasp.org/www-project-secure-headers/"


def _get_header_severity(header_name: str) -> str:
    """
    누락된 보안 헤더 이름에 따라 severity를 반환한다.

    Args:
        header_name (str): 누락된 보안 헤더 이름

    Returns:
        str: 헤더 누락 위험도
    """
    return HEADER_SEVERITY_MAP.get(header_name, DEFAULT_HEADER_SEVERITY)


def _build_header_finding(
    *,
    index: int,
    target: str,
    header_name: str,
) -> dict[str, Any]:
    """
    누락된 보안 헤더 1개를 프로젝트 공통 finding 형식으로 변환한다.

    Args:
        index (int): finding ID 생성을 위한 순번
        target (str): 점검 대상 URL
        header_name (str): 누락된 보안 헤더 이름

    Returns:
        dict[str, Any]: 정규화된 보안 헤더 finding
    """
    return {
        "id": f"HEADER-{index:03d}",
        "source": "header_scan",
        "name": f"Missing Security Header: {header_name}",
        "severity": _get_header_severity(header_name),
        "confidence": "High",
        "url": target,
        "description": f"{header_name} header is not set in the HTTP response.",
        "evidence": f"Missing response header: {header_name}",
        "solution": f"Configure the web server or application to set the {header_name} header.",
        "reference": SECURE_HEADERS_REFERENCE,
    }


def normalize_header_result(raw_header_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Header Scan 결과를 프로젝트 공통 findings 형식으로 변환한다.

    Args:
        raw_header_result (dict[str, Any]): header_scanner.run_header_scan()에서 반환한 원시 결과

    Returns:
        list[dict[str, Any]]: 정규화 및 OWASP 정보가 보강된 finding 목록
    """
    print("[INFO] Header normalization started")

    try:
        target = raw_header_result.get("target") or ""
        missing_headers = raw_header_result.get("missing_headers") or []

        findings = [
            _build_header_finding(
                index=index,
                target=target,
                header_name=header_name,
            )
            for index, header_name in enumerate(missing_headers, start=1)
        ]

        findings = enrich_findings(findings)

        print(f"[INFO] Header normalization completed: {len(findings)} finding(s)")
        return findings

    except Exception as e:
        print(f"[ERROR] Header normalization failed: {e}")
        return []