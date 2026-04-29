# sls_scanner/normalizers/zap_normalizer.py

"""
OWASP ZAP Alert 결과를 프로젝트 공통 취약점 형식으로 변환하는 모듈.

ZAP은 alert마다 risk, confidence, url, description, solution 등의 필드를 제공한다.
이 모듈은 해당 원시 Alert를 리포트와 위험도 평가에서 사용할 수 있는 표준 finding 구조로 정규화한다.
"""

from typing import Any

from sls_scanner.normalizers.owasp_normalizer import enrich_findings


def _get_alert_name(alert: dict[str, Any]) -> str:
    """
    ZAP Alert에서 취약점 이름을 추출한다.

    ZAP 결과는 버전이나 API 응답 형태에 따라 name 또는 alert 필드를 사용할 수 있으므로,
    두 필드를 순서대로 확인한다.

    Args:
        alert (dict[str, Any]): ZAP Alert 원시 데이터

    Returns:
        str: 취약점 이름
    """
    return alert.get("name") or alert.get("alert") or "Unknown ZAP Alert"


def _normalize_single_alert(alert: dict[str, Any], index: int) -> dict[str, Any]:
    """
    ZAP Alert 1개를 프로젝트 공통 finding 형식으로 변환한다.

    Args:
        alert (dict[str, Any]): ZAP Alert 원시 데이터
        index (int): finding ID 생성을 위한 순번

    Returns:
        dict[str, Any]: 정규화된 finding 데이터
    """
    return {
        "id": f"ZAP-{index:03d}",
        "source": "zap",
        "name": _get_alert_name(alert),
        "severity": alert.get("risk") or "Unknown",
        "confidence": alert.get("confidence") or "Unknown",
        "url": alert.get("url") or "",
        "description": alert.get("description") or "",
        "solution": alert.get("solution") or "",
        "reference": alert.get("reference") or "",
    }


def normalize_zap_result(raw_zap_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    ZAP 원시 Alert 결과를 프로젝트 공통 취약점 목록으로 변환한다.

    Args:
        raw_zap_result (dict[str, Any]): zap_scanner.run_zap_scan()에서 반환한 원시 결과

    Returns:
        list[dict[str, Any]]: 정규화 및 OWASP 정보가 보강된 취약점 목록
    """
    print("[INFO] ZAP normalization started")

    try:
        raw_alerts = raw_zap_result.get("raw_alerts", [])

        findings = [
            _normalize_single_alert(alert, index)
            for index, alert in enumerate(raw_alerts, start=1)
        ]

        findings = enrich_findings(findings)

        print(f"[INFO] ZAP normalization completed: {len(findings)} finding(s) found")
        return findings

    except Exception as e:
        print(f"[ERROR] ZAP normalization failed: {e}")
        return []