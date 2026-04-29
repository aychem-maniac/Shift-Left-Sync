# sls_scanner/evaluators/risk_evaluator.py

"""
취약점 및 포트 결과에 프로젝트 기준 위험도 정보를 추가하는 모듈.

이 모듈은 각 스캐너의 결과를 실제로 검증하지는 않고,
정규화된 severity 또는 포트 번호를 기준으로 risk_level, risk_score,
risk_reason, is_critical 등의 평가 필드를 추가한다.
"""

from typing import Any


SEVERITY_SCORE_MAP = {
    "Critical": 10,
    "High": 8,
    "Medium": 5,
    "Low": 3,
    "Info": 0,
    "Unknown": 0,
}

SEVERITY_NORMALIZATION_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

RISKY_PORTS = {
    21: {
        "risk_level": "High",
        "risk_score": 8,
        "risk_reason": "FTP service is exposed.",
    },
    22: {
        "risk_level": "Medium",
        "risk_score": 5,
        "risk_reason": "SSH management service is exposed.",
    },
    23: {
        "risk_level": "Critical",
        "risk_score": 10,
        "risk_reason": "Telnet service is exposed and may transmit credentials in plaintext.",
    },
    3306: {
        "risk_level": "High",
        "risk_score": 8,
        "risk_reason": "MySQL database service is exposed.",
    },
    5432: {
        "risk_level": "High",
        "risk_score": 8,
        "risk_reason": "PostgreSQL database service is exposed.",
    },
    6379: {
        "risk_level": "Critical",
        "risk_score": 10,
        "risk_reason": "Redis service is exposed.",
    },
    27017: {
        "risk_level": "Critical",
        "risk_score": 10,
        "risk_reason": "MongoDB service is exposed.",
    },
}

COMMON_WEB_PORTS = {80, 443}


def _safe_int(value: Any, default: int = 0) -> int:
    """
    포트 번호처럼 정수 변환이 필요한 값을 안전하게 int로 변환한다.

    Args:
        value (Any): 정수로 변환할 값
        default (int): 변환 실패 시 반환할 기본값

    Returns:
        int: 변환된 정수 값
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_severity(severity: str) -> str:
    """
    도구별 severity 표현을 프로젝트 기준 등급으로 통일한다.

    Args:
        severity (str): 원본 severity 값

    Returns:
        str: Critical, High, Medium, Low, Info, Unknown 중 하나
    """
    if not severity:
        return "Unknown"

    normalized = str(severity).strip().lower()

    return SEVERITY_NORMALIZATION_MAP.get(normalized, "Unknown")


def evaluate_risk(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    정규화된 취약점 findings에 프로젝트 기준 위험도 정보를 추가한다.

    Args:
        findings (list[dict[str, Any]]): 정규화된 취약점 목록

    Returns:
        list[dict[str, Any]]: 위험도 필드가 추가된 취약점 목록
    """
    print("[INFO] Risk evaluation started")

    evaluated = []

    for finding in findings:
        evaluated_finding = finding.copy()

        risk_level = normalize_severity(evaluated_finding.get("severity", "Unknown"))
        risk_score = SEVERITY_SCORE_MAP.get(risk_level, 0)

        evaluated_finding["risk_level"] = risk_level
        evaluated_finding["risk_score"] = risk_score
        evaluated_finding["is_critical"] = risk_level == "Critical"

        evaluated.append(evaluated_finding)

    print(f"[INFO] Risk evaluation completed: {len(evaluated)} finding(s)")

    return evaluated


def _evaluate_single_port(port_number: int, state: str) -> dict[str, Any]:
    """
    단일 포트의 상태와 번호를 기준으로 위험도를 평가한다.

    Args:
        port_number (int): 포트 번호
        state (str): Nmap 포트 상태

    Returns:
        dict[str, Any]: risk_level, risk_score, risk_reason
    """
    if state != "open":
        return {
            "risk_level": "Info",
            "risk_score": 0,
            "risk_reason": "Port is not confirmed as open.",
        }

    if port_number in RISKY_PORTS:
        return RISKY_PORTS[port_number]

    if port_number in COMMON_WEB_PORTS:
        return {
            "risk_level": "Low",
            "risk_score": 3,
            "risk_reason": "Common web service port is open.",
        }

    return {
        "risk_level": "Medium",
        "risk_score": 5,
        "risk_reason": "Unknown or uncommon open service detected.",
    }


def evaluate_port_risk(port_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    정규화된 Nmap 포트 결과에 프로젝트 기준 위험도를 추가한다.

    Args:
        port_results (list[dict[str, Any]]): 정규화된 포트 결과 목록

    Returns:
        list[dict[str, Any]]: 위험도 필드가 추가된 포트 결과 목록
    """
    print("[INFO] Port risk evaluation started")

    evaluated_ports = []

    for port in port_results:
        evaluated_port = port.copy()

        port_number = _safe_int(evaluated_port.get("port", 0))
        state = str(evaluated_port.get("state", "") or "").lower()

        risk_info = _evaluate_single_port(port_number, state)

        evaluated_port["risk_level"] = risk_info["risk_level"]
        evaluated_port["risk_score"] = risk_info["risk_score"]
        evaluated_port["risk_reason"] = risk_info["risk_reason"]
        evaluated_port["is_critical"] = risk_info["risk_level"] == "Critical"

        evaluated_ports.append(evaluated_port)

    print(f"[INFO] Port risk evaluation completed: {len(evaluated_ports)} port(s)")

    return evaluated_ports