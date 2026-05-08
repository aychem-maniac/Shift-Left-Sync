# sls_scanner/evaluators/risk_evaluator.py

"""
취약점 및 포트 결과에 프로젝트 기준 위험도 정보를 추가하는 모듈.

이 모듈은 각 스캐너의 결과를 실제로 검증하지는 않고,
정규화된 severity 또는 포트 번호를 기준으로 risk_level, risk_score,
risk_reason, cvss_rule, is_critical 등의 평가 필드를 추가한다.
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

CVSS_LEVEL_RULES = {
    "Critical": "CVSS 9.0 ~ 10.0",
    "High": "CVSS 7.0 ~ 8.9",
    "Medium": "CVSS 4.0 ~ 6.9",
    "Low": "CVSS 0.1 ~ 3.9",
    "Info": "CVSS 0.0",
    "Unknown": "CVSS score is not available.",
}

RISK_REASON_MAP = {
    "Critical": "CVSS 기준상 즉시 조치가 필요한 매우 높은 위험도의 취약점입니다.",
    "High": "CVSS 기준상 우선 조치가 필요한 높은 위험도의 취약점입니다.",
    "Medium": "일정 조건에서 공격에 악용될 수 있는 중간 수준의 취약점입니다.",
    "Low": "직접적인 위험은 낮지만 보안 강화를 위해 개선이 필요한 항목입니다.",
    "Info": "직접적인 취약점이라기보다 참고용 보안 정보입니다.",
    "Unknown": "원본 스캐너 결과에서 위험도 판단에 필요한 severity 정보가 부족합니다.",
}

RISKY_PORTS = {
    21: {
        "risk_level": "High",
        "risk_score": 8,
        "risk_reason": "FTP service is exposed.",
        "cvss_rule": CVSS_LEVEL_RULES["High"],
    },
    22: {
        "risk_level": "Medium",
        "risk_score": 5,
        "risk_reason": "SSH management service is exposed.",
        "cvss_rule": CVSS_LEVEL_RULES["Medium"],
    },
    23: {
        "risk_level": "Critical",
        "risk_score": 10,
        "risk_reason": "Telnet service is exposed and may transmit credentials in plaintext.",
        "cvss_rule": CVSS_LEVEL_RULES["Critical"],
    },
    3306: {
        "risk_level": "High",
        "risk_score": 8,
        "risk_reason": "MySQL database service is exposed.",
        "cvss_rule": CVSS_LEVEL_RULES["High"],
    },
    5432: {
        "risk_level": "High",
        "risk_score": 8,
        "risk_reason": "PostgreSQL database service is exposed.",
        "cvss_rule": CVSS_LEVEL_RULES["High"],
    },
    6379: {
        "risk_level": "Critical",
        "risk_score": 10,
        "risk_reason": "Redis service is exposed.",
        "cvss_rule": CVSS_LEVEL_RULES["Critical"],
    },
    27017: {
        "risk_level": "Critical",
        "risk_score": 10,
        "risk_reason": "MongoDB service is exposed.",
        "cvss_rule": CVSS_LEVEL_RULES["Critical"],
    },
}

COMMON_WEB_PORTS = {80, 443}


def _safe_int(value: Any, default: int = 0) -> int:
    """
    포트 번호처럼 정수 변환이 필요한 값을 안전하게 int로 변환한다.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_severity(severity: str) -> str:
    """
    도구별 severity 표현을 프로젝트 기준 등급으로 통일한다.
    """
    if not severity:
        return "Unknown"

    normalized = str(severity).strip().lower()

    return SEVERITY_NORMALIZATION_MAP.get(normalized, "Unknown")


def evaluate_risk(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    정규화된 취약점 findings에 프로젝트 기준 위험도 정보를 추가한다.

    추가되는 필드:
    - risk_level: Critical, High, Medium, Low, Info, Unknown
    - risk_score: 프로젝트 내부 위험도 점수
    - cvss_rule: CVSS 등급 기준 설명
    - risk_reason: 위험도 판단 근거 설명
    - is_critical: High 이상 여부
    """
    print("[INFO] Risk evaluation started")

    evaluated = []

    for finding in findings:
        evaluated_finding = finding.copy()

        risk_level = normalize_severity(evaluated_finding.get("severity", "Unknown"))
        risk_score = SEVERITY_SCORE_MAP.get(risk_level, 0)

        evaluated_finding["risk_level"] = risk_level
        evaluated_finding["risk_score"] = risk_score
        evaluated_finding["cvss_rule"] = CVSS_LEVEL_RULES.get(
            risk_level,
            CVSS_LEVEL_RULES["Unknown"],
        )
        evaluated_finding["risk_reason"] = RISK_REASON_MAP.get(
            risk_level,
            RISK_REASON_MAP["Unknown"],
        )
        evaluated_finding["is_critical"] = risk_level in {"Critical", "High"}

        evaluated.append(evaluated_finding)

    print(f"[INFO] Risk evaluation completed: {len(evaluated)} finding(s)")

    return evaluated


def _evaluate_single_port(port_number: int, state: str) -> dict[str, Any]:
    """
    단일 포트의 상태와 번호를 기준으로 위험도를 평가한다.
    """
    if state != "open":
        return {
            "risk_level": "Info",
            "risk_score": 0,
            "risk_reason": "Port is not confirmed as open.",
            "cvss_rule": CVSS_LEVEL_RULES["Info"],
        }

    if port_number in RISKY_PORTS:
        return RISKY_PORTS[port_number]

    if port_number in COMMON_WEB_PORTS:
        return {
            "risk_level": "Low",
            "risk_score": 3,
            "risk_reason": "Common web service port is open.",
            "cvss_rule": CVSS_LEVEL_RULES["Low"],
        }

    return {
        "risk_level": "Medium",
        "risk_score": 5,
        "risk_reason": "Unknown or uncommon open service detected.",
        "cvss_rule": CVSS_LEVEL_RULES["Medium"],
    }


def evaluate_port_risk(port_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    정규화된 Nmap 포트 결과에 프로젝트 기준 위험도를 추가한다.

    추가되는 필드:
    - risk_level
    - risk_score
    - risk_reason
    - cvss_rule
    - is_critical
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
        evaluated_port["cvss_rule"] = risk_info["cvss_rule"]
        evaluated_port["is_critical"] = risk_info["risk_level"] in {"Critical", "High"}

        evaluated_ports.append(evaluated_port)

    print(f"[INFO] Port risk evaluation completed: {len(evaluated_ports)} port(s)")

    return evaluated_ports