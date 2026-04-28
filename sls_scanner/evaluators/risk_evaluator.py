# sls_scanner/evaluators/risk_evaluator.py

SEVERITY_SCORE_MAP = {
    "Critical": 10,
    "High": 8,
    "Medium": 5,
    "Low": 3,
    "Info": 0,
    "Informational": 0,
    "Unknown": 0,
}


def evaluate_risk(findings: list[dict]) -> list[dict]:
    """
    정규화된 취약점 findings에 프로젝트 기준 위험도 정보를 추가한다.
    """

    print("[INFO] Risk evaluation started")

    evaluated = []

    for finding in findings:
        severity = finding.get("severity", "Unknown")

        risk_level = normalize_severity(severity)
        risk_score = SEVERITY_SCORE_MAP.get(risk_level, 0)

        finding["risk_level"] = risk_level
        finding["risk_score"] = risk_score
        finding["is_critical"] = risk_level == "Critical"

        evaluated.append(finding)

    print(f"[INFO] Risk evaluation completed: {len(evaluated)} finding(s)")

    return evaluated


def normalize_severity(severity: str) -> str:
    """
    도구별 severity 표현을 프로젝트 기준 등급으로 통일한다.
    """

    if not severity:
        return "Unknown"

    severity = severity.strip().lower()

    if severity == "critical":
        return "Critical"

    if severity == "high":
        return "High"

    if severity == "medium":
        return "Medium"

    if severity == "low":
        return "Low"

    if severity in ["info", "informational"]:
        return "Info"

    return "Unknown"

RISKY_PORTS = {
    21: ("High", 8, "FTP service is exposed."),
    22: ("Medium", 5, "SSH management service is exposed."),
    23: ("Critical", 10, "Telnet service is exposed and may transmit credentials in plaintext."),
    3306: ("High", 8, "MySQL database service is exposed."),
    5432: ("High", 8, "PostgreSQL database service is exposed."),
    6379: ("Critical", 10, "Redis service is exposed."),
    27017: ("Critical", 10, "MongoDB service is exposed."),
}


def evaluate_port_risk(port_results: list[dict]) -> list[dict]:
    """
    정규화된 Nmap 포트 결과에 프로젝트 기준 위험도를 추가한다.
    """

    print("[INFO] Port risk evaluation started")

    evaluated_ports = []

    for port in port_results:
        port_number = int(port.get("port", 0))
        state = str(port.get("state", "")).lower()

        if state != "open":
            risk_level = "Info"
            risk_score = 0
            risk_reason = "Port is not confirmed as open."
        elif port_number in RISKY_PORTS:
            risk_level, risk_score, risk_reason = RISKY_PORTS[port_number]
        elif port_number in [80, 443]:
            risk_level = "Low"
            risk_score = 3
            risk_reason = "Common web service port is open."
        else:
            risk_level = "Medium"
            risk_score = 5
            risk_reason = "Unknown or uncommon open service detected."

        port["risk_level"] = risk_level
        port["risk_score"] = risk_score
        port["risk_reason"] = risk_reason
        port["is_critical"] = risk_level == "Critical"

        evaluated_ports.append(port)

    print(f"[INFO] Port risk evaluation completed: {len(evaluated_ports)} port(s)")

    return evaluated_ports