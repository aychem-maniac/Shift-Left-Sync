# sls_scanner/evaluators/risk_evaluator.py

def evaluate_risk(findings: list[dict]) -> list[dict]:
    print("[INFO] Risk evaluation started")

    severity_score_map = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1,
        "Informational": 1,
        "Unknown": 0
    }

    evaluated_findings = []

    for finding in findings:
        severity = finding.get("severity", "Unknown")

        if severity == "Informational":
            severity = "Info"

        risk_score = severity_score_map.get(severity, 0)

        evaluated_finding = {
            **finding,
            "severity": severity,
            "risk_score": risk_score,
            "is_critical": risk_score >= 4
        }

        evaluated_findings.append(evaluated_finding)

    evaluated_findings.sort(
        key=lambda item: item.get("risk_score", 0),
        reverse=True
    )

    print(f"[INFO] Risk evaluation completed: {len(evaluated_findings)} finding(s)")

    return evaluated_findings