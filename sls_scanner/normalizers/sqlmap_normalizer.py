# sls_scanner/normalizers/sqlmap_normalizer.py

def normalize_sqlmap_result(raw_sqlmap_result: dict) -> list[dict]:
    """
    SQLMap 실행 결과를 프로젝트 공통 findings 형식으로 변환한다.
    """

    print("[INFO] SQLMap normalization started")

    findings = []

    try:
        is_vulnerable = raw_sqlmap_result.get("is_vulnerable", False)
        target = raw_sqlmap_result.get("target", "")
        stdout = raw_sqlmap_result.get("stdout", "")
        stderr = raw_sqlmap_result.get("stderr", "")

        if is_vulnerable:
            findings.append({
                "id": "SQLMAP-001",
                "source": "sqlmap",
                "name": "SQL Injection Vulnerability Detected",
                "severity": "High",
                "confidence": "High",
                "url": target,
                "description": "SQLMap detected a possible SQL Injection vulnerability.",
                "evidence": _extract_sqlmap_evidence(stdout),
                "solution": "Use parameterized queries, input validation, and proper ORM/query binding.",
                "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
            })
        else:
            findings.append({
                "id": "SQLMAP-INFO-001",
                "source": "sqlmap",
                "name": "SQL Injection Not Detected",
                "severity": "Info",
                "confidence": "Medium",
                "url": target,
                "description": "SQLMap did not detect SQL Injection with the current scan options.",
                "evidence": _extract_sqlmap_evidence(stdout) or stderr[:500],
                "solution": "No immediate SQL Injection issue was detected. Consider deeper testing if needed.",
                "reference": "https://sqlmap.org/"
            })

        print(f"[INFO] SQLMap normalization completed: {len(findings)} finding(s)")
        return findings

    except Exception as e:
        print(f"[ERROR] SQLMap normalization failed: {e}")
        return []


def _extract_sqlmap_evidence(stdout: str) -> str:
    """
    SQLMap 출력에서 리포트에 넣을 핵심 근거 문장만 추출한다.
    """

    keywords = [
        "is vulnerable",
        "injectable",
        "sql injection",
        "parameter",
        "back-end DBMS",
        "current user",
        "current database"
    ]

    evidence_lines = []

    for line in stdout.splitlines():
        lower_line = line.lower()

        if any(keyword in lower_line for keyword in keywords):
            evidence_lines.append(line.strip())

        if len(evidence_lines) >= 10:
            break

    return "\n".join(evidence_lines)