# sls_scanner/normalizers/sqlmap_normalizer.py

"""
SQLMap 실행 결과를 프로젝트 공통 취약점 형식으로 변환하는 모듈.

SQLMap scanner는 SQL Injection 탐지 여부와 실행 로그를 반환한다.
이 모듈은 해당 결과를 리포트와 위험도 평가에서 사용할 수 있는 finding 구조로 정규화한다.
"""

from typing import Any

from sls_scanner.normalizers.owasp_normalizer import enrich_findings


SQLMAP_EVIDENCE_KEYWORDS = [
    "is vulnerable",
    "injectable",
    "sql injection",
    "parameter",
    "back-end dbms",
    "current user",
    "current database",
]

MAX_EVIDENCE_LINES = 10
MAX_FALLBACK_ERROR_LENGTH = 500


def _extract_sqlmap_evidence(stdout: str) -> str:
    """
    SQLMap 출력 로그에서 리포트에 넣을 핵심 근거 문장만 추출한다.

    Args:
        stdout (str): SQLMap 표준 출력 로그

    Returns:
        str: 핵심 근거 문장 모음
    """
    evidence_lines = []

    for line in stdout.splitlines():
        lower_line = line.lower()

        if any(keyword in lower_line for keyword in SQLMAP_EVIDENCE_KEYWORDS):
            evidence_lines.append(line.strip())

        if len(evidence_lines) >= MAX_EVIDENCE_LINES:
            break

    return "\n".join(evidence_lines)


def _build_vulnerable_finding(target: str, evidence: str) -> dict[str, Any]:
    """
    SQL Injection이 탐지된 경우의 finding을 생성한다.

    Args:
        target (str): 점검 대상 URL
        evidence (str): SQLMap 로그에서 추출한 탐지 근거

    Returns:
        dict[str, Any]: 취약점 finding
    """
    return {
        "id": "SQLMAP-001",
        "source": "sqlmap",
        "name": "SQL Injection Vulnerability Detected",
        "severity": "High",
        "confidence": "High",
        "url": target,
        "description": "SQLMap detected a possible SQL Injection vulnerability.",
        "evidence": evidence,
        "solution": "Use parameterized queries, input validation, and proper ORM/query binding.",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
    }


def _build_info_finding(target: str, evidence: str) -> dict[str, Any]:
    """
    SQL Injection이 탐지되지 않은 경우의 정보성 finding을 생성한다.

    Args:
        target (str): 점검 대상 URL
        evidence (str): SQLMap 로그 또는 오류 메시지 요약

    Returns:
        dict[str, Any]: 정보성 finding
    """
    return {
        "id": "SQLMAP-INFO-001",
        "source": "sqlmap",
        "name": "SQL Injection Not Detected",
        "severity": "Info",
        "confidence": "Medium",
        "url": target,
        "description": "SQLMap did not detect SQL Injection with the current scan options.",
        "evidence": evidence,
        "solution": "No immediate SQL Injection issue was detected. Consider deeper testing if needed.",
        "reference": "https://sqlmap.org/",
    }


def normalize_sqlmap_result(raw_sqlmap_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    SQLMap 실행 결과를 프로젝트 공통 findings 형식으로 변환한다.

    Args:
        raw_sqlmap_result (dict[str, Any]): sqlmap_scanner.run_sqlmap_scan()에서 반환한 실행 결과

    Returns:
        list[dict[str, Any]]: 정규화 및 OWASP 정보가 보강된 finding 목록
    """
    print("[INFO] SQLMap normalization started")

    try:
        is_vulnerable = raw_sqlmap_result.get("is_vulnerable", False)
        target = raw_sqlmap_result.get("target") or ""
        stdout = raw_sqlmap_result.get("stdout") or ""
        stderr = raw_sqlmap_result.get("stderr") or ""

        evidence = _extract_sqlmap_evidence(stdout)

        if is_vulnerable:
            findings = [
                _build_vulnerable_finding(
                    target=target,
                    evidence=evidence,
                )
            ]
        else:
            fallback_evidence = evidence or stderr[:MAX_FALLBACK_ERROR_LENGTH]
            findings = [
                _build_info_finding(
                    target=target,
                    evidence=fallback_evidence,
                )
            ]

        findings = enrich_findings(findings)

        print(f"[INFO] SQLMap normalization completed: {len(findings)} finding(s)")
        return findings

    except Exception as e:
        print(f"[ERROR] SQLMap normalization failed: {e}")
        return []