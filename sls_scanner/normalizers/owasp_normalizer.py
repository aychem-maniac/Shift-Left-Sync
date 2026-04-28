# sls_scanner/normalizers/owasp_normalizer.py

OWASP_TOP10_2021 = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery",
}


def map_to_owasp_top10(finding: dict) -> str:
    source = str(finding.get("source", "")).lower()
    name = str(finding.get("name", "")).lower()
    description = str(finding.get("description", "")).lower()
    reference = str(finding.get("reference", "")).lower()

    text = f"{source} {name} {description} {reference}"

    # =====================================================
    # 0. 명확한 정보성 항목은 OWASP 매핑하지 않음
    # =====================================================
    if any(k in name for k in [
        "modern web application",
        "user agent 퍼저",
        "user agent fuzzer",
    ]):
        return "Unmapped"

    # =====================================================
    # 1. 명확한 보안 설정/헤더 누락 계열은 A05 우선
    # =====================================================
    if any(k in name for k in [
        "content security policy",
        "csp header not set",
        "missing anti-clickjacking header",
        "x-content-type-options header missing",
        "server leaks version information",
        "directory browsing",
        "디렉터리 탐색",
        "missing security header",
        "timestamp disclosure",
        "application error disclosure",
    ]):
        return OWASP_TOP10_2021["A05"]

    # =====================================================
    # 2. SRI는 무결성 검증 실패 계열
    # =====================================================
    if any(k in name for k in [
        "sub resource integrity",
        "subresource integrity",
        "integrity attribute missing",
    ]):
        return OWASP_TOP10_2021["A08"]

    # =====================================================
    # 3. HTTPS/TLS/암호화 관련
    # =====================================================
    if any(k in name for k in [
        "http only site",
        "https not enforced",
    ]):
        return OWASP_TOP10_2021["A02"]

    # =====================================================
    # 4. SQLMap 결과
    # =====================================================
    if source == "sqlmap":
        if "not detected" in name:
            return "Unmapped"
        return OWASP_TOP10_2021["A03"]

    # =====================================================
    # 5. 일반 키워드 기반 매핑
    # =====================================================

    # A05: Security Misconfiguration
    if any(k in text for k in [
        "missing security header",
        "security header",
        "content-security-policy",
        "x-frame-options",
        "strict-transport-security",
        "x-content-type-options",
        "hsts",
        "cors",
        "directory listing",
        "directory browsing",
        "디렉터리",
        "misconfiguration",
        "timestamp disclosure",
        "server leaks",
    ]):
        return OWASP_TOP10_2021["A05"]

    # A03: Injection
    if any(k in text for k in [
        "sql injection",
        "sqli",
        "cross site scripting",
        "xss",
        "command injection",
        "ldap injection",
    ]):
        return OWASP_TOP10_2021["A03"]

    # A02: Cryptographic Failures
    if any(k in text for k in [
        "ssl",
        "tls",
        "certificate",
        "weak cipher",
        "https",
        "cleartext",
    ]):
        return OWASP_TOP10_2021["A02"]

    # A06: Vulnerable and Outdated Components
    if any(k in text for k in [
        "outdated",
        "old version",
        "known vulnerability",
        "cve",
        "vulnerable component",
        "library",
        "framework",
        "server version",
    ]):
        return OWASP_TOP10_2021["A06"]

    # A01: Broken Access Control
    if any(k in text for k in [
        "access control",
        "unauthorized",
        "idor",
        "privilege",
        "restricted",
        "forbidden",
        "bypass",
    ]):
        return OWASP_TOP10_2021["A01"]

    # A07: Identification and Authentication Failures
    if any(k in text for k in [
        "authentication",
        "login",
        "session",
        "password",
        "credential",
        "jwt",
        "brute force",
    ]):
        return OWASP_TOP10_2021["A07"]

    # A10: SSRF
    if any(k in text for k in [
        "ssrf",
        "server-side request forgery",
    ]):
        return OWASP_TOP10_2021["A10"]

    return "Unmapped"


def assign_verification_status(finding: dict) -> str:
    source = str(finding.get("source", "")).lower()
    severity = str(finding.get("severity", "")).lower()
    confidence = str(finding.get("confidence", "")).lower()
    name = str(finding.get("name", "")).lower()

    if "not detected" in name or severity in ["info", "informational"]:
        return "Informational"

    if source == "header_scan":
        return "Likely True Positive"

    if source == "sqlmap" and severity == "high":
        return "Likely True Positive"

    if confidence == "high":
        return "Likely True Positive"

    if confidence in ["medium", "low"]:
        return "Need Manual Review"

    return "Need Manual Review"


def assign_verification_method(finding: dict) -> str:
    source = str(finding.get("source", "")).lower()
    severity = str(finding.get("severity", "")).lower()

    if severity in ["info", "informational"]:
        return "Informational"

    if source in ["zap", "sqlmap", "header_scan", "nmap"]:
        return "Tool Cross-Validation"

    return "Need Manual Review"


def assign_verification_note(finding: dict) -> str:
    source = str(finding.get("source", "")).lower()
    name = str(finding.get("name", "")).lower()

    if source == "header_scan":
        return "응답 헤더를 재요청하여 해당 보안 헤더가 실제로 누락되었는지 확인한다."

    if source == "sqlmap":
        if "not detected" in name:
            return "현재 옵션에서는 SQL Injection이 탐지되지 않았다. 필요 시 level/risk를 높여 재검증한다."
        return "SQLMap 출력의 injectable parameter 및 vulnerable 문구를 확인하고 동일 파라미터로 재검증한다."

    if source == "zap":
        return "ZAP 결과와 Header Scan/SQLMap/Nmap 결과를 비교하여 동일 취약점 유형이 반복 탐지되는지 확인한다."

    if source == "nmap":
        return "동일 대상 재스캔 및 서비스 배너 확인을 통해 실제 포트 노출 여부를 검증한다."

    return "탐지 결과의 근거와 재현 가능성을 기준으로 수동 검토한다."


def enrich_finding(finding: dict) -> dict:
    finding["owasp_category"] = map_to_owasp_top10(finding)
    finding["verification_status"] = assign_verification_status(finding)
    finding["verification_method"] = assign_verification_method(finding)
    finding["verification_note"] = assign_verification_note(finding)
    return finding


def enrich_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding(finding) for finding in findings]