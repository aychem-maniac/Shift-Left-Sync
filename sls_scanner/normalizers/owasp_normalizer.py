# sls_scanner/normalizers/owasp_normalizer.py

"""
OWASP Top 10 매핑 및 검증 상태 보강 모듈.

각 스캐너에서 정규화된 finding에 대해 다음 정보를 추가한다.

- owasp_category: OWASP Top 10 2021 기준 분류
- verification_status: 탐지 결과의 신뢰도 상태
- verification_method: 검증 방식
- verification_note: 검증 시 참고할 설명

이 모듈은 실제 스캔을 수행하지 않고, 이미 탐지된 결과에 설명과 분류 정보를 보강한다.
"""

from typing import Any


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

UNMAPPED_INFO_KEYWORDS = [
    "modern web application",
    "user agent 퍼저",
    "user agent fuzzer",
]

A05_NAME_KEYWORDS = [
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
]

A08_NAME_KEYWORDS = [
    "sub resource integrity",
    "subresource integrity",
    "integrity attribute missing",
]

A02_NAME_KEYWORDS = [
    "http only site",
    "https not enforced",
]

OWASP_KEYWORD_RULES = [
    (
        "A05",
        [
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
        ],
    ),
    (
        "A03",
        [
            "sql injection",
            "sqli",
            "cross site scripting",
            "xss",
            "command injection",
            "ldap injection",
        ],
    ),
    (
        "A02",
        [
            "ssl",
            "tls",
            "certificate",
            "weak cipher",
            "https",
            "cleartext",
        ],
    ),
    (
        "A06",
        [
            "outdated",
            "old version",
            "known vulnerability",
            "cve",
            "vulnerable component",
            "library",
            "framework",
            "server version",
        ],
    ),
    (
        "A01",
        [
            "access control",
            "unauthorized",
            "idor",
            "privilege",
            "restricted",
            "forbidden",
            "bypass",
        ],
    ),
    (
        "A07",
        [
            "authentication",
            "login",
            "session",
            "password",
            "credential",
            "jwt",
            "brute force",
        ],
    ),
    (
        "A10",
        [
            "ssrf",
            "server-side request forgery",
        ],
    ),
]


def _get_lower_value(finding: dict[str, Any], key: str) -> str:
    """
    finding의 특정 필드 값을 소문자 문자열로 안전하게 변환한다.

    Args:
        finding (dict[str, Any]): 취약점 finding 데이터
        key (str): 조회할 필드명

    Returns:
        str: 소문자로 변환된 문자열 값
    """
    return str(finding.get(key, "") or "").lower()


def _contains_any(text: str, keywords: list[str]) -> bool:
    """
    문자열에 키워드 목록 중 하나라도 포함되어 있는지 확인한다.

    Args:
        text (str): 검사할 문자열
        keywords (list[str]): 포함 여부를 확인할 키워드 목록

    Returns:
        bool: 하나 이상의 키워드가 포함되면 True
    """
    return any(keyword in text for keyword in keywords)


def _build_mapping_text(finding: dict[str, Any]) -> str:
    """
    OWASP 매핑에 사용할 주요 필드를 하나의 문자열로 합친다.

    Args:
        finding (dict[str, Any]): 취약점 finding 데이터

    Returns:
        str: source, name, description, reference를 합친 문자열
    """
    source = _get_lower_value(finding, "source")
    name = _get_lower_value(finding, "name")
    description = _get_lower_value(finding, "description")
    reference = _get_lower_value(finding, "reference")

    return f"{source} {name} {description} {reference}"


def map_to_owasp_top10(finding: dict[str, Any]) -> str:
    """
    finding 내용을 기반으로 OWASP Top 10 2021 카테고리를 추정한다.

    Args:
        finding (dict[str, Any]): 취약점 finding 데이터

    Returns:
        str: OWASP Top 10 카테고리 문자열 또는 "Unmapped"
    """
    source = _get_lower_value(finding, "source")
    name = _get_lower_value(finding, "name")
    mapping_text = _build_mapping_text(finding)

    # 명확한 정보성 항목은 OWASP 취약점 카테고리로 분류하지 않는다.
    if _contains_any(name, UNMAPPED_INFO_KEYWORDS):
        return "Unmapped"

    # 보안 헤더/설정 누락 계열은 일반 키워드보다 A05로 우선 분류한다.
    if _contains_any(name, A05_NAME_KEYWORDS):
        return OWASP_TOP10_2021["A05"]

    # Subresource Integrity 누락은 소프트웨어/데이터 무결성 실패 계열로 분류한다.
    if _contains_any(name, A08_NAME_KEYWORDS):
        return OWASP_TOP10_2021["A08"]

    # HTTPS/TLS 강제 미적용 등은 암호화 실패 계열로 분류한다.
    if _contains_any(name, A02_NAME_KEYWORDS):
        return OWASP_TOP10_2021["A02"]

    # SQLMap에서 실제 탐지된 항목은 Injection으로 분류한다.
    if source == "sqlmap":
        if "not detected" in name:
            return "Unmapped"
        return OWASP_TOP10_2021["A03"]

    # 일반 키워드 기반 매핑
    for category_code, keywords in OWASP_KEYWORD_RULES:
        if _contains_any(mapping_text, keywords):
            return OWASP_TOP10_2021[category_code]

    return "Unmapped"


def assign_verification_status(finding: dict[str, Any]) -> str:
    """
    finding의 source, severity, confidence를 기반으로 검증 상태를 부여한다.

    Args:
        finding (dict[str, Any]): 취약점 finding 데이터

    Returns:
        str: 검증 상태
    """
    source = _get_lower_value(finding, "source")
    severity = _get_lower_value(finding, "severity")
    confidence = _get_lower_value(finding, "confidence")
    name = _get_lower_value(finding, "name")

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


def assign_verification_method(finding: dict[str, Any]) -> str:
    """
    finding의 source와 severity를 기반으로 검증 방식을 부여한다.

    Args:
        finding (dict[str, Any]): 취약점 finding 데이터

    Returns:
        str: 검증 방식
    """
    source = _get_lower_value(finding, "source")
    severity = _get_lower_value(finding, "severity")

    if severity in ["info", "informational"]:
        return "Informational"

    if source in ["zap", "sqlmap", "header_scan", "nmap"]:
        return "Tool Cross-Validation"

    return "Need Manual Review"


def assign_verification_note(finding: dict[str, Any]) -> str:
    """
    finding의 source에 따라 검증 참고 문구를 생성한다.

    Args:
        finding (dict[str, Any]): 취약점 finding 데이터

    Returns:
        str: 검증 참고 문구
    """
    source = _get_lower_value(finding, "source")
    name = _get_lower_value(finding, "name")

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


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    단일 finding에 OWASP 분류와 검증 정보를 추가한다.

    원본 finding을 직접 수정하지 않기 위해 복사본을 생성한 뒤 보강한다.

    Args:
        finding (dict[str, Any]): 정규화된 finding 데이터

    Returns:
        dict[str, Any]: OWASP 및 검증 정보가 추가된 finding
    """
    enriched_finding = finding.copy()

    enriched_finding["owasp_category"] = map_to_owasp_top10(enriched_finding)
    enriched_finding["verification_status"] = assign_verification_status(enriched_finding)
    enriched_finding["verification_method"] = assign_verification_method(enriched_finding)
    enriched_finding["verification_note"] = assign_verification_note(enriched_finding)

    return enriched_finding


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    finding 목록 전체에 OWASP 분류와 검증 정보를 추가한다.

    Args:
        findings (list[dict[str, Any]]): 정규화된 finding 목록

    Returns:
        list[dict[str, Any]]: 보강된 finding 목록
    """
    return [enrich_finding(finding) for finding in findings]