"""
IDS/IPS detector

HTTP 요청의 path, query, header, body 일부를 검사하여 공격 의심 패턴을 탐지합니다.
URL 인코딩된 공격 페이로드도 탐지하기 위해 원문과 URL-decoded 값을 함께 검사합니다.
"""

from typing import Mapping, Iterable
from urllib.parse import unquote_plus

from sls_scanner.ids.models import IDSFinding
from sls_scanner.ids.rules import IDS_RULES


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def detect_http_request(
    *,
    method: str,
    path: str,
    query: str,
    headers: Mapping[str, str],
    body: str = "",
) -> list[IDSFinding]:
    """
    HTTP 요청 구성요소를 검사해 IDS 탐지 결과를 반환합니다.
    """
    user_agent = headers.get("user-agent", "") or ""
    referer = headers.get("referer", "") or ""
    content_type = headers.get("content-type", "") or ""

    raw_fields = {
        "method": method or "",
        "path": path or "",
        "query": query or "",
        "user_agent": user_agent,
        "referer": referer,
        "content_type": content_type,
        "body": body or "",
    }

    fields: dict[str, str] = {}

    for field_name, value in raw_fields.items():
        fields[field_name] = value

        decoded = _url_decode(value)
        if decoded != value:
            fields[field_name + "_decoded"] = decoded

    findings: list[IDSFinding] = []

    for field_name, value in fields.items():
        if not value:
            continue

        for rule in IDS_RULES:
            match = rule.pattern.search(value)
            if not match:
                continue

            findings.append(
                IDSFinding(
                    attack_type=rule.attack_type,
                    rule_name=rule.name,
                    severity=rule.severity,
                    matched_field=field_name,
                    matched_value=_safe_snippet(match.group(0)),
                    description=rule.description,
                )
            )

    return _deduplicate_findings(findings)


def highest_severity(findings: Iterable[IDSFinding]) -> str:
    """
    탐지 결과 중 가장 높은 severity를 반환합니다.
    """
    highest = "low"
    highest_score = 0

    for finding in findings:
        score = SEVERITY_ORDER.get(finding.severity, 0)
        if score > highest_score:
            highest = finding.severity
            highest_score = score

    return highest


def should_block(findings: Iterable[IDSFinding], min_severity: str = "high") -> bool:
    """
    IPS 모드에서 차단할지 판단합니다.
    기본값은 high 이상 차단입니다.
    """
    threshold = SEVERITY_ORDER.get(min_severity, 3)

    for finding in findings:
        if SEVERITY_ORDER.get(finding.severity, 0) >= threshold:
            return True

    return False


def _url_decode(value: str) -> str:
    try:
        return unquote_plus(value)
    except Exception:
        return value


def _safe_snippet(value: str, limit: int = 160) -> str:
    value = value.replace("\n", "\\n").replace("\r", "\\r")
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def _deduplicate_findings(findings: list[IDSFinding]) -> list[IDSFinding]:
    seen = set()
    result: list[IDSFinding] = []

    for finding in findings:
        key = (
            finding.attack_type,
            finding.rule_name,
            finding.severity,
            finding.matched_field,
            finding.matched_value,
        )
        if key in seen:
            continue

        seen.add(key)
        result.append(finding)

    return result
