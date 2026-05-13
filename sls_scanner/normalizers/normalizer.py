# sls_scanner/normalizers/normalizer.py
# 전 도구 결과 정규화 + 중복 제거 통합 모듈

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List
from config import OWASP_MAP, RISK_ORDER


@dataclass
class Vuln:
    tool:        str
    vuln_id:     str
    name:        str
    risk:        str
    url:         str
    param:       str
    evidence:    str
    description: str
    solution:    str
    cwe:         str
    owasp:       str
    poc_status:  str = "PENDING"
    timestamp:   str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


def map_owasp(name: str) -> str:
    nl = name.lower()
    for kw, cat in OWASP_MAP.items():
        if kw in nl:
            return cat
    return "A05:2021 - Security Misconfiguration"


# ── ZAP ───────────────────────────────────────────────────────
def normalize_zap(raw: list) -> List[Vuln]:
    results, seen = [], set()
    for a in raw:
        path = re.sub(r'https?://[^/]+', '', a.get('url', ''))
        key  = (a.get('alert', ''), path, a.get('param', ''))
        if key in seen:
            continue
        seen.add(key)
        results.append(Vuln(
            tool        = "OWASP ZAP",
            vuln_id     = f"ZAP-{a.get('alertRef', '0')}",
            name        = a.get('alert', ''),
            risk        = a.get('risk', 'Low'),
            url         = a.get('url', ''),
            param       = a.get('param', ''),
            evidence    = a.get('evidence', '')[:300],
            description = a.get('description', '')[:400],
            solution    = a.get('solution', '')[:400],
            cwe         = f"CWE-{a.get('cweid', '0')}",
            owasp       = map_owasp(a.get('alert', '')),
        ))
    return results


# ── Nmap ──────────────────────────────────────────────────────
def normalize_nmap(raw: dict) -> List[Vuln]:
    results = []
    raw_result = raw.get("raw_result", {})
    for host, host_data in raw_result.items():
        for protocol, ports in host_data.items():
            for port, port_data in ports.items():
                state = port_data.get("state", "")
                if state != "open":
                    continue
                service = port_data.get("name", "")
                version = port_data.get("version", "")
                product = port_data.get("product", "")
                name    = f"Open port {port}/{protocol} ({service})"
                results.append(Vuln(
                    tool        = "Nmap",
                    vuln_id     = f"NMAP-{host}-{port}",
                    name        = name,
                    risk        = "Informational",
                    url         = f"{host}:{port}",
                    param       = "",
                    evidence    = f"{product} {version}".strip(),
                    description = f"Port {port}/{protocol} is open. Service: {service} {product} {version}",
                    solution    = "포트 노출 여부 검토 및 불필요한 서비스 비활성화",
                    cwe         = "CWE-0",
                    owasp       = "A05:2021 - Security Misconfiguration",
                ))
    return results


# ── SQLMap ────────────────────────────────────────────────────
def normalize_sqlmap(raw: dict) -> List[Vuln]:
    results = []
    target   = raw.get("target", "")
    is_vuln  = raw.get("is_vulnerable", False)
    stdout   = raw.get("stdout", "")
    severity = "High" if is_vuln else "Informational"
    name     = "SQL Injection Detected" if is_vuln else "SQL Injection Not Detected"

    # SQLMap 자체가 PoC 도구이므로 vulnerable=True 이면 즉시 CONFIRMED
    # poc_verifier의 verify_sqli()는 generic HTTP 재검증이라 SQLMap보다 정확도가 낮음
    poc = "CONFIRMED" if is_vuln else "UNVERIFIED"

    v = Vuln(
        tool        = "SQLMap",
        vuln_id     = "SQLMAP-001",
        name        = name,
        risk        = severity,
        url         = target,
        param       = "",
        evidence    = _extract_sqlmap_evidence(stdout),
        description = "SQLMap으로 SQL Injection 점검한 결과입니다.",
        solution    = "파라미터화된 쿼리 및 입력값 검증 적용",
        cwe         = "CWE-89",
        owasp       = "A03:2021 - Injection",
    )
    v.poc_status = poc
    results.append(v)
    return results


def _extract_sqlmap_evidence(stdout: str) -> str:
    keywords = ["is vulnerable", "injectable", "sql injection",
                "back-end DBMS", "current user", "current database"]
    lines = []
    for line in stdout.splitlines():
        if any(k in line.lower() for k in keywords):
            lines.append(line.strip())
        if len(lines) >= 10:
            break
    return "\n".join(lines)


# ── Header scan ───────────────────────────────────────────────
def normalize_header(raw: dict) -> List[Vuln]:
    results        = []
    target         = raw.get("target", "")
    missing        = raw.get("missing_headers", [])
    for idx, header in enumerate(missing, start=1):
        results.append(Vuln(
            tool        = "HeaderScan",
            vuln_id     = f"HEADER-{idx:03d}",
            name        = f"Missing Security Header: {header}",
            risk        = "Medium",
            url         = target,
            param       = "",
            evidence    = f"Response header '{header}' not present",
            description = f"{header} 헤더가 응답에 없습니다.",
            solution    = f"웹 서버 또는 애플리케이션에서 {header} 헤더를 설정하세요.",
            cwe         = "CWE-693",
            owasp       = "A05:2021 - Security Misconfiguration",
        ))
    return results


# ── Nikto ─────────────────────────────────────────────────────
def normalize_nikto(raw: list) -> List[Vuln]:
    results, seen = [], set()
    for item in raw:
        msg = item.get('msg', '')
        key = (msg, item.get('uri', ''))
        if key in seen:
            continue
        seen.add(key)
        risk = "Low"
        if any(k in msg.lower() for k in ["sql", "injection", "xss", "rce", "exec"]):
            risk = "High"
        elif any(k in msg.lower() for k in ["outdated", "header", "config", "expose"]):
            risk = "Medium"
        results.append(Vuln(
            tool        = "Nikto",
            vuln_id     = f"NIKTO-{item.get('id', '0')}",
            name        = msg,
            risk        = risk,
            url         = item.get('uri', ''),
            param       = "",
            evidence    = msg[:300],
            description = msg,
            solution    = "Nikto 탐지 항목 수동 검토 필요",
            cwe         = "CWE-0",
            owasp       = map_owasp(msg),
        ))
    return results


# ── Nuclei ────────────────────────────────────────────────────
def normalize_nuclei(raw: list) -> List[Vuln]:
    SEVERITY_MAP = {
        "critical": "High", "high": "High",
        "medium":   "Medium", "low": "Low",
        "info":     "Informational", "unknown": "Low",
    }
    results, seen = [], set()
    for item in raw:
        info     = item.get('info', {})
        template = item.get('template-id', '')
        matched  = item.get('matched-at', '')
        name     = info.get('name', template)
        key      = (template, matched)
        if key in seen:
            continue
        seen.add(key)
        results.append(Vuln(
            tool        = "Nuclei",
            vuln_id     = f"NUCLEI-{template}",
            name        = name,
            risk        = SEVERITY_MAP.get(info.get('severity', 'unknown').lower(), "Low"),
            url         = matched,
            param       = "",
            evidence    = str(item.get('extracted-results', ''))[:300],
            description = info.get('description', '')[:400],
            solution    = info.get('remediation', '')[:400],
            cwe         = "",
            owasp       = map_owasp(name),
        ))
    return results


# ── 병합 + 정렬 ───────────────────────────────────────────────
def merge_and_sort(vulns: List[Vuln]) -> List[Vuln]:
    vulns.sort(key=lambda v: RISK_ORDER.get(v.risk, 99))
    return vulns


def to_dict_list(vulns: List[Vuln]) -> list:
    return [asdict(v) for v in vulns]
