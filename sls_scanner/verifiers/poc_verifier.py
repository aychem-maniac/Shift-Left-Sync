# modules/poc_verifier.py — PoC 재검증 + 오탐 필터링

import requests, time
requests.packages.urllib3.disable_warnings()

TIMEOUT = 10

# ── XSS ────────────────────────────────────────────────────────
def verify_xss(url: str, param: str) -> tuple:
    if not param:
        return "UNVERIFIED", "파라미터 정보 없음"
    CANARY   = "ShiftLeftXSS_8472"
    payloads = [
        f"<{CANARY}>",
        f"<script>alert('{CANARY}')</script>",
        f"'\"><img src=x onerror=alert('{CANARY}')>",
        f"javascript:alert('{CANARY}')",
    ]
    try:
        for pl in payloads:
            r = requests.get(url, params={param: pl},
                             timeout=TIMEOUT, verify=False)
            if CANARY in r.text:
                return "CONFIRMED", f"XSS canary 미인코딩 반사: {pl[:50]}"
        return "FALSE_POSITIVE", "모든 페이로드 인코딩됨"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"

# ── SQL Injection ───────────────────────────────────────────────
def verify_sqli(url: str, param: str) -> tuple:
    if not param:
        return "UNVERIFIED", "파라미터 정보 없음"
    SQL_ERRORS = [
        "you have an error in your sql",
        "syntax error", "unclosed quotation",
        "ora-", "pg::", "sqlite", "odbc",
        "mysql_fetch", "sqlstate",
    ]
    try:
        # 에러 기반
        r = requests.get(url, params={param: "'"},
                         timeout=TIMEOUT, verify=False)
        if any(e in r.text.lower() for e in SQL_ERRORS):
            return "CONFIRMED", "SQL 에러 메시지 노출 확인"

        # 시간 기반 블라인드
        t0 = time.time()
        requests.get(url, params={param: "1' AND SLEEP(4)-- -"},
                     timeout=12, verify=False)
        elapsed = time.time() - t0
        if elapsed >= 3.8:
            return "CONFIRMED", f"시간 기반 SQLi 확인 (지연: {elapsed:.1f}s)"

        return "FALSE_POSITIVE", f"에러 없음, 지연 없음 ({elapsed:.1f}s)"
    except requests.Timeout:
        return "CONFIRMED", "타임아웃 → 블라인드 SQLi 강하게 의심"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"

# ── 헤더 누락 ───────────────────────────────────────────────────
def verify_header(url: str, header_name: str) -> tuple:
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         allow_redirects=True)
        val = r.headers.get(header_name, "")
        if not val:
            return "CONFIRMED", f"'{header_name}' 헤더 부재 직접 확인"
        return "FALSE_POSITIVE", f"헤더 존재: {val[:80]}"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"

# ── 쿠키 속성 ───────────────────────────────────────────────────
def verify_cookie(url: str) -> tuple:
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        issues = []
        for c in r.cookies:
            if not c.secure:
                issues.append(f"{c.name}:Secure없음")
            if not c.has_nonstandard_attr("HttpOnly"):
                issues.append(f"{c.name}:HttpOnly없음")
            if not c.has_nonstandard_attr("SameSite"):
                issues.append(f"{c.name}:SameSite없음")
        if issues:
            return "CONFIRMED", " | ".join(issues[:4])
        return "FALSE_POSITIVE", "모든 쿠키 속성 정상"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"

# ── 세션 ID URL 노출 ────────────────────────────────────────────
def verify_session_in_url(url: str) -> tuple:
    import re
    patterns = [
        r"[?&](jsessionid|sessionid|phpsessid|sid|token)=[\w\-]+",
        r"[?&](sess|session|auth)=[\w\-]{10,}",
    ]
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         allow_redirects=True)
        final_url = r.url
        for pat in patterns:
            if re.search(pat, final_url, re.IGNORECASE):
                return "CONFIRMED", f"URL에 세션 ID 포함: {final_url[:80]}"
        return "FALSE_POSITIVE", "URL에 세션 ID 없음"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"

# ── Private IP 노출 ─────────────────────────────────────────────
def verify_private_ip(url: str) -> tuple:
    import re
    PRIVATE_PATTERNS = [
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    ]
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        for pat in PRIVATE_PATTERNS:
            m = re.search(pat, r.text)
            if m:
                return "CONFIRMED", f"응답 본문에 내부 IP 노출: {m.group()}"
        return "FALSE_POSITIVE", "내부 IP 패턴 없음"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"

# ── CORS 설정 오류 ──────────────────────────────────────────────
def verify_cors(url: str) -> tuple:
    try:
        r = requests.get(
            url, timeout=TIMEOUT, verify=False,
            headers={"Origin": "https://evil.com"}
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            return "CONFIRMED", "ACAO: * 와일드카드 허용"
        if "evil.com" in acao:
            return "CONFIRMED", f"임의 Origin 반사됨: {acao}"
        if acao and acac.lower() == "true":
            return "CONFIRMED", f"ACAO+Credentials 조합 위험: {acao}"
        return "FALSE_POSITIVE", f"CORS 정상: ACAO={acao or '없음'}"
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── 메인 디스패처 ───────────────────────────────────────────────
def dispatch(vuln: dict) -> dict:
    name  = vuln.get("name", "").lower()
    url   = vuln.get("url", "")
    param = vuln.get("param", "")

    if any(k in name for k in ["xss", "cross site script", "reflected"]):
        status, detail = verify_xss(url, param)

    elif any(k in name for k in ["sql injection", "sqli"]):
        status, detail = verify_sqli(url, param)

    elif "x-frame-options" in name or "anti-clickjacking" in name:
        status, detail = verify_header(url, "X-Frame-Options")

    elif "content security policy" in name or "csp" in name:
        status, detail = verify_header(url, "Content-Security-Policy")

    elif "strict-transport" in name or "hsts" in name:
        status, detail = verify_header(url, "Strict-Transport-Security")

    elif "x-content-type" in name:
        status, detail = verify_header(url, "X-Content-Type-Options")

    elif "referrer" in name:
        status, detail = verify_header(url, "Referrer-Policy")

    elif "cookie" in name:
        status, detail = verify_cookie(url)

    elif "session id in url" in name:
        status, detail = verify_session_in_url(url)

    elif "private ip" in name:
        status, detail = verify_private_ip(url)

    elif "cross-domain" in name or "cors" in name:
        status, detail = verify_cors(url)

    else:
        if vuln.get("risk") == "High":
            status, detail = "CONFIRMED", "High 위험도 자동 승인 (수동 검토 권장)"
        else:
            status, detail = "UNVERIFIED", "자동 검증 루틴 미매핑 — 수동 검토 필요"

    vuln["poc_status"] = status
    vuln["evidence"]   = detail
    return vuln