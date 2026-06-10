# sls_scanner/verifiers/poc_verifier.py — PoC 재검증 + 오탐 필터링
# 변경: evidence 덮어쓰기 제거 → poc_reason 필드로 분리
#       각 검증 함수에 상세 근거(페이로드·응답 스니펫·헤더값) 포함

import re
import time
import requests
requests.packages.urllib3.disable_warnings()

TIMEOUT = 10


# ── 공통 유틸 ────────────────────────────────────────────────────
def _safe_get(url: str, timeout: int = TIMEOUT, **kwargs) -> requests.Response | None:
    try:
        return requests.get(url, timeout=timeout, verify=False,
                            allow_redirects=True, **kwargs)
    except Exception:
        return None


def _snippet(text: str, keyword: str, window: int = 60) -> str:
    """응답 본문에서 keyword 주변 snippet 추출"""
    idx = text.lower().find(keyword.lower())
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end   = min(len(text), idx + len(keyword) + window)
    return text[start:end].replace("\n", " ").strip()


# ── XSS ──────────────────────────────────────────────────────────
def verify_xss(url: str, param: str) -> tuple:
    if not param:
        return "UNVERIFIED", "파라미터 정보 없음 — 수동 확인 필요"

    CANARY = "ShiftLeftXSS_8472"
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
                snip = _snippet(r.text, CANARY)
                return (
                    "CONFIRMED",
                    f"XSS canary 미인코딩 반사 확인 | "
                    f"파라미터: {param} | 페이로드: {pl[:60]} | "
                    f"응답 스니펫: ...{snip}..."
                )
        # 모두 인코딩됨 — 인코딩 형태 확인
        r_last = requests.get(url, params={param: f"<{CANARY}>"},
                              timeout=TIMEOUT, verify=False)
        encoded_form = ""
        for enc in [f"&lt;{CANARY}&gt;", f"%3C{CANARY}%3E",
                    CANARY.lower(), CANARY]:
            if enc in r_last.text:
                encoded_form = enc
                break
        reason = (
            f"모든 페이로드 인코딩 처리됨 — 오탐으로 판단 | "
            f"파라미터: {param} | "
            f"인코딩 확인값: {encoded_form or '응답에 canary 없음(필터링)'}"
        )
        return "FALSE_POSITIVE", reason
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── SQL Injection ─────────────────────────────────────────────────
def verify_sqli(url: str, param: str) -> tuple:
    if not param:
        return "UNVERIFIED", "파라미터 정보 없음 — 수동 확인 필요"

    SQL_ERRORS = [
        "you have an error in your sql",
        "syntax error",
        "unclosed quotation",
        "ora-", "pg::",
        "sqlite", "odbc",
        "mysql_fetch", "sqlstate",
        "quoted string not properly terminated",
        "division by zero",
    ]
    try:
        # 1단계: 에러 기반
        r = requests.get(url, params={param: "'"},
                         timeout=TIMEOUT, verify=False)
        for err in SQL_ERRORS:
            if err in r.text.lower():
                snip = _snippet(r.text, err)
                return (
                    "CONFIRMED",
                    f"SQL 에러 메시지 노출 | "
                    f"파라미터: {param} | 페이로드: ' (단일 따옴표) | "
                    f"에러 키워드: '{err}' | 응답 스니펫: ...{snip}..."
                )

        # 2단계: 응답 길이 차이 (Boolean 기반)
        r_true  = requests.get(url, params={param: "1' OR '1'='1"},
                               timeout=TIMEOUT, verify=False)
        r_false = requests.get(url, params={param: "1' AND '1'='2"},
                               timeout=TIMEOUT, verify=False)
        len_diff = abs(len(r_true.text) - len(r_false.text))
        if len_diff > 200:
            return (
                "CONFIRMED",
                f"Boolean 기반 SQLi 의심 | "
                f"파라미터: {param} | "
                f"TRUE 응답: {len(r_true.text)}bytes / FALSE 응답: {len(r_false.text)}bytes | "
                f"차이: {len_diff}bytes"
            )

        # 3단계: 시간 기반 블라인드
        t0 = time.time()
        requests.get(url, params={param: "1' AND SLEEP(4)-- -"},
                     timeout=12, verify=False)
        elapsed = time.time() - t0
        if elapsed >= 3.8:
            return (
                "CONFIRMED",
                f"시간 기반 SQLi 확인 | "
                f"파라미터: {param} | 페이로드: SLEEP(4) | "
                f"응답 지연: {elapsed:.1f}s (정상: < 1s)"
            )

        return (
            "FALSE_POSITIVE",
            f"에러 없음 / Boolean 차이 없음({len_diff}bytes) / 지연 없음({elapsed:.1f}s) | "
            f"파라미터: {param} — 오탐으로 판단"
        )
    except requests.Timeout:
        return (
            "CONFIRMED",
            f"타임아웃 발생 → 블라인드 SQLi 강하게 의심 | "
            f"파라미터: {param} | SLEEP 페이로드에서 서버 응답 없음"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── 보안 헤더 누락 ────────────────────────────────────────────────
def verify_header(url: str, header_name: str) -> tuple:
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         allow_redirects=True)
        val = r.headers.get(header_name, "")
        if not val:
            all_headers = ", ".join(r.headers.keys())
            return (
                "CONFIRMED",
                f"'{header_name}' 헤더 부재 직접 확인 | "
                f"HTTP {r.status_code} | "
                f"응답에 포함된 헤더 목록: {all_headers[:200]}"
            )
        return (
            "FALSE_POSITIVE",
            f"'{header_name}' 헤더 존재 — 오탐으로 판단 | "
            f"실제 값: {val[:120]}"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── 쿠키 속성 ─────────────────────────────────────────────────────
def verify_cookie(url: str) -> tuple:
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        if not r.cookies:
            return (
                "UNVERIFIED",
                f"응답에 Set-Cookie 없음 (HTTP {r.status_code}) — 수동 확인 필요"
            )
        issues  = []
        details = []
        for c in r.cookies:
            attrs = []
            if not c.secure:
                attrs.append("Secure 없음")
                issues.append(f"{c.name}:Secure없음")
            if not c.has_nonstandard_attr("HttpOnly"):
                attrs.append("HttpOnly 없음")
                issues.append(f"{c.name}:HttpOnly없음")
            if not c.has_nonstandard_attr("SameSite"):
                attrs.append("SameSite 없음")
                issues.append(f"{c.name}:SameSite없음")
            if attrs:
                details.append(f"{c.name} → {', '.join(attrs)}")
            else:
                details.append(f"{c.name} → 속성 정상")

        if issues:
            return (
                "CONFIRMED",
                f"쿠키 보안 속성 미설정 확인 | "
                f"문제 쿠키: {' | '.join(details[:4])}"
            )
        return (
            "FALSE_POSITIVE",
            f"모든 쿠키 보안 속성 정상 — 오탐으로 판단 | "
            f"검사 쿠키: {' | '.join(details[:4])}"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── 세션 ID URL 노출 ──────────────────────────────────────────────
def verify_session_in_url(url: str) -> tuple:
    patterns = [
        r"[?&](jsessionid|sessionid|phpsessid|sid|token)=[\w\-]+",
        r"[?&](sess|session|auth)=[\w\-]{10,}",
    ]
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         allow_redirects=True)
        final_url = r.url
        for pat in patterns:
            m = re.search(pat, final_url, re.IGNORECASE)
            if m:
                return (
                    "CONFIRMED",
                    f"URL에 세션 식별자 노출 | "
                    f"최종 URL: {final_url[:100]} | "
                    f"매칭 파라미터: {m.group()[:60]}"
                )
        return (
            "FALSE_POSITIVE",
            f"URL에 세션 식별자 없음 — 오탐으로 판단 | "
            f"최종 URL: {final_url[:100]}"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── Private IP 노출 ───────────────────────────────────────────────
def verify_private_ip(url: str) -> tuple:
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
                snip = _snippet(r.text, m.group())
                return (
                    "CONFIRMED",
                    f"응답 본문에 내부 IP 노출 | "
                    f"발견된 IP: {m.group()} | "
                    f"컨텍스트: ...{snip}..."
                )
        return (
            "FALSE_POSITIVE",
            f"응답 본문에 내부 IP 패턴 없음 — 오탐으로 판단 | "
            f"응답 크기: {len(r.text)}bytes"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── CORS 설정 오류 ────────────────────────────────────────────────
def verify_cors(url: str) -> tuple:
    try:
        # 1단계: 단순 GET Origin 반사 확인
        r = requests.get(
            url, timeout=TIMEOUT, verify=False,
            headers={"Origin": "https://evil.com"}
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            return (
                "CONFIRMED",
                f"CORS 와일드카드 허용 (ACAO: *) | "
                f"모든 출처에서 리소스 접근 가능 | HTTP {r.status_code}"
            )
        if "evil.com" in acao:
            cred_risk = " + Credentials=true → 인증 정보 탈취 가능" if acac.lower() == "true" else ""
            return (
                "CONFIRMED",
                f"임의 Origin 반사 확인 | "
                f"ACAO: {acao}{cred_risk} | HTTP {r.status_code}"
            )
        if acao and acac.lower() == "true":
            return (
                "CONFIRMED",
                f"ACAO+Credentials 위험 조합 | "
                f"ACAO: {acao} / ACAC: {acac} | HTTP {r.status_code}"
            )

        # 2단계: Preflight 확인
        try:
            preflight = requests.options(
                url, timeout=TIMEOUT, verify=False,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                }
            )
            acam = preflight.headers.get("Access-Control-Allow-Methods", "")
            acao_pre = preflight.headers.get("Access-Control-Allow-Origin", "")
            if "evil.com" in acao_pre:
                return (
                    "CONFIRMED",
                    f"Preflight에서 임의 Origin 허용 | "
                    f"ACAO: {acao_pre} / 허용 메서드: {acam} | HTTP {preflight.status_code}"
                )
        except Exception:
            pass

        return (
            "FALSE_POSITIVE",
            f"CORS 정상 설정 — 오탐으로 판단 | "
            f"ACAO: '{acao or '없음'}' / ACAC: '{acac or '없음'}' | "
            f"evil.com Origin 반사 없음"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── Open Redirect ─────────────────────────────────────────────────
def verify_open_redirect(url: str, param: str) -> tuple:
    if not param:
        return "UNVERIFIED", "파라미터 정보 없음"
    REDIRECT_TARGET = "https://evil.com"
    try:
        r = requests.get(url, params={param: REDIRECT_TARGET},
                         timeout=TIMEOUT, verify=False,
                         allow_redirects=False)
        loc = r.headers.get("Location", "")
        if "evil.com" in loc:
            return (
                "CONFIRMED",
                f"오픈 리다이렉트 확인 | "
                f"파라미터: {param} | "
                f"Location 헤더: {loc[:100]} | HTTP {r.status_code}"
            )
        r2 = requests.get(url, params={param: REDIRECT_TARGET},
                          timeout=TIMEOUT, verify=False,
                          allow_redirects=True)
        if "evil.com" in r2.url:
            return (
                "CONFIRMED",
                f"오픈 리다이렉트 확인 (최종 URL) | "
                f"파라미터: {param} | 최종 URL: {r2.url[:100]}"
            )
        return (
            "FALSE_POSITIVE",
            f"리다이렉트 대상 제한됨 — 오탐으로 판단 | "
            f"파라미터: {param} | Location: '{loc or '없음'}'"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── 디렉토리 리스팅 ───────────────────────────────────────────────
def verify_directory_listing(url: str) -> tuple:
    LISTING_SIGNS = [
        "index of /", "parent directory",
        "directory listing for", "[to parent directory]",
    ]
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        body_lower = r.text.lower()
        for sign in LISTING_SIGNS:
            if sign in body_lower:
                snip = _snippet(r.text, sign)
                return (
                    "CONFIRMED",
                    f"디렉토리 리스팅 노출 확인 | "
                    f"URL: {url} | 키워드: '{sign}' | "
                    f"스니펫: ...{snip}..."
                )
        return (
            "FALSE_POSITIVE",
            f"디렉토리 리스팅 없음 — 오탐으로 판단 | "
            f"HTTP {r.status_code} | 응답 크기: {len(r.text)}bytes"
        )
    except Exception as e:
        return "UNVERIFIED", f"요청 실패: {e}"


# ── 메인 디스패처 ─────────────────────────────────────────────────
def dispatch(vuln: dict) -> dict:
    """
    PoC 검증 수행 후 poc_status / poc_reason 설정.
    원본 evidence는 덮어쓰지 않음.
    """
    name  = vuln.get("name", "").lower()
    url   = vuln.get("url", "")
    param = vuln.get("param", "")

    if any(k in name for k in ["xss", "cross site script", "reflected"]):
        status, reason = verify_xss(url, param)

    elif any(k in name for k in ["sql injection", "sqli"]):
        status, reason = verify_sqli(url, param)

    elif "x-frame-options" in name or "anti-clickjacking" in name:
        status, reason = verify_header(url, "X-Frame-Options")

    elif "content security policy" in name or "csp" in name:
        status, reason = verify_header(url, "Content-Security-Policy")

    elif "strict-transport" in name or "hsts" in name:
        status, reason = verify_header(url, "Strict-Transport-Security")

    elif "x-content-type" in name:
        status, reason = verify_header(url, "X-Content-Type-Options")

    elif "referrer" in name:
        status, reason = verify_header(url, "Referrer-Policy")

    elif "cookie" in name:
        status, reason = verify_cookie(url)

    elif "session id in url" in name or "session token in url" in name:
        status, reason = verify_session_in_url(url)

    elif "private ip" in name or "internal ip" in name:
        status, reason = verify_private_ip(url)

    elif "cross-domain" in name or "cors" in name:
        status, reason = verify_cors(url)

    elif "open redirect" in name or "redirect" in name:
        status, reason = verify_open_redirect(url, param)

    elif "directory" in name and ("listing" in name or "browsing" in name):
        status, reason = verify_directory_listing(url)

    else:
        # 매핑 안 된 항목 — HTTP 상태 코드 + 위험도 기반 판단
        try:
            r = requests.get(url, timeout=5, verify=False,
                             allow_redirects=True)
            base = (
                f"HTTP {r.status_code} | 응답 크기: {len(r.text)}bytes | "
                f"Content-Type: {r.headers.get('Content-Type','N/A')[:60]}"
            )
        except Exception as e:
            base = f"연결 실패: {e}"

        risk = vuln.get("risk", "")
        tool = vuln.get("tool", "")
        if risk in ("High", "Critical"):
            status = "CONFIRMED"
            reason = (
                f"자동 검증 규칙 없음 — {risk} 위험도로 CONFIRMED 처리 | "
                f"도구: {tool} | {base} | 수동 검토 권장"
            )
        elif risk == "Medium":
            status = "UNVERIFIED"
            reason = (
                f"자동 검증 규칙 없음 — Medium 위험도 | "
                f"도구: {tool} | {base} | 수동 검토 필요"
            )
        else:
            status = "UNVERIFIED"
            reason = (
                f"자동 검증 규칙 없음 — {risk or 'Unknown'} 위험도 | "
                f"도구: {tool} | {base}"
            )

    # evidence는 원본 유지, poc_reason만 업데이트
    vuln["poc_status"] = status
    vuln["poc_reason"] = reason
    return vuln
