# sls_scanner/enrichers/cve_enricher.py
# NVD API v2 연동으로 CVE → CVSS 점수·설명·패치 링크 자동 조회
# 캐시: data/cve_cache.json (CVE ID 단위 영구 저장)

import json
import os
import re
import time
import requests

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH   = os.path.join("data", "cve_cache.json")
REQUEST_DELAY = 0.7   # NVD 무인증 rate-limit: 50req/30s → 0.6s 간격 권장
TIMEOUT       = 10
CVE_RE        = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# NVD API 키 (환경변수 NVD_API_KEY 설정 시 rate-limit 40배 완화)
_API_KEY = os.environ.get("NVD_API_KEY", "")


# ── 캐시 ──────────────────────────────────────────────────────────
def _load_cache() -> dict:
    os.makedirs("data", exist_ok=True)
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"  [CVE] 캐시 저장 실패: {e}")


# ── NVD API 조회 ──────────────────────────────────────────────────
def _fetch_nvd(cve_id: str) -> dict | None:
    """NVD API v2에서 CVE 상세 정보 조회. 실패 시 None 반환."""
    headers = {"Accept": "application/json"}
    if _API_KEY:
        headers["apiKey"] = _API_KEY

    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {}   # 존재하지 않는 CVE
        if resp.status_code == 403:
            print(f"  [CVE] NVD API rate-limit 초과 — {cve_id} 건너뜀")
            return None
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        return vulns[0].get("cve", {})
    except requests.Timeout:
        print(f"  [CVE] NVD 타임아웃: {cve_id}")
        return None
    except Exception as e:
        print(f"  [CVE] NVD 조회 오류 ({cve_id}): {e}")
        return None


def _parse_nvd(cve_data: dict) -> dict:
    """NVD 응답에서 필요한 필드만 추출."""
    if not cve_data:
        return {}

    # CVSS v3.1 우선, 없으면 v3.0, 없으면 v2.0
    cvss_score    = ""
    cvss_severity = ""
    cvss_vector   = ""

    metrics = cve_data.get("metrics", {})
    for ver_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(ver_key, [])
        if metric_list:
            m = metric_list[0].get("cvssData", {})
            cvss_score    = str(m.get("baseScore", ""))
            cvss_severity = m.get("baseSeverity", "") or m.get("baseScore", "")
            cvss_vector   = m.get("vectorString", "")
            if isinstance(cvss_severity, float):
                cvss_severity = str(cvss_severity)
            break

    # 영문 설명 (en)
    descriptions = cve_data.get("descriptions", [])
    description  = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    # 참고 링크 첫 번째 (패치·공식 권고 우선)
    references = cve_data.get("references", [])
    patch_url  = ""
    for ref in references:
        tags = [t.lower() for t in ref.get("tags", [])]
        if any(t in tags for t in ["patch", "vendor advisory", "mitigation"]):
            patch_url = ref.get("url", "")
            break
    if not patch_url and references:
        patch_url = references[0].get("url", "")

    return {
        "cvss_score":    cvss_score,
        "cvss_severity": cvss_severity.upper() if cvss_severity else "",
        "cvss_vector":   cvss_vector,
        "patch_url":     patch_url[:300],
        "nvd_description": description[:400],
    }


# ── 공개 인터페이스 ───────────────────────────────────────────────
_cache: dict = {}
_cache_dirty = False


def init_cache() -> None:
    """파이프라인 시작 시 1회 호출 — 캐시를 메모리에 로드."""
    global _cache
    _cache = _load_cache()
    print(f"  [CVE] 캐시 로드: {len(_cache)}개 항목")


def flush_cache() -> None:
    """파이프라인 종료 시 1회 호출 — 변경된 캐시 저장."""
    global _cache_dirty
    if _cache_dirty:
        _save_cache(_cache)
        print(f"  [CVE] 캐시 저장: {len(_cache)}개 항목")
        _cache_dirty = False


def enrich_cve(vuln: dict) -> dict:
    """
    vuln dict의 cve_id 필드를 기반으로 NVD에서 CVSS 정보를 조회해 인라인 업데이트.
    cve_id가 없으면 name/description에서 추출 재시도.
    """
    global _cache_dirty

    # cve_id 확정
    cve_id = vuln.get("cve_id", "").strip().upper()
    if not cve_id:
        # name, description, vuln_id에서 CVE 패턴 재탐색
        for field in ("name", "description", "vuln_id", "evidence"):
            m = CVE_RE.search(vuln.get(field, ""))
            if m:
                cve_id = m.group().upper()
                vuln["cve_id"] = cve_id
                break

    if not cve_id:
        return vuln   # CVE 없는 취약점은 그대로

    # 캐시 히트
    if cve_id in _cache:
        info = _cache[cve_id]
        _apply_enrichment(vuln, info)
        return vuln

    # NVD API 조회
    time.sleep(REQUEST_DELAY)
    raw = _fetch_nvd(cve_id)
    if raw is None:
        # 일시적 오류 — 캐시에 저장하지 않고 건너뜀
        return vuln

    info = _parse_nvd(raw)
    _cache[cve_id] = info
    _cache_dirty   = True
    _apply_enrichment(vuln, info)
    return vuln


def _apply_enrichment(vuln: dict, info: dict) -> None:
    """조회된 NVD 정보를 vuln dict에 반영. 빈 값은 덮어쓰지 않음."""
    if info.get("cvss_score"):
        vuln["cvss_score"]    = info["cvss_score"]
        vuln["cvss_severity"] = info["cvss_severity"]
        vuln["cvss_vector"]   = info["cvss_vector"]
    if info.get("patch_url"):
        vuln["patch_url"] = info["patch_url"]
    # NVD 설명이 기존 description보다 풍부하면 보완
    if info.get("nvd_description") and not vuln.get("description"):
        vuln["description"] = info["nvd_description"]
