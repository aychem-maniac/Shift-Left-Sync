# sls_scanner/core/pipeline.py

import time
import threading
import concurrent.futures
from datetime import datetime
import os as _os_env

from sls_scanner.core.target import validate_target
from sls_scanner.core.exceptions import InvalidTargetError

MAX_CONCURRENT_SCANS = int(_os_env.getenv("MAX_CONCURRENT_SCANS", "3"))

# ── ZAP 직렬화 락 ─────────────────────────────────────────────
# ZAP은 단일 데몬이라 동시 호출 시 충돌 → 한 번에 하나만 실행
_zap_lock = threading.Lock()

# ── 취소 플래그 ────────────────────────────────────────────────
_cancel_flags: dict[str, bool] = {}

def request_cancel(job_id: str) -> None:
    """api.py에서 호출 — 해당 job_id 취소 요청"""
    _cancel_flags[job_id] = True

def _check_cancel(job_id: str | None, cb=None, phase: str = "") -> None:
    """취소 요청 시 ScanCancelledError 발생"""
    if job_id and _cancel_flags.get(job_id):
        _cancel_flags.pop(job_id, None)
        if cb:
            cb("사용자가 스캔을 취소했습니다", -1)
        raise ScanCancelledError(f"사용자 취소 요청 — {phase}")

class ScanCancelledError(Exception):
    pass


from sls_scanner.scanners.registry import run_scanner

from sls_scanner.normalizers.normalizer import (
    normalize_zap, normalize_nmap, normalize_sqlmap,
    normalize_header, normalize_nikto, normalize_nuclei,
    merge_and_sort, to_dict_list,
)
from sls_scanner.verifiers.poc_verifier import dispatch as poc_dispatch
from sls_scanner.enrichers.cve_enricher import init_cache, enrich_cve, flush_cache
from sls_scanner.reports.reporter import (
    make_paths, export_csv, export_json, export_html, export_html_plain, print_summary
)
from sls_scanner.utils.target_monitor import TargetHealthMonitor

# database는 런타임 import (순환 의존 방지)
def _save_report_safe(job_id, *args, **kwargs):
    if not job_id:
        return
    try:
        from database import save_report
        save_report(job_id, *args, **kwargs)
    except Exception as e:
        print(f"  [DB] save_report 실패 (무시): {e}")


def _fmt(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m}분 {s:02d}초" if m else f"{s}초"


def run_pipeline(target: str, strength: str = "medium") -> None:
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    pipe_start = time.time()

    print(f"[INFO] Target:   {target}")
    print(f"[INFO] Strength: {strength}")

    if not validate_target(target):
        raise InvalidTargetError(f"Invalid target: {target}")

    print("[INFO] Pipeline started")

    # ── 1. 병렬 스캔 ──────────────────────────────────────────
    # ZAP은 단독 실행 (상태가 있는 도구라 병렬 실행 시 충돌 가능)
    # 나머지 5개는 독립적이므로 병렬 실행
    print("[INFO] Phase 1: 병렬 스캔 시작 (Nmap/SQLMap/Header/Nikto/Nuclei 동시 실행)")
    scan_start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_nmap   = ex.submit(run_scanner, "nmap", target, strength)
        f_sqlmap = ex.submit(run_scanner, "sqlmap", target, strength)
        f_header = ex.submit(run_scanner, "header", target, strength)
        f_nikto  = ex.submit(run_scanner, "nikto", target, strength)
        f_nuclei = ex.submit(run_scanner, "nuclei", target, strength)

        # ZAP 직렬화 (단일 데몬 충돌 방지)
        with _zap_lock:
            raw_zap = run_scanner("zap", target, strength=strength, progress_cb=None)

        raw_nmap   = f_nmap.result()
        raw_sqlmap = f_sqlmap.result()
        raw_header = f_header.result()
        raw_nikto  = f_nikto.result()
        raw_nuclei = f_nuclei.result()

    print(f"[TIME] 전체 스캔 소요 시간: {_fmt(time.time() - scan_start)}")

    # ── 2. 정규화 ─────────────────────────────────────────────
    norm_start = time.time()
    vulns = []
    vulns.extend(normalize_zap(raw_zap.get("raw_alerts", [])))
    vulns.extend(normalize_nmap(raw_nmap))
    vulns.extend(normalize_sqlmap(raw_sqlmap))
    vulns.extend(normalize_header(raw_header))
    vulns.extend(normalize_nikto(raw_nikto))
    vulns.extend(normalize_nuclei(raw_nuclei))
    vulns = merge_and_sort(vulns)
    print(f"[INFO] Normalized findings: {len(vulns)}건  ({_fmt(time.time()-norm_start)})")

    # ── 2.5 CVE Enrichment ────────────────────────────────────
    cve_targets = [v for v in vulns if v.cve_id or
                   any(k in v.name.upper() for k in ["CVE-"]) or
                   any(k in v.vuln_id.upper() for k in ["CVE-"])]
    print(f"[INFO] CVE enrichment 대상: {len(cve_targets)}건")
    if cve_targets:
        init_cache()
        vuln_dicts_pre = to_dict_list(vulns)
        for v in vuln_dicts_pre:
            enrich_cve(v)
        flush_cache()
        enriched_count = sum(1 for v in vuln_dicts_pre if v.get("cvss_score"))
        print(f"[INFO] CVE enrichment 완료: {enriched_count}건 CVSS 정보 추가")
    else:
        vuln_dicts_pre = to_dict_list(vulns)

    # ── 3. PoC 검증 ───────────────────────────────────────────
    print("[INFO] PoC verification started")
    poc_start  = time.time()
    vuln_dicts = vuln_dicts_pre
    for v in vuln_dicts:
        poc_dispatch(v)
    print(f"[TIME] PoC verification: {_fmt(time.time() - poc_start)}")

    # ── 4. 리포트 생성 ────────────────────────────────────────
    paths      = make_paths(target=target, timestamp=timestamp)
    confirmed  = [v for v in vuln_dicts if v.get("poc_status") == "CONFIRMED"]
    false_pos  = [v for v in vuln_dicts if v.get("poc_status") == "FALSE_POSITIVE"]
    unverified = [v for v in vuln_dicts if v.get("poc_status") in ("UNVERIFIED", "PENDING")]

    port_info = []
    raw_result = raw_nmap.get("raw_result", {})
    for host, host_data in raw_result.items():
        for proto, ports in host_data.items():
            for port, pdata in ports.items():
                port_info.append({
                    "host": host, "port": port, "protocol": proto,
                    "service": pdata.get("name", ""),
                    "state":   pdata.get("state", ""),
                    "product": pdata.get("product", ""),
                    "version": pdata.get("version", ""),
                })

    export_csv(confirmed,  paths["csv_confirmed"])
    export_csv(false_pos,  paths["csv_false_positive"])
    export_csv(unverified, paths["csv_unverified"])
    export_csv(vuln_dicts, paths["csv_full"])
    export_json(vuln_dicts, paths["json_full"])
    export_html(
        target=target, vulns=vuln_dicts, port_info=port_info,
        path=paths["html"], timestamp=timestamp,
    )
    export_html_plain(
        target=target, vulns=vuln_dicts,
        path=paths["html_plain"], timestamp=timestamp,
    )

    print_summary(vuln_dicts)
    print(f"[INFO] HTML report: {paths['html']}")
    print(f"[TIME] Pipeline 총 소요 시간: {_fmt(time.time() - pipe_start)}")
    print(f"[INFO] Pipeline completed")

def run_pipeline_with_cb(
    target: str,
    strength: str = "medium",
    cb=None,
    job_id: str | None = None,
) -> None:
    """
    SSE·취소 지원 파이프라인.
    cb(phase: str, progress: int) — progress=-1 은 취소 신호.
    """
    def _cb(phase: str, pct: int):
        if cb:
            cb(phase, pct)

    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    pipe_start = time.time()

    if not validate_target(target):
        raise InvalidTargetError(f"Invalid target: {target}")

    # ── 0. 취소 초기 체크 ─────────────────────────────────────
    _check_cancel(job_id, _cb, "시작 전")

    # ── 타겟 부하 모니터 시작 ─────────────────────────────────
    def _warn(msg: str):
        """부하 경고 → SSE warning 이벤트로 전달"""
        if cb:
            cb(f"[부하감지] {msg}", -2)   # -2: warning 전용 신호
    monitor = TargetHealthMonitor(target, warn_cb=_warn).start()

    # ── 1. ZAP + non-ZAP 동시 시작 ───────────────────────────────
    # ZAP  : 별도 스레드에서 락 대기 → 슬롯 생기면 즉시 실행
    # non-ZAP: 메인 스레드에서 즉시 실행 (ZAP 대기와 무관)
    import threading as _threading

    # ZAP 대기 타임아웃: 동시 스캔 수에 비례해서 늘림
    ZAP_BASE = {"low": 1800, "medium": 3600, "high": 7200}
    zap_timeout = ZAP_BASE.get(strength, 3600) * MAX_CONCURRENT_SCANS
    scan_start   = time.time()

    # 진행률: 두 스레드가 동시에 호출 → 항상 최대값 유지 (역행 방지)
    _max_pct   = [3]
    _pct_mutex = _threading.Lock()

    def _safe_cb(phase: str, pct: int) -> None:
        with _pct_mutex:
            if pct > _max_pct[0]:
                _max_pct[0] = pct
            else:
                pct = _max_pct[0]
        _cb(phase, pct)

    # ZAP 스레드: 락 획득 후 ZAP 실행
    raw_zap       = {"target": target, "raw_alerts": []}
    zap_exception = [None]

    def _zap_runner() -> None:
        _safe_cb("ZAP 슬롯 대기 중 — non-ZAP 스캔과 병렬 진행", 5)
        acquired = _zap_lock.acquire(timeout=zap_timeout)
        try:
            if acquired:
                _safe_cb("ZAP 스파이더 시작", 33)
                def _zap_pcb(msg: str, abs_pct: int) -> None:
                    # ZAP 내부(9-35) → 파이프라인(33-43) 재매핑
                    remap = 33 + int((abs_pct - 9) / max(35 - 9, 1) * (43 - 33))
                    remap = max(33, min(43, remap))
                    _safe_cb(msg, remap)
                    if _cancel_flags.get(job_id):
                        raise ScanCancelledError("ZAP 중 사용자 취소")
                raw_zap.update(
                    run_scanner("zap", target, strength=strength, progress_cb=_zap_pcb)
                )
            else:
                _safe_cb(f"ZAP 대기 타임아웃 ({zap_timeout//60}분) — ZAP 없이 진행", 43)
                print(f"  [ZAP] 락 획득 타임아웃 — {target}")
        except ScanCancelledError as e:
            zap_exception[0] = e
        except Exception as e:
            print(f"  [ZAP] 오류 (무시): {e}")
        finally:
            if acquired:
                _zap_lock.release()

    zap_thread = _threading.Thread(target=_zap_runner, daemon=True, name=f"zap-{job_id}")
    zap_thread.start()

    # non-ZAP 스레드풀: 즉시 병렬 실행
    _safe_cb("Nmap / SQLMap / Header / Nikto / Nuclei 시작", 5)
    NON_ZAP = [
        ("Nmap",   lambda: run_scanner("nmap", target, strength=strength)),
        ("SQLMap", lambda: run_scanner("sqlmap", target, strength=strength)),
        ("Header", lambda: run_scanner("header", target, strength=strength)),
        ("Nikto",  lambda: run_scanner("nikto", target, strength=strength)),
        ("Nuclei", lambda: run_scanner("nuclei", target, strength=strength)),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {name: ex.submit(fn) for name, fn in NON_ZAP}

        done_set = set()
        while len(done_set) < len(futs):
            _check_cancel(job_id, _safe_cb, "비ZAP 스캔 중")
            for name, f in futs.items():
                if name not in done_set and f.done():
                    done_set.add(name)
                    pct = 5 + int(len(done_set) / len(futs) * 25)
                    _safe_cb(f"{name} 완료 ({len(done_set)}/{len(futs)})", pct)
            if len(done_set) < len(futs):
                time.sleep(2)

        raw_nmap   = futs["Nmap"].result()
        raw_sqlmap = futs["SQLMap"].result()
        raw_header = futs["Header"].result()
        raw_nikto  = futs["Nikto"].result()
        raw_nuclei = futs["Nuclei"].result()

    _safe_cb("비-ZAP 완료 — ZAP 완료 대기 중", 31)
    print(f"  [SCAN] 비-ZAP 완료: {_fmt(time.time()-scan_start)}")
    _check_cancel(job_id, _safe_cb, "비ZAP 완료 후")

    # ZAP 스레드 완료 대기
    zap_thread.join()

    if zap_exception[0]:
        raise zap_exception[0]

    _safe_cb("전체 스캔 완료 (ZAP + 비-ZAP)", 44)
    _check_cancel(job_id, _safe_cb, "스캔 완료 후")

    # 이후 단계에서 _safe_cb 대신 _cb 사용 (단일 스레드로 복귀)
    def _cb(phase: str, pct: int):
        if cb:
            cb(phase, pct)

    # ── 2. 정규화 ─────────────────────────────────────────────
    _cb("결과 정규화 중", 45)
    vulns = []
    vulns.extend(normalize_zap(raw_zap.get("raw_alerts", [])))
    vulns.extend(normalize_nmap(raw_nmap))
    vulns.extend(normalize_sqlmap(raw_sqlmap))
    vulns.extend(normalize_header(raw_header))
    vulns.extend(normalize_nikto(raw_nikto))
    vulns.extend(normalize_nuclei(raw_nuclei))
    vulns = merge_and_sort(vulns)
    _cb(f"정규화 완료 — {len(vulns)}건 취약점", 50)
    _check_cancel(job_id, _cb, "정규화 완료 후")

    # ── 2.5 CVE Enrichment ────────────────────────────────────
    cve_targets = [v for v in vulns if v.cve_id or
                   "CVE-" in v.name.upper() or "CVE-" in v.vuln_id.upper()]
    if cve_targets:
        _cb(f"CVE 정보 조회 중 ({len(cve_targets)}건)", 52)
        init_cache()
        vuln_dicts_pre = to_dict_list(vulns)
        for v in vuln_dicts_pre:
            enrich_cve(v)
        flush_cache()
        enriched = sum(1 for v in vuln_dicts_pre if v.get("cvss_score"))
        _cb(f"CVE 조회 완료 — CVSS 매핑 {enriched}건", 60)
    else:
        vuln_dicts_pre = to_dict_list(vulns)
        _cb("CVE 대상 없음 — PoC 검증 시작", 60)

    _check_cancel(job_id, _cb, "CVE enrichment 후")

    # ── 3. PoC 검증 ───────────────────────────────────────────
    total      = len(vuln_dicts_pre)
    vuln_dicts = vuln_dicts_pre
    for i, v in enumerate(vuln_dicts, 1):
        _check_cancel(job_id, _cb, f"PoC #{i}")
        pct = 60 + int(i / max(total, 1) * 28)
        _cb(f"PoC 검증 중 ({i}/{total}) — {v.get('name','')[:30]}", pct)
        poc_dispatch(v)

    _cb("PoC 검증 완료", 90)

    # ── 4. 리포트 생성 ────────────────────────────────────────
    _cb("리포트 생성 중", 92)
    paths      = make_paths(target=target, timestamp=timestamp)
    confirmed  = [v for v in vuln_dicts if v.get("poc_status") == "CONFIRMED"]
    false_pos  = [v for v in vuln_dicts if v.get("poc_status") == "FALSE_POSITIVE"]
    unverified = [v for v in vuln_dicts if v.get("poc_status") in ("UNVERIFIED", "PENDING")]

    port_info  = []
    raw_result = raw_nmap.get("raw_result", {})
    for host, host_data in raw_result.items():
        for proto, ports in host_data.items():
            for port, pdata in ports.items():
                port_info.append({
                    "host": host, "port": port, "protocol": proto,
                    "service": pdata.get("name", ""),
                    "state":   pdata.get("state", ""),
                    "product": pdata.get("product", ""),
                    "version": pdata.get("version", ""),
                })

    export_csv(confirmed,  paths["csv_confirmed"])
    export_csv(false_pos,  paths["csv_false_positive"])
    export_csv(unverified, paths["csv_unverified"])
    export_csv(vuln_dicts, paths["csv_full"])
    export_json(vuln_dicts, paths["json_full"])
    export_html(
        target=target, vulns=vuln_dicts, port_info=port_info,
        path=paths["html"], timestamp=timestamp,
    )
    export_html_plain(
        target=target, vulns=vuln_dicts,
        path=paths["html_plain"], timestamp=timestamp,
    )

    total        = len(vuln_dicts)
    confirmed_n  = len(confirmed)
    unverified_n = len(unverified)
    high_n       = sum(1 for v in vuln_dicts if v.get("risk") in ("High", "Critical"))
    medium_n     = sum(1 for v in vuln_dicts if v.get("risk") == "Medium")

    counts = {
        "total":      total,
        "confirmed":  confirmed_n,
        "unverified": unverified_n,
        "high":       high_n,
        "medium":     medium_n,
    }

    import os as _os
    for rtype, fpath in [
        ("csv_confirmed",      paths["csv_confirmed"]),
        ("csv_false_positive", paths["csv_false_positive"]),
        ("csv_unverified",     paths["csv_unverified"]),
        ("csv_full",           paths["csv_full"]),
        ("json_full",          paths["json_full"]),
        ("expert_html",        paths["html"]),
        ("simple_html",        paths["html_plain"]),
    ]:
        fname = _os.path.basename(fpath)
        _save_report_safe(job_id, rtype, fname, counts)
    _cb("리포트 저장 완료", 98)

    print_summary(vuln_dicts)
    _cb("완료", 100)

    # 부하 모니터 종료 및 요약
    monitor.stop()
    load_summary = monitor.summary()
    if load_summary["load_detected"]:
        print(f"  [부하감지] 스캔 중 타겟 부하 감지 — "
              f"위험:{load_summary['danger_count']}회 "
              f"경고:{load_summary['warn_count']}회 "
              f"타임아웃:{load_summary['timeout_count']}회")

    print(f"[TIME] Pipeline 총 소요 시간: {_fmt(time.time() - pipe_start)}")
    print("[INFO] Pipeline completed")

