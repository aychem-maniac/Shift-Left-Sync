# sls_scanner/core/pipeline.py

import time
import concurrent.futures
from datetime import datetime

from sls_scanner.core.target import validate_target
from sls_scanner.core.exceptions import InvalidTargetError

from sls_scanner.scanners.nmap_scanner    import run_nmap_scan
from sls_scanner.scanners.zap_scanner     import run_zap_scan
from sls_scanner.scanners.sqlmap_scanner  import run_sqlmap_scan
from sls_scanner.scanners.header_scanner  import run_header_scan
from sls_scanner.scanners.nikto_scanner   import NiktoScanner
from sls_scanner.scanners.nuclei_scanner  import NucleiScanner

from sls_scanner.normalizers.normalizer import (
    normalize_zap, normalize_nmap, normalize_sqlmap,
    normalize_header, normalize_nikto, normalize_nuclei,
    merge_and_sort, to_dict_list,
)
from sls_scanner.verifiers.poc_verifier import dispatch as poc_dispatch
from sls_scanner.reports.reporter import (
    make_paths, export_csv, export_json, export_html, export_html_plain, print_summary
)


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
        f_nmap   = ex.submit(run_nmap_scan,   target)
        f_sqlmap = ex.submit(run_sqlmap_scan,  target)
        f_header = ex.submit(run_header_scan,  target)
        f_nikto  = ex.submit(lambda: NiktoScanner(target=target, strength=strength).run())
        f_nuclei = ex.submit(lambda: NucleiScanner(target=target, strength=strength).run())

        # ZAP은 메인 스레드에서 실행 (GUI 연동 도구)
        raw_zap = run_zap_scan(target, strength=strength)

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

    # ── 3. PoC 검증 ───────────────────────────────────────────
    print("[INFO] PoC verification started")
    poc_start  = time.time()
    vuln_dicts = to_dict_list(vulns)
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