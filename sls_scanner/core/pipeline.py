# sls_scanner/core/pipeline.py

from datetime import datetime

from sls_scanner.core.target import validate_target
from sls_scanner.core.exceptions import InvalidTargetError

# ── 스캐너 ────────────────────────────────────────────────────
from sls_scanner.scanners.nmap_scanner    import run_nmap_scan
from sls_scanner.scanners.zap_scanner     import run_zap_scan
from sls_scanner.scanners.sqlmap_scanner  import run_sqlmap_scan
from sls_scanner.scanners.header_scanner  import run_header_scan
from sls_scanner.scanners.nikto_scanner   import NiktoScanner
from sls_scanner.scanners.nuclei_scanner  import NucleiScanner

# ── 정규화 ────────────────────────────────────────────────────
from sls_scanner.normalizers.normalizer import (
    normalize_zap, normalize_nmap, normalize_sqlmap,
    normalize_header, normalize_nikto, normalize_nuclei,
    merge_and_sort, to_dict_list,
)

# ── PoC 검증 ─────────────────────────────────────────────────
from sls_scanner.verifiers.poc_verifier import dispatch as poc_dispatch

# ── 리포트 ────────────────────────────────────────────────────
from sls_scanner.reports.reporter import (
    make_paths, export_csv, export_json, export_html, print_summary
)


def run_pipeline(target: str, strength: str = "medium") -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f"[INFO] Target:   {target}")
    print(f"[INFO] Strength: {strength}")

    if not validate_target(target):
        raise InvalidTargetError(f"Invalid target: {target}")

    print("[INFO] Pipeline started")

    # ── 1. 스캔 ───────────────────────────────────────────────
    raw_nmap    = run_nmap_scan(target)
    raw_zap     = run_zap_scan(target, strength=strength)
    raw_sqlmap  = run_sqlmap_scan(target)
    raw_header  = run_header_scan(target)
    raw_nikto   = NiktoScanner(target=target, strength=strength).run()
    raw_nuclei  = NucleiScanner(target=target, strength=strength).run()

    # ── 2. 정규화 ─────────────────────────────────────────────
    vulns = []
    vulns.extend(normalize_zap(raw_zap.get("raw_alerts", [])))
    vulns.extend(normalize_nmap(raw_nmap))
    vulns.extend(normalize_sqlmap(raw_sqlmap))
    vulns.extend(normalize_header(raw_header))
    vulns.extend(normalize_nikto(raw_nikto))
    vulns.extend(normalize_nuclei(raw_nuclei))

    vulns = merge_and_sort(vulns)
    print(f"[INFO] Normalized findings: {len(vulns)}건")

    # ── 3. PoC 검증 ───────────────────────────────────────────
    print("[INFO] PoC verification started")
    vuln_dicts = to_dict_list(vulns)
    for v in vuln_dicts:
        poc_dispatch(v)

    # ── 4. 리포트 생성 ────────────────────────────────────────
    paths = make_paths(target=target, timestamp=timestamp)

    confirmed   = [v for v in vuln_dicts if v.get("poc_status") == "CONFIRMED"]
    false_pos   = [v for v in vuln_dicts if v.get("poc_status") == "FALSE_POSITIVE"]
    unverified  = [v for v in vuln_dicts if v.get("poc_status") in ("UNVERIFIED", "PENDING")]

    # Nmap 포트 정보 (HTML용)
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
        target=target,
        vulns=vuln_dicts,
        port_info=port_info,
        path=paths["html"],
        timestamp=timestamp,
    )

    print_summary(vuln_dicts)
    print(f"[INFO] HTML report: {paths['html']}")
    print(f"[INFO] Pipeline completed")
