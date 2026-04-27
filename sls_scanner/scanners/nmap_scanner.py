# sls_scanner/scanners/nmap_scanner.py

from urllib.parse import urlparse
import nmap


def run_nmap_scan(target: str) -> dict:
    print(f"[INFO] Nmap scan started: {target}")
    try:
        parsed = urlparse(target)
        scan_target = parsed.hostname if parsed.hostname else target
        nm = nmap.PortScanner()
        # -F: 빠른 포트 스캔
        # -sV: 서비스/버전 정보 확인
        nm.scan(hosts=scan_target, arguments="-F -sV")
        raw_result = {}
        for host in nm.all_hosts():
            raw_result[host] = {}
            for protocol in nm[host].all_protocols():
                raw_result[host][protocol] = {}
                for port in nm[host][protocol].keys():
                    raw_result[host][protocol][port] = dict(nm[host][protocol][port])
        print(f"[INFO] Nmap scan completed: {len(raw_result)} host(s) found")
        return {
            "target": target,
            "scan_target": scan_target,
            "raw_result": raw_result
        }

    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        return {
            "target": target,
            "scan_target": target,
            "raw_result": {}
        }