# sls_scanner/scanners/header_scanner.py

import requests

def run_header_scan(target: str) -> dict:
    print("[INFO] Header scan started")

    try:
        res = requests.get(target, timeout=5)

        headers = res.headers

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        missing = []

        for h in security_headers:
            if h not in headers:
                missing.append(h)

        print(f"[INFO] Header scan completed: {len(missing)} missing")

        return {
            "target": target,
            "missing_headers": missing
        }

    except Exception as e:
        print(f"[ERROR] Header scan failed: {e}")
        return {
            "target": target,
            "missing_headers": []
        }