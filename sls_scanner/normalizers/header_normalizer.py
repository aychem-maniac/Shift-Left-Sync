# sls_scanner/normalizers/header_normalizer.py

from sls_scanner.normalizers.owasp_normalizer import enrich_findings


def normalize_header_result(raw_header_result: dict) -> list[dict]:
    """
    Header Scan 결과를 공통 findings 형식으로 변환한다.
    """

    print("[INFO] Header normalization started")

    findings = []

    try:
        target = raw_header_result.get("target", "")
        missing_headers = raw_header_result.get("missing_headers", [])

        for idx, header in enumerate(missing_headers, start=1):
            findings.append({
                "id": f"HEADER-{idx:03d}",
                "source": "header_scan",
                "name": f"Missing Security Header: {header}",
                "severity": "Medium",
                "confidence": "High",
                "url": target,
                "description": f"{header} header is not set.",
                "evidence": f"Missing response header: {header}",
                "solution": f"Configure the web server or application to set the {header} header.",
                "reference": "https://owasp.org/www-project-secure-headers/"
            })

        findings = enrich_findings(findings)

        print(f"[INFO] Header normalization completed: {len(findings)} finding(s)")
        return findings

    except Exception as e:
        print(f"[ERROR] Header normalization failed: {e}")
        return []