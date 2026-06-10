# sls_scanner/normalizers/zap_normalizer.py

def normalize_zap_result(raw_zap_result: dict) -> list[dict]:
    """
    ZAP alert 결과를 공통 취약점 형식으로 변환한다.
    """

    print("[INFO] ZAP normalization started")

    findings = []

    try:
        raw_alerts = raw_zap_result.get("raw_alerts", [])

        for idx, alert in enumerate(raw_alerts, start=1):
            findings.append({
                "id": f"ZAP-{idx:03d}",
                "source": "zap",
                "name": alert.get("name", ""),
                "severity": alert.get("risk", "Unknown"),
                "confidence": alert.get("confidence", "Unknown"),
                "url": alert.get("url", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", "")
            })

        print(f"[INFO] ZAP normalization completed: {len(findings)} finding(s) found")

        return findings

    except Exception as e:
        print(f"[ERROR] ZAP normalization failed: {e}")
        return []