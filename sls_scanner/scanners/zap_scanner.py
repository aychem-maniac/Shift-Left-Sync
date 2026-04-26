# sls_scanner/scanners/zap_scanner.py


def run_zap_scan(target: str) -> dict:
    # 나중에 실제 OWASP ZAP 스캔 코드가 들어갈 자리다.
    print("[INFO] ZAP scan placeholder")

    # 지금은 더미 결과를 반환한다.
    return {
        "target": target,
        "raw_alerts": []
    }