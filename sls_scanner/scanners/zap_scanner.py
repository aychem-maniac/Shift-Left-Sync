# sls_scanner/scanners/zap_scanner.py

import time
from zapv2 import ZAPv2


ZAP_ADDRESS = "127.0.0.1"
ZAP_PORT = "8080"
ZAP_API_KEY = ""


def run_zap_scan(target: str) -> dict:
    """
    OWASP ZAP API에 연결하여 대상 URL을 Spider 및 Passive Scan으로 점검한다.
    """

    print(f"[INFO] ZAP scan started: {target}")

    try:
        zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={
                "http": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
                "https": f"http://{ZAP_ADDRESS}:{ZAP_PORT}"
            }
        )

        # ZAP 연결 확인
        print(f"[INFO] Connected to ZAP version: {zap.core.version}")

        # 대상 URL 접근
        zap.urlopen(target)
        time.sleep(2)

        # Spider 실행
        print("[INFO] ZAP spider started")
        scan_id = zap.spider.scan(target)

        while int(zap.spider.status(scan_id)) < 100:
            progress = zap.spider.status(scan_id)
            print(f"[INFO] ZAP spider progress: {progress}%")
            time.sleep(2)

        print("[INFO] ZAP spider completed")

        # Active Scan 실행
        print("[INFO] ZAP active scan started")
        scan_id = zap.ascan.scan(target)

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"[INFO] ZAP active progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("[INFO] ZAP active scan completed")
        
        # Passive Scan 대기
        print("[INFO] ZAP passive scan waiting")
        while int(zap.pscan.records_to_scan) > 0:
            remaining = zap.pscan.records_to_scan
            print(f"[INFO] ZAP passive records remaining: {remaining}")
            time.sleep(2)

        print("[INFO] ZAP passive scan completed")

        # Alert 결과 수집
        alerts = zap.core.alerts(baseurl=target)

        print(f"[INFO] ZAP scan completed: {len(alerts)} alert(s) found")

        return {
            "target": target,
            "raw_alerts": alerts
        }

    except Exception as e:
        print(f"[ERROR] ZAP scan failed: {e}")

        return {
            "target": target,
            "raw_alerts": []
        }