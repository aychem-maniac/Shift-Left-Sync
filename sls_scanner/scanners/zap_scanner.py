# sls_scanner/scanners/zap_scanner.py

import time
from zapv2 import ZAPv2

# .env 로드 (없으면 기본값)
try:
    from config import ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY, SCAN_STRENGTH, ZAP_STRENGTH_MAP
except Exception:
    ZAP_ADDRESS     = "127.0.0.1"
    ZAP_PORT        = "8090"
    ZAP_API_KEY     = ""
    SCAN_STRENGTH   = {
        "low":    {"spider_recurse": False, "ajax_timeout": 30,  "ascan_strength": "LOW"},
        "medium": {"spider_recurse": True,  "ajax_timeout": 60,  "ascan_strength": "MEDIUM"},
        "high":   {"spider_recurse": True,  "ajax_timeout": 90,  "ascan_strength": "HIGH"},
    }
    ZAP_STRENGTH_MAP = {"low": 2, "medium": 3, "high": 4}


class ZAPScanner:
    def __init__(self, target: str, strength: str = "medium"):
        self.target   = target
        self.strength = strength
        self.cfg      = SCAN_STRENGTH.get(strength, SCAN_STRENGTH["medium"])
        proxy         = f"http://{ZAP_ADDRESS}:{ZAP_PORT}"
        self.zap      = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={"http": proxy, "https": proxy}
        )
        self.name = "OWASP ZAP"

    def _poll(self, get_fn, label: str, interval: int = 3):
        prev = -1
        while True:
            try:
                pct = int(get_fn())
            except Exception:
                pct = 0
            if pct != prev:
                print(f"\r  [{label}] {pct}%", end="", flush=True)
                prev = pct
            if pct >= 100:
                break
            time.sleep(interval)
        print()

    def check_connection(self) -> bool:
        try:
            ver = self.zap.core.version
            print(f"  [ZAP] 연결 성공 — 버전: {ver}")
            return True
        except Exception as e:
            print(f"  [ZAP] 연결 실패: {e}")
            return False

    def _clear_session(self):
        """매 스캔마다 세션과 alert를 완전히 초기화 — 캐시 결과 반환 방지"""
        session_name = f"SLS_{int(time.time())}"
        try:
            self.zap.core.new_session(name=session_name, overwrite=True)
            self.zap.core.delete_all_alerts()
            print(f"  [ZAP] 세션 초기화 완료: {session_name}")
        except Exception as e:
            print(f"  [ZAP] 세션 초기화 경고 (무시): {e}")

    def _configure_ascan_strength(self):
        zap_str = {2: "LOW", 3: "MEDIUM", 4: "HIGH"}.get(
            ZAP_STRENGTH_MAP.get(self.strength, 3), "MEDIUM"
        )
        try:
            for scanner in self.zap.ascan.scanners():
                sid = scanner.get("id", "")
                if sid:
                    self.zap.ascan.set_scanner_attack_strength(
                        id=sid, attackstrength=zap_str
                    )
                    self.zap.ascan.set_scanner_alert_threshold(
                        id=sid, alertthreshold="LOW"
                    )
            print(f"  [ZAP] 스캐너 강도: {zap_str}")
        except Exception as e:
            print(f"  [ZAP] 강도 설정 경고 (무시): {e}")

    def _run_spider(self):
        print("  [ZAP] Traditional Spider 시작...")
        sid = self.zap.spider.scan(self.target, recurse=self.cfg["spider_recurse"])
        self._poll(lambda: self.zap.spider.status(sid), "Spider", 2)
        urls = self.zap.spider.results(sid)
        print(f"  [ZAP] Spider 수집 URL: {len(urls)}건")

    def _run_ajax_spider(self):
        print("  [ZAP] Ajax Spider 시작...")
        self.zap.ajaxSpider.scan(self.target)
        elapsed, timeout = 0, self.cfg["ajax_timeout"]
        prev_count, stall_count = 0, 0
        while str(self.zap.ajaxSpider.status) != "stopped":
            try:
                current_count = len(self.zap.ajaxSpider.results(start=0, count=9999))
            except Exception:
                current_count = 0
            stall_count = stall_count + 3 if current_count == prev_count else 0
            prev_count = current_count
            print(f"\r  [AjaxSpider] {self.zap.ajaxSpider.status} | {elapsed}s | URL: {current_count}건",
                  end="", flush=True)
            time.sleep(3)
            elapsed += 3
            if stall_count >= 15 and current_count == 0:
                self.zap.ajaxSpider.stop()
                print(f"\n  [ZAP] Ajax Spider — 브라우저 미연동 (ChromeDriver 확인 필요)")
                break
            if elapsed >= timeout:
                self.zap.ajaxSpider.stop()
                print(f"\n  [ZAP] Ajax Spider 타임아웃 → 강제 중지")
                break
        print()

    def _run_active_scan(self):
        print("  [ZAP] Active Scan 시작...")
        self._configure_ascan_strength()
        ascan_id = self.zap.ascan.scan(self.target, recurse=True)
        self._poll(lambda: self.zap.ascan.status(ascan_id), "ActiveScan", 5)

    def run(self) -> list:
        if not self.check_connection():
            return []
        self._clear_session()      # ← 핵심: 매 스캔 전 완전 초기화
        self._run_spider()
        self._run_ajax_spider()
        self._run_active_scan()
        raw = self.zap.core.alerts(baseurl=self.target)
        print(f"  [ZAP] 원시 탐지: {len(raw)}건")
        return raw


def run_zap_scan(target: str, strength: str = "medium") -> dict:
    print(f"[INFO] ZAP scan started: {target}")
    print(f"[INFO] ZAP daemon: {ZAP_ADDRESS}:{ZAP_PORT}")
    try:
        scanner = ZAPScanner(target=target, strength=strength)
        raw     = scanner.run()
        return {"target": target, "raw_alerts": raw}
    except Exception as e:
        print(f"[ERROR] ZAP scan failed: {e}")
        return {"target": target, "raw_alerts": []}