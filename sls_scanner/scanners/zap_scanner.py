# sls_scanner/scanners/zap_scanner.py

import time
from zapv2 import ZAPv2

try:
    from config import ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY, SCAN_STRENGTH, ZAP_STRENGTH_MAP
except Exception:
    ZAP_ADDRESS      = "127.0.0.1"
    ZAP_PORT         = "8090"
    ZAP_API_KEY      = ""
    SCAN_STRENGTH    = {
        "low":    {"spider_recurse": False, "ajax_timeout": 30,  "ascan_strength": "LOW"},
        "medium": {"spider_recurse": True,  "ajax_timeout": 60,  "ascan_strength": "MEDIUM"},
        "high":   {"spider_recurse": True,  "ajax_timeout": 90,  "ascan_strength": "HIGH"},
    }
    ZAP_STRENGTH_MAP = {"low": 2, "medium": 3, "high": 4}

# 강도별 단계 타임아웃 (초)
SCAN_TIMEOUTS = {
    "low":    {"spider": 600,  "ascan": 1200},
    "medium": {"spider": 1200, "ascan": 2400},
    "high":   {"spider": 1800, "ascan": 5400},
}


class ZAPScanner:
    def __init__(self, target: str, strength: str = "medium", progress_cb=None):
        self.target      = target
        self.strength    = strength
        self.cfg         = SCAN_STRENGTH.get(strength, SCAN_STRENGTH["medium"])
        self.timeouts    = SCAN_TIMEOUTS.get(strength, SCAN_TIMEOUTS["medium"])
        self.progress_cb = progress_cb or (lambda msg, pct: None)
        proxy            = f"http://{ZAP_ADDRESS}:{ZAP_PORT}"
        self.zap         = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={"http": proxy, "https": proxy}
        )
        self.name = "OWASP ZAP"

    def _poll(self, get_fn, label: str, interval: int = 3,
              timeout: int = 1800, cb_range: tuple = (0, 0)) -> bool:
        """
        ZAP 내부 진행률 폴링.
        cb_range=(start_pct, end_pct) 로 전체 진행바에 매핑.
        timeout 초 초과 시 강제 중단 후 True 반환.
        """
        start_pct, end_pct = cb_range
        prev, elapsed = -1, 0
        while True:
            try:
                pct = int(get_fn())
            except Exception:
                pct = 0

            if pct != prev:
                print(f"\r  [{label}] {pct}%", end="", flush=True)
                prev = pct

            # 전체 진행바 매핑
            if start_pct < end_pct:
                overall = start_pct + int(pct * (end_pct - start_pct) / 100)
                self.progress_cb(f"ZAP {label} {pct}%", overall)

            if pct >= 100:
                print()
                return True

            time.sleep(interval)
            elapsed += interval
            if elapsed >= timeout:
                print(f"\n  [ZAP] {label} 타임아웃 ({timeout}s) → 강제 중단")
                self.progress_cb(f"ZAP {label} 타임아웃 — 결과 수집 진행", end_pct)
                return False

    def check_connection(self) -> bool:
        try:
            ver = self.zap.core.version
            print(f"  [ZAP] 연결 성공 — 버전: {ver}")
            return True
        except Exception as e:
            print(f"  [ZAP] 연결 실패: {e}")
            return False

    def _clear_session(self):
        """ZAP 세션 초기화 (락 보유 상태에서만 호출 — 단독 실행 보장)"""
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
        self.progress_cb("ZAP Spider 시작", 10)
        sid = self.zap.spider.scan(self.target, recurse=self.cfg["spider_recurse"])
        self._poll(
            lambda: self.zap.spider.status(sid),
            label="Spider", interval=2,
            timeout=self.timeouts["spider"],
            cb_range=(10, 18),
        )
        urls = self.zap.spider.results(sid)
        print(f"  [ZAP] Spider 수집 URL: {len(urls)}건")

    def _run_ajax_spider(self):
        print("  [ZAP] Ajax Spider 시작...")
        self.progress_cb("ZAP Ajax Spider 시작", 18)
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
            print(
                f"\r  [AjaxSpider] {self.zap.ajaxSpider.status} | "
                f"{elapsed}s | URL: {current_count}건",
                end="", flush=True,
            )
            # 시간 기반 진행률 (18% → 24%)
            time_pct = min(int(elapsed / timeout * 100), 99)
            overall  = 18 + int(time_pct * 6 / 100)
            self.progress_cb(f"ZAP Ajax Spider {elapsed}s/{timeout}s", overall)

            time.sleep(3)
            elapsed += 3
            if stall_count >= 15 and current_count == 0:
                self.zap.ajaxSpider.stop()
                print(f"\n  [ZAP] Ajax Spider — 브라우저 미연동")
                break
            if elapsed >= timeout:
                self.zap.ajaxSpider.stop()
                print(f"\n  [ZAP] Ajax Spider 타임아웃 → 강제 중지")
                break
        print()
        self.progress_cb("ZAP Ajax Spider 완료", 24)

    def _run_active_scan(self):
        print("  [ZAP] Active Scan 시작...")
        self.progress_cb("ZAP Active Scan 시작", 24)
        self._configure_ascan_strength()
        ascan_id = self.zap.ascan.scan(self.target, recurse=True)
        self._poll(
            lambda: self.zap.ascan.status(ascan_id),
            label="ActiveScan", interval=5,
            timeout=self.timeouts["ascan"],
            cb_range=(24, 35),
        )

    def run(self) -> list:
        if not self.check_connection():
            self.progress_cb("ZAP 연결 실패 — 결과 없음", 35)
            return []
        self.progress_cb("ZAP 세션 초기화 중", 9)
        self._clear_session()
        self._run_spider()
        self._run_ajax_spider()
        self._run_active_scan()
        raw = self.zap.core.alerts(baseurl=self.target)
        print(f"  [ZAP] 원시 탐지: {len(raw)}건")
        self.progress_cb(f"ZAP 완료 — {len(raw)}건 탐지", 35)
        return raw


def run_zap_scan(target: str, strength: str = "medium", progress_cb=None) -> dict:
    print(f"[INFO] ZAP scan started: {target}")
    print(f"[INFO] ZAP daemon: {ZAP_ADDRESS}:{ZAP_PORT}")
    try:
        scanner = ZAPScanner(target=target, strength=strength, progress_cb=progress_cb)
        raw     = scanner.run()
        return {"target": target, "raw_alerts": raw}
    except Exception as e:
        print(f"[ERROR] ZAP scan failed: {e}")
        return {"target": target, "raw_alerts": []}
