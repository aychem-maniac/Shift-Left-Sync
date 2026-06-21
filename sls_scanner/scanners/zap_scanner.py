# sls_scanner/scanners/zap_scanner.py

import os
import time
from datetime import datetime, timedelta, timezone
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

KST = timezone(timedelta(hours=9))
ACTIVE_SCAN_STALE_LIMIT = 600


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
        self.log_path = self._init_log_file()

    def _kst_now(self) -> datetime:
        return datetime.now(KST)

    def _init_log_file(self) -> str | None:
        try:
            log_dir = os.path.join("results", "logs")
            os.makedirs(log_dir, exist_ok=True)
            stamp = self._kst_now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(log_dir, f"zap_scan_{stamp}.log")
            with open(path, "a", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write("ZAP SCAN LOG\n")
                f.write("=" * 60 + "\n")
                f.write(f"Started At : {self._kst_now().strftime('%Y-%m-%d %H:%M:%S KST')}\n")
                f.write(f"Target     : {self.target}\n")
                f.write(f"Strength   : {self.strength}\n")
                f.write(f"Log File   : {path}\n\n")
            return path
        except Exception as e:
            print(f"  [ZAP] 로그 파일 생성 실패 (무시): {e}")
            return None

    def _write_log(self, level: str, message: str) -> None:
        if not self.log_path:
            return
        try:
            ts = self._kst_now().strftime("%Y-%m-%d %H:%M:%S KST")
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{level}] {message}\n")
        except Exception:
            pass

    def _write_section(self, title: str) -> None:
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write("\n" + "-" * 60 + "\n")
                f.write(f"{title}\n")
                f.write("-" * 60 + "\n")
        except Exception:
            pass

    def _poll(self, get_fn, label: str, interval: int = 3,
              timeout: int = 1800, cb_range: tuple = (0, 0),
              max_errors: int = 3, stale_limit: int | None = None) -> bool:
        """
        ZAP 내부 진행률 폴링.
        cb_range=(start_pct, end_pct) 로 전체 진행바에 매핑.
        timeout 초 초과 시 강제 중단 후 True 반환.
        """
        start_pct, end_pct = cb_range
        prev, elapsed = -1, 0
        error_count = 0
        stale_elapsed = 0
        while True:
            try:
                pct = int(get_fn())
                error_count = 0
            except Exception as e:
                msg = str(e)
                msg_lower = msg.lower()
                is_missing_scan = (
                    "DOES_NOT_EXIST" in msg
                    or "scanid" in msg_lower
                    or "scan id" in msg_lower
                )
                if is_missing_scan:
                    print(f"\n  [ZAP] {label} 중단 — scanId 없음: {e}")
                    self._write_log("ERROR", f"{label} stopped: scanId missing. error={e}")
                    self.progress_cb(f"ZAP {label} 실패 — 결과 수집 진행", end_pct)
                    return False

                error_count += 1
                print(f"\n  [ZAP] {label} 진행률 조회 경고 ({error_count}/{max_errors}): {e}")
                self._write_log("WARN", f"{label} status error ({error_count}/{max_errors}): {e}")
                if error_count >= max_errors:
                    print(f"  [ZAP] {label} 진행률 조회 실패 — 결과 수집 진행")
                    self._write_log("ERROR", f"{label} skipped: status errors exceeded {max_errors}")
                    self.progress_cb(f"ZAP {label} 진행률 조회 실패 — 결과 수집 진행", end_pct)
                    return False

                time.sleep(interval)
                elapsed += interval
                if elapsed >= timeout:
                    print(f"\n  [ZAP] {label} 타임아웃 ({timeout}s) → 강제 중단")
                    self._write_log("ERROR", f"{label} timeout after {timeout}s")
                    self.progress_cb(f"ZAP {label} 타임아웃 — 결과 수집 진행", end_pct)
                    return False
                continue

            if pct != prev:
                print(f"\r  [{label}] {pct}%", end="", flush=True)
                self._write_log("PROGRESS", f"{label} {pct}%")
                prev = pct
                stale_elapsed = 0
            else:
                stale_elapsed += interval

            # 전체 진행바 매핑
            if start_pct < end_pct:
                overall = start_pct + int(pct * (end_pct - start_pct) / 100)
                self.progress_cb(f"ZAP {label} {pct}%", overall)

            if pct >= 100:
                print()
                self._write_log("INFO", f"{label} completed")
                return True

            if stale_limit and stale_elapsed >= stale_limit:
                print(f"\n  [ZAP] {label} 진행률 정체 ({pct}%, {stale_elapsed}s) — 결과 수집 진행")
                self._write_log(
                    "ERROR",
                    f"{label} skipped: progress stale pct={pct}, stale={stale_elapsed}s",
                )
                self.progress_cb(f"ZAP {label} 정체 — 결과 수집 진행", end_pct)
                return False

            time.sleep(interval)
            elapsed += interval
            if elapsed >= timeout:
                print(f"\n  [ZAP] {label} 타임아웃 ({timeout}s) → 강제 중단")
                self._write_log("ERROR", f"{label} timeout after {timeout}s")
                self.progress_cb(f"ZAP {label} 타임아웃 — 결과 수집 진행", end_pct)
                return False

    def check_connection(self) -> bool:
        try:
            ver = self.zap.core.version
            print(f"  [ZAP] 연결 성공 — 버전: {ver}")
            self._write_log("INFO", f"ZAP version: {ver}")
            return True
        except Exception as e:
            print(f"  [ZAP] 연결 실패: {e}")
            self._write_log("ERROR", f"ZAP connection failed: {e}")
            return False

    def _clear_session(self):
        """ZAP 세션 초기화 (락 보유 상태에서만 호출 — 단독 실행 보장)"""
        session_name = f"SLS_{int(time.time())}"
        try:
            self.zap.core.new_session(name=session_name, overwrite=True)
            self.zap.core.delete_all_alerts()
            print(f"  [ZAP] 세션 초기화 완료: {session_name}")
            self._write_log("INFO", f"Session initialized: {session_name}")
        except Exception as e:
            print(f"  [ZAP] 세션 초기화 경고 (무시): {e}")
            self._write_log("WARN", f"Session init warning: {e}")

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
            self._write_log("INFO", f"Active Scan strength: {zap_str}")
        except Exception as e:
            print(f"  [ZAP] 강도 설정 경고 (무시): {e}")
            self._write_log("WARN", f"Active Scan strength warning: {e}")

    def _run_spider(self):
        self._write_section("SPIDER")
        print("  [ZAP] Traditional Spider 시작...")
        self._write_log("INFO", "Traditional Spider started")
        self.progress_cb("ZAP Spider 시작", 10)
        sid = self.zap.spider.scan(self.target, recurse=self.cfg["spider_recurse"])
        self._write_log("INFO", f"Spider ID: {sid}")
        self._poll(
            lambda: self.zap.spider.status(sid),
            label="Spider", interval=2,
            timeout=self.timeouts["spider"],
            cb_range=(10, 18),
        )
        urls = self.zap.spider.results(sid)
        print(f"  [ZAP] Spider 수집 URL: {len(urls)}건")
        self._write_log("INFO", f"Spider collected URLs: {len(urls)}")

    def _run_ajax_spider(self):
        self._write_section("AJAX SPIDER")
        print("  [ZAP] Ajax Spider 시작...")
        self._write_log("INFO", "Ajax Spider started")
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
                self._write_log("WARN", "Ajax Spider stopped: browser not connected")
                break
            if elapsed >= timeout:
                self.zap.ajaxSpider.stop()
                print(f"\n  [ZAP] Ajax Spider 타임아웃 → 강제 중지")
                self._write_log("WARN", f"Ajax Spider timeout after {timeout}s")
                break
        print()
        self.progress_cb("ZAP Ajax Spider 완료", 24)
        self._write_log("INFO", "Ajax Spider finished")

    def _run_active_scan(self):
        self._write_section("ACTIVE SCAN")
        print("  [ZAP] Active Scan 시작...")
        self._write_log("INFO", "Active Scan started")
        self.progress_cb("ZAP Active Scan 시작", 24)
        self._configure_ascan_strength()
        try:
            ascan_id = self.zap.ascan.scan(self.target, recurse=True)
        except Exception as e:
            print(f"  [ZAP] Active Scan 시작 실패 — 결과 수집 진행: {e}")
            self._write_log("ERROR", f"Active Scan start failed: {e}")
            self.progress_cb("ZAP Active Scan 시작 실패 — 결과 수집 진행", 35)
            return False

        ascan_id_str = str(ascan_id).strip()
        print(f"  [ZAP] Active Scan ID: {ascan_id_str}")
        self._write_log("INFO", f"Active Scan ID: {ascan_id_str}")
        if not ascan_id_str.isdigit():
            print(f"  [ZAP] Active Scan ID 비정상 — 결과 수집 진행: {ascan_id_str}")
            self._write_log("ERROR", f"Active Scan ID invalid: {ascan_id_str}")
            self.progress_cb("ZAP Active Scan ID 비정상 — 결과 수집 진행", 35)
            return False

        try:
            scans = self.zap.ascan.scans()
            scans_text = repr(scans)
            if len(scans_text) > 1200:
                scans_text = scans_text[:1200] + "...(truncated)"
            self._write_log("DEBUG", f"Active scans: {scans_text}")
        except Exception as e:
            self._write_log("WARN", f"Active scans list failed: {e}")

        ok = self._poll(
            lambda: self.zap.ascan.status(ascan_id),
            label="ActiveScan", interval=5,
            timeout=self.timeouts["ascan"],
            cb_range=(24, 35),
            stale_limit=ACTIVE_SCAN_STALE_LIMIT,
        )
        if not ok:
            print("  [ZAP] Active Scan 스킵 — 기존 탐지 결과로 진행")
            self._write_log("WARN", "Active Scan skipped; continue with collected alerts")
            return False
        return True

    def run(self) -> list:
        self._write_section("START")
        self._write_log("INFO", f"ZAP daemon: {ZAP_ADDRESS}:{ZAP_PORT}")
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
        self._write_section("RESULT")
        self._write_log("INFO", f"Raw ZAP alerts: {len(raw)}")
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
