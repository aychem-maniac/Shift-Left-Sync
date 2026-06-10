# sls_scanner/utils/target_monitor.py
# 스캔 중 타겟 서버 응답시간을 주기적으로 측정,
# 과부하 감지 시 SSE warning 이벤트 전송

import threading
import time
import requests
requests.packages.urllib3.disable_warnings()

BASELINE_SAMPLES    = 3      # 기준값 측정 횟수
MONITOR_INTERVAL    = 30     # 모니터링 주기 (초)
DEGRADATION_WARN    = 3.0    # 기준 대비 경고 배수
DEGRADATION_DANGER  = 6.0    # 기준 대비 위험 배수
REQUEST_TIMEOUT     = 10     # HTTP 요청 타임아웃


class TargetHealthMonitor:
    """
    스캔 파이프라인 실행 중 타겟 응답시간 모니터링.

    사용법:
        monitor = TargetHealthMonitor(target, warn_cb=lambda msg: ...)
        monitor.start()
        try:
            run_scan(...)
        finally:
            monitor.stop()
    """

    def __init__(self, target: str, warn_cb=None):
        self.target    = target.rstrip("/")
        self.warn_cb   = warn_cb or (lambda msg: None)
        self.baseline  = None          # 초기 응답시간 (초)
        self._stop     = threading.Event()
        self._thread   = None
        self.warned    = False
        self.results: list[dict] = []  # 측정 이력 (최대 50건)

    # ── 내부 유틸 ─────────────────────────────────────────────

    def _get(self) -> float | None:
        """단일 HTTP GET 응답시간 측정. 실패 시 None."""
        try:
            t0 = time.time()
            requests.get(self.target, timeout=REQUEST_TIMEOUT,
                         verify=False, allow_redirects=True)
            return round(time.time() - t0, 3)
        except requests.Timeout:
            return None
        except Exception:
            return None

    def _measure_baseline(self) -> float | None:
        times = []
        for _ in range(BASELINE_SAMPLES):
            t = self._get()
            if t is not None:
                times.append(t)
            time.sleep(1)
        return round(sum(times) / len(times), 3) if times else None

    def _record(self, response_ms: int | None, status: str, message: str):
        self.results.append({
            "timestamp":   time.strftime("%H:%M:%S"),
            "response_ms": response_ms,
            "status":      status,
            "message":     message,
        })
        if len(self.results) > 50:
            self.results.pop(0)

    # ── 모니터링 루프 ──────────────────────────────────────────

    def _run(self):
        # 기준값 측정
        self.warn_cb("🔍 타겟 기준 응답시간 측정 중...")
        self.baseline = self._measure_baseline()

        if self.baseline is None:
            self.warn_cb("⚠️ 타겟 응답 없음 — 부하 모니터링 건너뜀")
            self._record(None, "unreachable", "기준값 측정 실패")
            return

        baseline_ms = int(self.baseline * 1000)
        self.warn_cb(f"📊 타겟 기준 응답시간: {baseline_ms}ms")
        self._record(baseline_ms, "ok", f"기준값: {baseline_ms}ms")

        while not self._stop.wait(timeout=MONITOR_INTERVAL):
            current = self._get()

            if current is None:
                msg = "⚠️ 타겟 응답 없음 — 스캔 부하로 인한 다운 가능"
                self.warn_cb(msg)
                self._record(None, "timeout", msg)
                self.warned = True
                continue

            current_ms = int(current * 1000)
            ratio = current / self.baseline

            if ratio >= DEGRADATION_DANGER:
                msg = (f"🔴 타겟 심각 지연: {current_ms}ms "
                       f"(기준 {baseline_ms}ms의 {ratio:.1f}배) — 스캔 중단 권장")
                self.warn_cb(msg)
                self._record(current_ms, "danger", msg)
                self.warned = True

            elif ratio >= DEGRADATION_WARN:
                msg = (f"🟠 타겟 응답 지연: {current_ms}ms "
                       f"(기준 {baseline_ms}ms의 {ratio:.1f}배) — 부하 감지")
                self.warn_cb(msg)
                self._record(current_ms, "warn", msg)
                self.warned = True

            else:
                if self.warned:
                    msg = f"✅ 타겟 응답 정상화: {current_ms}ms"
                    self.warn_cb(msg)
                    self.warned = False
                self._record(current_ms, "ok", f"{current_ms}ms")

    # ── 공개 인터페이스 ────────────────────────────────────────

    def start(self) -> "TargetHealthMonitor":
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name=f"health-{self.target[:20]}"
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def summary(self) -> dict:
        """최종 부하 리포트 반환."""
        danger = sum(1 for r in self.results if r["status"] == "danger")
        warn   = sum(1 for r in self.results if r["status"] == "warn")
        timeout_n = sum(1 for r in self.results if r["status"] == "timeout")
        ok_times  = [r["response_ms"] for r in self.results
                     if r["status"] == "ok" and r["response_ms"]]
        avg_ok    = int(sum(ok_times) / len(ok_times)) if ok_times else None

        return {
            "baseline_ms":  int(self.baseline * 1000) if self.baseline else None,
            "avg_ok_ms":    avg_ok,
            "danger_count": danger,
            "warn_count":   warn,
            "timeout_count": timeout_n,
            "checks":       len(self.results),
            "load_detected": danger > 0 or timeout_n > 0,
        }
