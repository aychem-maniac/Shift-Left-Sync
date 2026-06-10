"""
Scanner Registry

개별 스캐너 실행 함수를 한 곳에서 관리합니다.

목표:
- pipeline.py가 개별 scanner 모듈에 직접 의존하지 않도록 분리
- 스캐너 추가/교체 시 registry만 수정하도록 구조화
- 모든 스캐너를 동일한 인터페이스로 실행

표준 호출 형태:
    run_scanner(name, target, strength="medium", progress_cb=None)
"""

from typing import Callable, Dict, Any, Optional

from sls_scanner.scanners.nmap_scanner import run_nmap_scan
from sls_scanner.scanners.sqlmap_scanner import run_sqlmap_scan
from sls_scanner.scanners.header_scanner import run_header_scan
from sls_scanner.scanners.nikto_scanner import NiktoScanner
from sls_scanner.scanners.nuclei_scanner import NucleiScanner
from sls_scanner.scanners.zap_scanner import run_zap_scan


ScannerCallable = Callable[..., Any]


def _run_nmap(target: str, strength: str = "medium", progress_cb: Optional[Callable] = None) -> dict:
    return run_nmap_scan(target)


def _run_sqlmap(target: str, strength: str = "medium", progress_cb: Optional[Callable] = None) -> Any:
    return run_sqlmap_scan(target)


def _run_header(target: str, strength: str = "medium", progress_cb: Optional[Callable] = None) -> Any:
    return run_header_scan(target)


def _run_nikto(target: str, strength: str = "medium", progress_cb: Optional[Callable] = None) -> list:
    return NiktoScanner(target=target, strength=strength).run()


def _run_nuclei(target: str, strength: str = "medium", progress_cb: Optional[Callable] = None) -> list:
    return NucleiScanner(target=target, strength=strength).run()


def _run_zap(target: str, strength: str = "medium", progress_cb: Optional[Callable] = None) -> dict:
    return run_zap_scan(target, strength=strength, progress_cb=progress_cb)


SCANNER_REGISTRY: Dict[str, ScannerCallable] = {
    "nmap": _run_nmap,
    "sqlmap": _run_sqlmap,
    "header": _run_header,
    "nikto": _run_nikto,
    "nuclei": _run_nuclei,
    "zap": _run_zap,
}


NON_ZAP_SCANNERS = ["nmap", "sqlmap", "header", "nikto", "nuclei"]
ZAP_SCANNER = "zap"


def get_scanner(name: str) -> ScannerCallable:
    try:
        return SCANNER_REGISTRY[name]
    except KeyError:
        available = ", ".join(sorted(SCANNER_REGISTRY.keys()))
        raise KeyError(f"Unknown scanner: {name}. Available scanners: {available}")


def run_scanner(
    name: str,
    target: str,
    strength: str = "medium",
    progress_cb: Optional[Callable] = None,
) -> Any:
    scanner = get_scanner(name)
    return scanner(target=target, strength=strength, progress_cb=progress_cb)


def list_scanners() -> list[str]:
    return sorted(SCANNER_REGISTRY.keys())


def list_non_zap_scanners() -> list[str]:
    return list(NON_ZAP_SCANNERS)
