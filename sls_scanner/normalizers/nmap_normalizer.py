# sls_scanner/normalizers/nmap_normalizer.py

"""
Nmap 원시 결과를 프로젝트 공통 포트 결과 형식으로 변환하는 모듈.

scanner에서 반환한 Nmap raw_result는 host -> protocol -> port 구조의 중첩 dict이므로,
리포트와 위험도 평가에서 사용하기 쉬운 list[dict] 형태로 정규화한다.
"""

from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    """
    포트 번호처럼 정수 변환이 필요한 값을 안전하게 int로 변환한다.

    Args:
        value (Any): 정수로 변환할 값
        default (int): 변환 실패 시 사용할 기본값

    Returns:
        int: 변환된 정수 값
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_nmap_result(raw_nmap_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Nmap 원시 결과를 포트 결과 목록으로 변환한다.

    Args:
        raw_nmap_result (dict[str, Any]): nmap_scanner.run_nmap_scan()에서 반환한 원시 결과

    Returns:
        list[dict[str, Any]]: 정규화된 포트 결과 목록
    """
    print("[INFO] Nmap normalization started")

    port_results: list[dict[str, Any]] = []

    try:
        raw_result = raw_nmap_result.get("raw_result", {})

        for host, host_data in raw_result.items():
            for protocol, ports in host_data.items():
                for port, port_data in ports.items():
                    port_results.append(
                        {
                            "host": host,
                            "port": _safe_int(port),
                            "protocol": protocol,
                            "service": port_data.get("name", ""),
                            "state": port_data.get("state", ""),
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", ""),
                        }
                    )

        print(f"[INFO] Nmap normalization completed: {len(port_results)} ports found")
        return port_results

    except Exception as e:
        print(f"[ERROR] Nmap normalization failed: {e}")
        return []