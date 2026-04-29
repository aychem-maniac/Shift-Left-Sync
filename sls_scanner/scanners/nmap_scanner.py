# sls_scanner/scanners/nmap_scanner.py

"""
Nmap을 이용한 포트 및 서비스 버전 스캔 모듈.

이 모듈은 사용자가 입력한 URL/IP에서 실제 호스트명을 추출한 뒤,
Nmap을 실행하여 열린 포트와 서비스 정보를 수집한다.
"""

from typing import Any
from urllib.parse import urlparse

import nmap


NMAP_ARGUMENTS = "-F -sV"


def _extract_scan_target(target: str) -> str:
    """
    사용자가 입력한 URL 또는 IP에서 Nmap이 스캔할 실제 호스트명을 추출한다.

    예:
        - "http://scanme.nmap.org" -> "scanme.nmap.org"
        - "https://example.com/login" -> "example.com"
        - "192.168.0.10" -> "192.168.0.10"

    Args:
        target (str): 사용자가 입력한 점검 대상

    Returns:
        str: Nmap에 전달할 호스트명 또는 IP
    """
    parsed = urlparse(target)

    if parsed.hostname:
        return parsed.hostname

    return target


def _convert_nmap_result(nm: nmap.PortScanner) -> dict[str, dict[str, dict[int, dict[str, Any]]]]:
    """
    python-nmap의 PortScanner 결과를 일반 dict 형태로 변환한다.

    python-nmap 객체는 그대로 다루기 불편하므로,
    이후 normalizer에서 사용하기 쉬운 중첩 dict 형태로 정리한다.

    Args:
        nm (nmap.PortScanner): Nmap 스캔 결과 객체

    Returns:
        dict: host -> protocol -> port -> service_info 구조의 원시 결과
    """
    raw_result = {}

    for host in nm.all_hosts():
        raw_result[host] = {}

        for protocol in nm[host].all_protocols():
            raw_result[host][protocol] = {}

            for port, port_info in nm[host][protocol].items():
                raw_result[host][protocol][port] = dict(port_info)

    return raw_result


def run_nmap_scan(target: str) -> dict[str, Any]:
    """
    Nmap을 실행하여 대상의 포트 및 서비스 정보를 수집한다.

    Args:
        target (str): 사용자가 입력한 점검 대상 URL 또는 IP

    Returns:
        dict[str, Any]: Nmap 원시 스캔 결과
    """
    print(f"[INFO] Nmap scan started: {target}")

    scan_target = _extract_scan_target(target)

    try:
        nm = nmap.PortScanner()

        # -F  : 빠른 포트 스캔
        # -sV : 열린 포트의 서비스/버전 정보 확인
        nm.scan(hosts=scan_target, arguments=NMAP_ARGUMENTS)

        raw_result = _convert_nmap_result(nm)

        print(f"[INFO] Nmap scan completed: {len(raw_result)} host(s) found")

        return {
            "target": target,
            "scan_target": scan_target,
            "raw_result": raw_result,
        }

    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")

        return {
            "target": target,
            "scan_target": scan_target,
            "raw_result": {},
        }