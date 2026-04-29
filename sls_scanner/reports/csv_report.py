# sls_scanner/reports/csv_report.py

"""
CSV 보안 스캔 리포트 생성 모듈.

Nmap 포트 스캔 결과와 ZAP/SQLMap/Header Scan 취약점 결과를
하나의 CSV 파일로 저장한다.
"""

import csv
import os
from typing import Any


REPORT_DIR = "results/reports"
REPORT_FILENAME = "report.csv"

PORT_SECTION_TITLE = "=== Nmap Port Results ==="
FINDING_SECTION_TITLE = "=== Security Findings ==="

PORT_COLUMNS = [
    "host",
    "port",
    "protocol",
    "service",
    "state",
    "product",
    "version",
    "risk_level",
    "risk_score",
    "risk_reason",
]

FINDING_COLUMNS = [
    "source",
    "name",
    "severity",
    "confidence",
    "url",
    "description",
    "risk_level",
    "risk_score",
    "is_critical",
    "owasp_category",
    "verification_status",
    "verification_method",
    "verification_note",
]


def _build_port_row(port: dict[str, Any]) -> list[Any]:
    """
    포트 결과 1개를 CSV row 형식으로 변환한다.

    Args:
        port (dict[str, Any]): 위험도 평가가 완료된 포트 결과

    Returns:
        list[Any]: CSV에 기록할 포트 row
    """
    return [
        port.get("host", ""),
        port.get("port", ""),
        port.get("protocol", ""),
        port.get("service", ""),
        port.get("state", ""),
        port.get("product", ""),
        port.get("version", ""),
        port.get("risk_level", ""),
        port.get("risk_score", ""),
        port.get("risk_reason", ""),
    ]


def _build_finding_row(finding: dict[str, Any]) -> list[Any]:
    """
    취약점 finding 1개를 CSV row 형식으로 변환한다.

    Args:
        finding (dict[str, Any]): 위험도 평가가 완료된 취약점 finding

    Returns:
        list[Any]: CSV에 기록할 finding row
    """
    return [
        finding.get("source", ""),
        finding.get("name", ""),
        finding.get("severity", ""),
        finding.get("confidence", ""),
        finding.get("url", ""),
        finding.get("description", ""),
        finding.get("risk_level", ""),
        finding.get("risk_score", ""),
        finding.get("is_critical", ""),
        finding.get("owasp_category", "Unmapped"),
        finding.get("verification_status", "Need Manual Review"),
        finding.get("verification_method", "Need Manual Review"),
        finding.get("verification_note", ""),
    ]


def _write_port_section(writer: csv.writer, port_results: list[dict[str, Any]]) -> None:
    """
    CSV 파일에 Nmap 포트 결과 섹션을 기록한다.

    Args:
        writer (csv.writer): CSV writer 객체
        port_results (list[dict[str, Any]]): 포트 결과 목록
    """
    writer.writerow([PORT_SECTION_TITLE])
    writer.writerow(PORT_COLUMNS)

    if not port_results:
        writer.writerow(["No port results"])
        return

    for port in port_results:
        writer.writerow(_build_port_row(port))


def _write_finding_section(writer: csv.writer, findings: list[dict[str, Any]]) -> None:
    """
    CSV 파일에 취약점 finding 섹션을 기록한다.

    Args:
        writer (csv.writer): CSV writer 객체
        findings (list[dict[str, Any]]): 취약점 결과 목록
    """
    writer.writerow([FINDING_SECTION_TITLE])
    writer.writerow(FINDING_COLUMNS)

    if not findings:
        writer.writerow(["No findings"])
        return

    for finding in findings:
        writer.writerow(_build_finding_row(finding))


def generate_csv_report(
    findings: list[dict[str, Any]],
    port_results: list[dict[str, Any]],
) -> str:
    """
    포트 결과와 취약점 결과를 CSV 파일로 저장한다.

    Args:
        findings (list[dict[str, Any]]): 위험도 평가가 완료된 취약점 finding 목록
        port_results (list[dict[str, Any]]): 위험도 평가가 완료된 포트 결과 목록

    Returns:
        str: 생성된 CSV 리포트 파일 경로
    """
    print("[INFO] CSV report generation started")

    os.makedirs(REPORT_DIR, exist_ok=True)

    report_path = os.path.join(REPORT_DIR, REPORT_FILENAME)

    with open(report_path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)

        _write_port_section(writer, port_results)
        writer.writerow([])
        _write_finding_section(writer, findings)

    print(f"[INFO] CSV report generated: {report_path}")

    return report_path