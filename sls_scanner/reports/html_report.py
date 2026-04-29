# sls_scanner/reports/html_report.py

"""
HTML 보안 스캔 리포트 생성 모듈.

Nmap 포트 스캔 결과와 ZAP/SQLMap/Header Scan 취약점 결과를
하나의 HTML 파일로 저장한다.
"""

import os
from collections import Counter
from datetime import datetime
from html import escape
from typing import Any


REPORT_DIR = "results/reports"
REPORT_FILENAME = "report.html"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def _safe_html(value: Any) -> str:
    """
    HTML에 출력할 값을 안전한 문자열로 변환한다.

    취약점 설명이나 URL에 HTML 특수문자가 포함될 수 있으므로,
    escape 처리를 통해 HTML 구조가 깨지지 않도록 한다.

    Args:
        value (Any): HTML에 출력할 값

    Returns:
        str: HTML escape 처리된 문자열
    """
    return escape(str(value or ""))


def _get_severity_class(severity: str) -> str:
    """
    severity 값을 CSS class 이름에 사용할 수 있는 형태로 변환한다.

    Args:
        severity (str): 취약점 severity 값

    Returns:
        str: severity CSS class suffix
    """
    return str(severity or "Unknown").strip().lower()


def _count_severity(findings: list[dict[str, Any]]) -> Counter:
    """
    findings 목록에서 severity별 개수를 계산한다.

    Args:
        findings (list[dict[str, Any]]): 취약점 finding 목록

    Returns:
        Counter: severity별 개수
    """
    return Counter(
        finding.get("severity", "Unknown")
        for finding in findings
    )


def _build_port_rows(port_results: list[dict[str, Any]]) -> str:
    """
    Nmap 포트 결과를 HTML table row 문자열로 변환한다.

    Args:
        port_results (list[dict[str, Any]]): 위험도 평가가 완료된 포트 결과 목록

    Returns:
        str: 포트 결과 table row HTML
    """
    if not port_results:
        return """
        <tr>
            <td colspan="10">포트 스캔 결과가 없습니다.</td>
        </tr>
        """

    rows = []

    for port in port_results:
        rows.append(
            f"""
            <tr>
                <td>{_safe_html(port.get("host"))}</td>
                <td>{_safe_html(port.get("port"))}</td>
                <td>{_safe_html(port.get("protocol"))}</td>
                <td>{_safe_html(port.get("service"))}</td>
                <td>{_safe_html(port.get("state"))}</td>
                <td>{_safe_html(port.get("product"))}</td>
                <td>{_safe_html(port.get("version"))}</td>
                <td>{_safe_html(port.get("risk_level"))}</td>
                <td>{_safe_html(port.get("risk_score"))}</td>
                <td>{_safe_html(port.get("risk_reason"))}</td>
            </tr>
            """
        )

    return "\n".join(rows)


def _build_finding_rows(findings: list[dict[str, Any]]) -> str:
    """
    취약점 finding 결과를 HTML table row 문자열로 변환한다.

    Args:
        findings (list[dict[str, Any]]): 위험도 평가가 완료된 취약점 finding 목록

    Returns:
        str: 취약점 결과 table row HTML
    """
    if not findings:
        return """
        <tr>
            <td colspan="10">취약점 결과가 없습니다.</td>
        </tr>
        """

    rows = []

    for finding in findings:
        severity = finding.get("severity", "Unknown")
        severity_class = _get_severity_class(severity)

        rows.append(
            f"""
            <tr>
                <td>{_safe_html(finding.get("source"))}</td>
                <td>{_safe_html(finding.get("name"))}</td>
                <td class="severity-{_safe_html(severity_class)}">{_safe_html(severity)}</td>
                <td>{_safe_html(finding.get("confidence"))}</td>
                <td>{_safe_html(finding.get("url"))}</td>
                <td>{_safe_html(finding.get("description"))}</td>
                <td>{_safe_html(finding.get("owasp_category", "Unmapped"))}</td>
                <td>{_safe_html(finding.get("verification_status", "Need Manual Review"))}</td>
                <td>{_safe_html(finding.get("verification_method", "Need Manual Review"))}</td>
                <td>{_safe_html(finding.get("verification_note"))}</td>
            </tr>
            """
        )

    return "\n".join(rows)


def _build_html_content(
    *,
    target: str,
    generated_at: str,
    port_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    severity_counts: Counter,
    port_rows: str,
    finding_rows: str,
) -> str:
    """
    HTML 리포트 전체 문서를 생성한다.

    Args:
        target (str): 점검 대상
        generated_at (str): 리포트 생성 시각
        port_results (list[dict[str, Any]]): 포트 결과 목록
        findings (list[dict[str, Any]]): 취약점 결과 목록
        severity_counts (Counter): severity별 취약점 개수
        port_rows (str): 포트 결과 table row HTML
        finding_rows (str): 취약점 결과 table row HTML

    Returns:
        str: 전체 HTML 문서 문자열
    """
    return f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Shift-Left-Sync Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background-color: #f5f5f5;
        }}

        h1, h2 {{
            color: #222;
        }}

        .summary {{
            background-color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-top: 15px;
        }}

        .summary-card {{
            background-color: #fafafa;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 10px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            margin-bottom: 30px;
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            font-size: 14px;
            vertical-align: top;
        }}

        th {{
            background-color: #222;
            color: white;
        }}

        .severity-critical {{
            color: white;
            background-color: #8b0000;
            font-weight: bold;
            text-align: center;
        }}

        .severity-high {{
            color: white;
            background-color: #d9534f;
            font-weight: bold;
            text-align: center;
        }}

        .severity-medium {{
            color: white;
            background-color: #f0ad4e;
            font-weight: bold;
            text-align: center;
        }}

        .severity-low {{
            color: white;
            background-color: #5bc0de;
            font-weight: bold;
            text-align: center;
        }}

        .severity-info,
        .severity-informational {{
            color: white;
            background-color: #5cb85c;
            font-weight: bold;
            text-align: center;
        }}

        .severity-unknown {{
            color: white;
            background-color: #777;
            font-weight: bold;
            text-align: center;
        }}
    </style>
</head>
<body>
    <h1>Shift-Left-Sync Scan Report</h1>

    <div class="summary">
        <p><strong>Target:</strong> {_safe_html(target)}</p>
        <p><strong>Generated At:</strong> {_safe_html(generated_at)}</p>
        <p><strong>Open Port Results:</strong> {len(port_results)}</p>
        <p><strong>Finding Results:</strong> {len(findings)}</p>

        <div class="summary-grid">
            <div class="summary-card">
                <strong>Critical</strong><br>
                {severity_counts.get("Critical", 0)}
            </div>
            <div class="summary-card">
                <strong>High</strong><br>
                {severity_counts.get("High", 0)}
            </div>
            <div class="summary-card">
                <strong>Medium</strong><br>
                {severity_counts.get("Medium", 0)}
            </div>
            <div class="summary-card">
                <strong>Low / Info</strong><br>
                {severity_counts.get("Low", 0)} / {severity_counts.get("Info", 0) + severity_counts.get("Informational", 0)}
            </div>
        </div>
    </div>

    <h2>Nmap Port Scan Results</h2>
    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>State</th>
                <th>Product</th>
                <th>Version</th>
                <th>Risk Level</th>
                <th>Risk Score</th>
                <th>Risk Reason</th>
            </tr>
        </thead>
        <tbody>
            {port_rows}
        </tbody>
    </table>

    <h2>Security Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Source</th>
                <th>Name</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>URL</th>
                <th>Description</th>
                <th>OWASP Top 10</th>
                <th>Verification Status</th>
                <th>Verification Method</th>
                <th>Verification Note</th>
            </tr>
        </thead>
        <tbody>
            {finding_rows}
        </tbody>
    </table>
</body>
</html>
"""


def generate_html_report(
    target: str,
    port_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> str:
    """
    Nmap 포트 결과와 취약점 결과를 HTML 리포트로 생성한다.

    Args:
        target (str): 점검 대상 URL 또는 IP
        port_results (list[dict[str, Any]]): 위험도 평가가 완료된 포트 결과 목록
        findings (list[dict[str, Any]]): 위험도 평가가 완료된 취약점 finding 목록

    Returns:
        str: 생성된 HTML 리포트 파일 경로
    """
    print("[INFO] HTML report generation started")

    os.makedirs(REPORT_DIR, exist_ok=True)

    report_path = os.path.join(REPORT_DIR, REPORT_FILENAME)
    generated_at = datetime.now().strftime(DATETIME_FORMAT)

    severity_counts = _count_severity(findings)
    port_rows = _build_port_rows(port_results)
    finding_rows = _build_finding_rows(findings)

    html_content = _build_html_content(
        target=target,
        generated_at=generated_at,
        port_results=port_results,
        findings=findings,
        severity_counts=severity_counts,
        port_rows=port_rows,
        finding_rows=finding_rows,
    )

    with open(report_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"[INFO] HTML report generated: {report_path}")

    return report_path