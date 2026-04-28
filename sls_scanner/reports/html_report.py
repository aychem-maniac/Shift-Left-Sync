# sls_scanner/reports/html_report.py

import os
from datetime import datetime
from collections import Counter


def generate_html_report(
    target: str,
    port_results: list[dict],
    findings: list[dict]
) -> str:
    """
    Nmap 포트 결과와 취약점 결과를 HTML 리포트로 생성한다.
    """

    print("[INFO] HTML report generation started")

    # 리포트 저장 폴더를 생성한다.
    report_dir = "results/reports"
    os.makedirs(report_dir, exist_ok=True)

    report_path = os.path.join(report_dir, "report.html")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 위험도별 개수를 계산한다.
    severity_counts = Counter(
        finding.get("severity", "Unknown") for finding in findings
    )

    # 포트 결과 HTML 행을 생성한다.
    port_rows = ""

    if port_results:
        for port in port_results:
            port_rows += f"""
            <tr>
                <td>{port.get("host", "")}</td>
                <td>{port.get("port", "")}</td>
                <td>{port.get("protocol", "")}</td>
                <td>{port.get("service", "")}</td>
                <td>{port.get("state", "")}</td>
                <td>{port.get("product", "")}</td>
                <td>{port.get("version", "")}</td>
            </tr>
            """
    else:
        port_rows = """
        <tr>
            <td colspan="7">포트 스캔 결과가 없습니다.</td>
        </tr>
        """

    # 취약점 결과 HTML 행을 생성한다.
    finding_rows = ""

    if findings:
        for finding in findings:
            severity = finding.get("severity", "Unknown")
            severity_class = severity.lower()

            finding_rows += f"""
            <tr>
                <td>{finding.get("source", "")}</td>
                <td>{finding.get("name", "")}</td>
                <td class="severity-{severity_class}">{severity}</td>
                <td>{finding.get("confidence", "")}</td>
                <td>{finding.get("url", "")}</td>
                <td>{finding.get("description", "")}</td>
                <td>{finding.get("owasp_category", "Unmapped")}</td>
                <td>{finding.get("verification_status", "Need Manual Review")}</td>
                <td>{finding.get("verification_method", "Need Manual Review")}</td>
                <td>{finding.get("verification_note", "")}</td>
            </tr>
            """
    else:
        finding_rows = """
        <tr>
            <td colspan="10">취약점 결과가 없습니다.</td>
        </tr>
        """

    html_content = f"""
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
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Generated At:</strong> {generated_at}</p>
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

    with open(report_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"[INFO] HTML report generated: {report_path}")

    return report_path