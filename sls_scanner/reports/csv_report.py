# sls_scanner/reports/csv_report.py

import os
import csv


def generate_csv_report(findings: list[dict], port_results: list[dict]) -> str:
    """
    포트 결과 + 취약점 결과를 CSV 파일로 저장한다.
    """

    print("[INFO] CSV report generation started")

    report_dir = "results/reports"
    os.makedirs(report_dir, exist_ok=True)

    report_path = os.path.join(report_dir, "report.csv")

    with open(report_path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)

        # 🔹 포트 결과 먼저 저장
        writer.writerow(["=== Nmap Port Results ==="])
        writer.writerow([
            "host",
            "port",
            "protocol",
            "service",
            "state",
            "product",
            "version",
            "risk_level",
            "risk_score",
            "risk_reason"
        ])

        if port_results:
            for port in port_results:
                writer.writerow([
                    port.get("host", ""),
                    port.get("port", ""),
                    port.get("protocol", ""),
                    port.get("service", ""),
                    port.get("state", ""),
                    port.get("product", ""),
                    port.get("version", ""),
                    port.get("risk_level", ""),
                    port.get("risk_score", ""),
                    port.get("risk_reason", "")
                ])
        else:
            writer.writerow(["No port results"])

        writer.writerow([])

        # 🔹 취약점 결과 저장
        writer.writerow(["=== Security Findings ==="])
        writer.writerow([
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
            "verification_note"
        ])

        if findings:
            for finding in findings:
                writer.writerow([
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
                    finding.get("verification_note", "")
                ])
        else:
            writer.writerow(["No findings"])

    print(f"[INFO] CSV report generated: {report_path}")

    return report_path