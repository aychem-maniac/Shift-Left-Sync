# sls_scanner/scanners/sqlmap_scanner.py

import os
import subprocess
from urllib.parse import urlparse


def run_sqlmap_scan(target: str) -> dict:
    """
    sqlmap을 실행하여 SQL Injection 가능성을 점검한다.
    """

    print(f"[INFO] SQLMap scan started: {target}")

    output_dir = "results/sqlmap"
    os.makedirs(output_dir, exist_ok=True)

    try:
        parsed = urlparse(target)
        host_name = parsed.netloc.replace(":", "_") if parsed.netloc else "unknown_host"

        command = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--level=1",
            "--risk=1",
            "--crawl=1",
            "--forms",
            "--smart",
            "--output-dir", output_dir
        ]

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        stdout = completed.stdout
        stderr = completed.stderr

        is_vulnerable = (
            "is vulnerable" in stdout.lower()
            or "sql injection vulnerability has been detected" in stdout.lower()
            or "parameter" in stdout.lower() and "injectable" in stdout.lower()
        )

        print(f"[INFO] SQLMap scan completed: vulnerable={is_vulnerable}")

        return {
            "target": target,
            "tool": "sqlmap",
            "host": host_name,
            "is_vulnerable": is_vulnerable,
            "return_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr
        }

    except Exception as e:
        print(f"[ERROR] SQLMap scan failed: {e}")

        return {
            "target": target,
            "tool": "sqlmap",
            "host": "",
            "is_vulnerable": False,
            "return_code": -1,
            "stdout": "",
            "stderr": str(e)
        }