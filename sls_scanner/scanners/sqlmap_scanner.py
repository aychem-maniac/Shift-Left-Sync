# sls_scanner/scanners/sqlmap_scanner.py

"""
SQLMap을 이용한 SQL Injection 점검 모듈.

대상 URL을 sqlmap CLI에 전달하여 SQL Injection 가능성을 자동 점검한다.
sqlmap은 Python 패키지가 아니라 별도 실행 파일이므로,
시스템 PATH에서 `sqlmap` 명령어가 실행 가능해야 한다.
"""

import os
import subprocess
from typing import Any
from urllib.parse import urlparse


SQLMAP_OUTPUT_DIR = "results/sqlmap"
SQLMAP_TIMEOUT_SECONDS = 600

SQLMAP_VULNERABLE_KEYWORDS = [
    "is vulnerable",
    "sql injection vulnerability has been detected",
    "injectable",
]


def _extract_host_name(target: str) -> str:
    """
    SQLMap 결과 디렉터리 식별용 호스트명을 추출한다.

    Args:
        target (str): 점검 대상 URL

    Returns:
        str: 포트 구분자를 파일/폴더명에 안전한 형태로 바꾼 호스트명
    """
    parsed = urlparse(target)

    if parsed.netloc:
        return parsed.netloc.replace(":", "_")

    return "unknown_host"


def _build_sqlmap_command(target: str, output_dir: str) -> list[str]:
    """
    SQLMap 실행 명령어를 생성한다.

    Args:
        target (str): 점검 대상 URL
        output_dir (str): SQLMap 결과 저장 디렉터리

    Returns:
        list[str]: subprocess.run에 전달할 명령어 리스트
    """
    return [
        "sqlmap",
        "-u",
        target,
        "--batch",
        "--level=1",
        "--risk=1",
        "--crawl=1",
        "--forms",
        "--smart",
        "--output-dir",
        output_dir,
    ]


def _detect_sql_injection(stdout: str) -> bool:
    """
    SQLMap 표준 출력 로그에서 SQL Injection 탐지 여부를 판단한다.

    Args:
        stdout (str): sqlmap 실행 표준 출력 로그

    Returns:
        bool: SQL Injection 가능성이 탐지되면 True
    """
    normalized_stdout = stdout.lower()

    return any(
        keyword in normalized_stdout
        for keyword in SQLMAP_VULNERABLE_KEYWORDS
    )


def _empty_result(
    *,
    target: str,
    host_name: str,
    return_code: int,
    stderr: str,
) -> dict[str, Any]:
    """
    SQLMap 실행 실패 또는 스킵 상황에서 반환할 기본 결과를 생성한다.

    Args:
        target (str): 점검 대상 URL
        host_name (str): 결과 식별용 호스트명
        return_code (int): 실행 결과 코드
        stderr (str): 오류 메시지

    Returns:
        dict[str, Any]: SQLMap 기본 결과
    """
    return {
        "target": target,
        "tool": "sqlmap",
        "host": host_name,
        "is_vulnerable": False,
        "return_code": return_code,
        "stdout": "",
        "stderr": stderr,
    }


def run_sqlmap_scan(target: str) -> dict[str, Any]:
    """
    SQLMap을 실행하여 대상 URL의 SQL Injection 가능성을 점검한다.

    Args:
        target (str): 점검 대상 URL

    Returns:
        dict[str, Any]: SQLMap 실행 결과 및 취약 여부
    """
    print(f"[INFO] SQLMap scan started: {target}")

    os.makedirs(SQLMAP_OUTPUT_DIR, exist_ok=True)

    host_name = _extract_host_name(target)
    command = _build_sqlmap_command(target, SQLMAP_OUTPUT_DIR)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=SQLMAP_TIMEOUT_SECONDS,
        )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""

        is_vulnerable = _detect_sql_injection(stdout)

        print(f"[INFO] SQLMap scan completed: vulnerable={is_vulnerable}")

        return {
            "target": target,
            "tool": "sqlmap",
            "host": host_name,
            "is_vulnerable": is_vulnerable,
            "return_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }

    except FileNotFoundError:
        message = "sqlmap command not found. Please install sqlmap or add it to PATH."
        print(f"[SKIP] {message}")

        return _empty_result(
            target=target,
            host_name=host_name,
            return_code=-1,
            stderr=message,
        )

    except subprocess.TimeoutExpired:
        message = f"SQLMap scan timeout after {SQLMAP_TIMEOUT_SECONDS}s"
        print(f"[WARN] {message}")

        return _empty_result(
            target=target,
            host_name=host_name,
            return_code=-1,
            stderr=message,
        )

    except Exception as e:
        print(f"[ERROR] SQLMap scan failed: {e}")

        return _empty_result(
            target=target,
            host_name=host_name,
            return_code=-1,
            stderr=str(e),
        )