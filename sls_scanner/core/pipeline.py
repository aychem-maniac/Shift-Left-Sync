# sls_scanner/core/pipeline.py

"""
전체 보안 스캔 파이프라인을 실행하는 모듈.

이 파일은 개별 스캐너를 직접 구현하지 않고,
각 스캐너 실행 → 결과 정규화 → 위험도 평가 → 리포트 생성 흐름을 조립하는 역할을 한다.
"""

from sls_scanner.core.exceptions import InvalidTargetError
from sls_scanner.core.target import validate_target

from sls_scanner.scanners.nmap_scanner import run_nmap_scan
from sls_scanner.scanners.zap_scanner import run_zap_scan
from sls_scanner.scanners.sqlmap_scanner import run_sqlmap_scan
from sls_scanner.scanners.header_scanner import run_header_scan

from sls_scanner.normalizers.nmap_normalizer import normalize_nmap_result
from sls_scanner.normalizers.zap_normalizer import normalize_zap_result
from sls_scanner.normalizers.sqlmap_normalizer import normalize_sqlmap_result
from sls_scanner.normalizers.header_normalizer import normalize_header_result

from sls_scanner.evaluators.risk_evaluator import evaluate_risk, evaluate_port_risk

from sls_scanner.reports.html_report import generate_html_report
from sls_scanner.reports.csv_report import generate_csv_report


def run_pipeline(target: str) -> None:
    """
    입력받은 타깃을 대상으로 전체 보안 스캔 파이프라인을 실행한다.

    실행 순서:
        1. 타깃 URL/IP 유효성 검사
        2. Nmap 포트 스캔
        3. ZAP 웹 취약점 스캔
        4. SQLMap SQL Injection 점검
        5. 보안 헤더 점검
        6. 각 스캐너 결과 정규화
        7. 위험도 평가
        8. HTML/CSV 리포트 생성

    Args:
        target (str): 사용자가 입력한 점검 대상 URL 또는 IP

    Raises:
        InvalidTargetError: 타깃 형식이 올바르지 않은 경우
    """
    print(f"[INFO] Target: {target}")

    if not validate_target(target):
        raise InvalidTargetError(f"Invalid target: {target}")

    print("[INFO] Pipeline started")

    # 1. 스캐너 실행
    # 각 스캐너는 원시(raw) 결과를 반환하고, 표준 형식 변환은 normalizer에서 처리한다.
    raw_nmap_result = run_nmap_scan(target)
    raw_zap_result = run_zap_scan(target)
    raw_sqlmap_result = run_sqlmap_scan(target)
    raw_header_result = run_header_scan(target)

    # 2. 결과 정규화
    # 서로 다른 도구의 출력 형식을 프로젝트 공통 데이터 구조로 변환한다.
    port_results = normalize_nmap_result(raw_nmap_result)
    zap_findings = normalize_zap_result(raw_zap_result)
    sqlmap_findings = normalize_sqlmap_result(raw_sqlmap_result)
    header_findings = normalize_header_result(raw_header_result)

    # 3. 결과 통합
    # 웹 취약점 계열 결과는 하나의 findings 목록으로 병합한다.
    findings = zap_findings + sqlmap_findings + header_findings

    # 4. 위험도 평가
    # 포트 결과와 취약점 결과에 severity/risk_score 기준을 적용한다.
    evaluated_port_results = evaluate_port_risk(port_results)
    evaluated_findings = evaluate_risk(findings)

    # 5. 리포트 생성
    html_report_path = generate_html_report(
        target=target,
        port_results=evaluated_port_results,
        findings=evaluated_findings,
    )

    csv_report_path = generate_csv_report(
        findings=evaluated_findings,
        port_results=evaluated_port_results,
    )

    print(f"[INFO] HTML report path: {html_report_path}")
    print(f"[INFO] CSV report path: {csv_report_path}")
    print("[INFO] Pipeline completed")