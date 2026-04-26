# sls_scanner/core/pipeline.py

# 대상 URL/IP 검증 함수를 가져온다.
from sls_scanner.core.target import validate_target

# 공통 예외 클래스를 가져온다.
from sls_scanner.core.exceptions import InvalidTargetError

# Nmap, ZAP 스캔 함수를 가져온다.
from sls_scanner.scanners.nmap_scanner import run_nmap_scan
from sls_scanner.scanners.zap_scanner import run_zap_scan

# 정규화 함수를 가져온다.
from sls_scanner.normalizers.nmap_normalizer import normalize_nmap_result
from sls_scanner.normalizers.zap_normalizer import normalize_zap_result

# 위험도 평가 함수를 가져온다.
from sls_scanner.evaluators.risk_evaluator import evaluate_risk

# 리포트 생성 함수를 가져온다.
from sls_scanner.reports.html_report import generate_html_report
from sls_scanner.reports.csv_report import generate_csv_report


def run_pipeline(target: str) -> None:
    # 사용자가 입력한 대상을 출력한다.
    print(f"[INFO] Target: {target}")

    # 대상 URL/IP 형식이 올바른지 확인한다.
    if not validate_target(target):
        raise InvalidTargetError(f"Invalid target: {target}")

    # 전체 파이프라인 시작 메시지를 출력한다.
    print("[INFO] Pipeline started")

    # Nmap 스캔을 실행한다.
    raw_nmap_result = run_nmap_scan(target)

    # ZAP 스캔을 실행한다.
    raw_zap_result = run_zap_scan(target)

    # Nmap 결과를 공통 형식으로 변환한다.
    port_results = normalize_nmap_result(raw_nmap_result)

    # ZAP 결과를 공통 형식으로 변환한다.
    findings = normalize_zap_result(raw_zap_result)

    # 취약점 위험도를 평가한다.
    evaluated_findings = evaluate_risk(findings)

    # HTML 리포트를 생성한다.
    html_report_path = generate_html_report(
        target=target,
        port_results=port_results,
        findings=evaluated_findings
    )

    # CSV 리포트를 생성한다.
    csv_report_path = generate_csv_report(evaluated_findings)

    # 생성된 리포트 경로를 출력한다.
    print(f"[INFO] HTML report path: {html_report_path}")
    print(f"[INFO] CSV report path: {csv_report_path}")

    # 전체 파이프라인 종료 메시지를 출력한다.
    print("[INFO] Pipeline completed")