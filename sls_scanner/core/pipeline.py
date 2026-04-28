# sls_scanner/core/pipeline.py
from sls_scanner.normalizers.header_normalizer import normalize_header_result
from sls_scanner.evaluators.risk_evaluator import evaluate_risk, evaluate_port_risk
# 대상 URL/IP 검증 함수를 가져온다.
from sls_scanner.core.target import validate_target

# A05 연결
from sls_scanner.scanners.header_scanner import run_header_scan

# 공통 예외 클래스를 가져온다.
from sls_scanner.core.exceptions import InvalidTargetError

# Nmap, ZAP, SQLMap 스캔 함수를 가져온다.
from sls_scanner.scanners.nmap_scanner import run_nmap_scan
from sls_scanner.scanners.zap_scanner import run_zap_scan
from sls_scanner.scanners.sqlmap_scanner import run_sqlmap_scan

# 정규화 함수를 가져온다.
from sls_scanner.normalizers.nmap_normalizer import normalize_nmap_result
from sls_scanner.normalizers.zap_normalizer import normalize_zap_result
from sls_scanner.normalizers.sqlmap_normalizer import normalize_sqlmap_result

# 위험도 평가 함수를 가져온다.
from sls_scanner.evaluators.risk_evaluator import evaluate_risk

# 리포트 생성 함수를 가져온다.
from sls_scanner.reports.html_report import generate_html_report
from sls_scanner.reports.csv_report import generate_csv_report


def run_pipeline(target: str) -> None:
    # 사용자가 입력한 점검 대상을 출력한다.
    print(f"[INFO] Target: {target}")

    # 대상 URL/IP 형식이 올바른지 확인한다.
    if not validate_target(target):
        raise InvalidTargetError(f"Invalid target: {target}")

    # 전체 파이프라인 시작 메시지를 출력한다.
    print("[INFO] Pipeline started")

    # 1. Nmap 스캔을 실행한다.
    # 포트 상태, 서비스 이름, 제품명, 버전 정보를 수집한다.
    raw_nmap_result = run_nmap_scan(target)

    # 2. OWASP ZAP 스캔을 실행한다.
    # Spider와 Passive Scan을 통해 웹 취약점 Alert를 수집한다.
    raw_zap_result = run_zap_scan(target)

    # 3. SQLMap 스캔을 실행한다.
    # SQL Injection 가능성을 자동 점검한다.
    raw_sqlmap_result = run_sqlmap_scan(target)
    # A05 검사
    raw_header_result = run_header_scan(target)

    # 4. Nmap 원시 결과를 프로젝트 표준 포트 결과 형식으로 변환한다.
    port_results = normalize_nmap_result(raw_nmap_result)

    # 5. ZAP Alert 결과를 프로젝트 표준 취약점 결과 형식으로 변환한다.
    zap_findings = normalize_zap_result(raw_zap_result)
    evaluated_port_results = evaluate_port_risk(port_results)
    # 6. SQLMap 결과를 프로젝트 표준 취약점 결과 형식으로 변환한다.
    sqlmap_findings = normalize_sqlmap_result(raw_sqlmap_result)

    # 7. ZAP 결과와 SQLMap 결과를 하나의 취약점 목록으로 합친다.
    findings = zap_findings + sqlmap_findings

    header_findings = normalize_header_result(raw_header_result)

    findings = zap_findings + sqlmap_findings + header_findings
    # 8. 취약점 위험도를 평가한다.
    # severity 기준으로 risk_score와 is_critical 값을 추가한다.
    evaluated_findings = evaluate_risk(findings)

    # 9. HTML 리포트를 생성한다.
    html_report_path = generate_html_report(
        target=target,
        port_results=evaluated_port_results,
        findings=evaluated_findings
    )

    csv_report_path = generate_csv_report(
        findings=evaluated_findings,
        port_results=evaluated_port_results
    )

    # 생성된 리포트 경로를 출력한다.
    print(f"[INFO] HTML report path: {html_report_path}")
    print(f"[INFO] CSV report path: {csv_report_path}")

    # 전체 파이프라인 종료 메시지를 출력한다.
    print("[INFO] Pipeline completed")