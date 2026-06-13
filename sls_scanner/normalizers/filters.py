# sls_scanner/normalizers/filters.py
# 정규화 단계에서 취약점이 아닌 도구 로그성 결과를 제외하기 위한 필터 모음

ZAP_EXCLUDED_NAMES = {
    "Modern Web Application",
}

NIKTO_EXCLUDED_PREFIXES = (
    "No CGI Directories found",
    "Platform:",
    "Server: No banner retrieved",
    "Scan terminated:",
    "ERROR:",
)

NUCLEI_EXCLUDED_NAMES = {
    # 테스트용 애플리케이션 식별 템플릿은 실제 취약점 판정에서 제외한다.
    "OWASP Juice Shop",
}
