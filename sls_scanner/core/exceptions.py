# sls_scanner/core/exceptions.py


class InvalidTargetError(Exception):
    # 대상 URL 또는 IP가 잘못되었을 때 사용하는 예외다.
    pass


class ScannerExecutionError(Exception):
    # 스캐너 실행 중 문제가 생겼을 때 사용하는 예외다.
    pass


class ReportGenerationError(Exception):
    # 리포트 생성 중 문제가 생겼을 때 사용하는 예외다.
    pass