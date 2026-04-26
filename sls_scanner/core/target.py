# sls_scanner/core/target.py

import ipaddress


def validate_target(target: str) -> bool:
    # 입력값이 비어 있는지 확인한다.
    if not target:
        return False

    # URL 형식인지 확인한다.
    if target.startswith("http://") or target.startswith("https://"):
        return True

    # IP 주소 형식인지 확인한다.
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False