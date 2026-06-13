from pathlib import Path


PAYLOAD_DIR = Path(__file__).resolve().parents[1] / "payloads"
PAYLOADS_ALL_THE_THINGS_DIR = PAYLOAD_DIR / "payloadsallthethings"

# PayloadsAllTheThings는 Python 패키지로 import하지 않는다.
# PoC 검증에 필요한 일부 txt payload 파일만 로컬에서 읽는다.
PAYLOAD_FILES = {
    "xss": PAYLOADS_ALL_THE_THINGS_DIR / "xss" / "xss.txt",
    "sqli_error": PAYLOADS_ALL_THE_THINGS_DIR / "sqli" / "sqli_error.txt",
    "sqli_time": PAYLOADS_ALL_THE_THINGS_DIR / "sqli" / "sqli_time.txt",
    "cors": PAYLOADS_ALL_THE_THINGS_DIR / "cors" / "cors_origins.txt",
}


def load_payloads(category: str, canary: str = "") -> list[str]:
    path = PAYLOAD_FILES.get(category)
    if path is None:
        return []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    payloads = []
    seen = set()
    for line in lines:
        value = line.strip()

        # 출처 주석은 파일에 남겨두되, 실제 요청 payload로는 보내지 않는다.
        if (
            not value
            or value.startswith("#")
            or value.startswith("//")
            or value.startswith("<!--")
        ):
            continue

        if canary:
            value = value.replace("{{CANARY}}", canary)
            value = value.replace("INJECTX", canary)
            value = value.replace("alert(1)", f"alert('{canary}')")
            value = value.replace("prompt(1)", f"prompt('{canary}')")

        if value in seen:
            continue
        seen.add(value)
        payloads.append(value)

    return payloads
