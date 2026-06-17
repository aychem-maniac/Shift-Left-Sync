import hashlib
import json
import os

from database import log_security_event


WAF_AUDIT_LOG_PATH = os.getenv("WAF_AUDIT_LOG_PATH", "logs/waf/audit.log")


# ModSecurity 로그 필드는 누락될 수 있으므로 None을 빈 문자열로 맞춘다.
# ModSecurity 로그 필드는 누락될 수 있으므로 None을 빈 문자열로 통일한다.
def _text(value):
    if value is None:
        return ""
    return str(value)


# 관리자 화면에서 payload/reason이 과하게 길어지지 않도록 저장 길이를 제한한다.
# 관리자 화면에서 payload/reason이 과하게 길어지지 않도록 표시 길이를 제한한다.
def _clip(value, limit=500):
    return _text(value).strip()[:limit]


# ModSecurity severity는 숫자/문자열이 섞여 들어오므로 내부 등급으로 통일한다.
# ModSecurity severity 값은 숫자/문자가 섞일 수 있어 화면용 등급으로 정규화한다.
def _normalize_severity(value):
    raw = _text(value).strip().lower()
    if raw in {"critical", "high", "medium", "low"}:
        return raw
    if raw.isdigit():
        score = int(raw)
        if score <= 2:
            return "critical"
        if score == 3:
            return "high"
        if score == 4:
            return "medium"
        return "low"
    if raw == "error":
        return "high"
    if raw in {"warning", "warn"}:
        return "medium"
    return "low"


# 룰 메시지와 태그를 기준으로 관리자 화면용 이벤트 유형을 1차 분류한다.
# CRS 룰 전체를 완벽히 매핑하는 단계는 아니므로 모호한 항목은 rule_match로 남긴다.
# WAF rule_id와 메시지/태그를 기준으로 관리자 화면용 이벤트 유형을 분류한다.
# 920350/949110처럼 의미가 명확한 CRS 룰은 문자열 태그보다 rule_id를 우선한다.
def _event_type(message, tags, rule_id=None):
    rule_id = _text(rule_id).strip()
    if rule_id == "920350":
        return "host_header"
    if rule_id == "949110":
        return "anomaly_summary"

    blob = " ".join([_text(message), " ".join(_text(t) for t in tags)]).lower()
    if any(v in blob for v in ("attack-sqli", "sql injection", "sqli")):
        return "sqli"
    if any(v in blob for v in ("attack-xss", "cross site scripting", "xss")):
        return "xss"
    if any(v in blob for v in ("path traversal", "attack-lfi", "attack-rfi", "../")):
        return "path_traversal"
    if any(v in blob for v in ("command injection", "rce", "attack-rce", "shell")):
        return "command_injection"
    if any(v in blob for v in ("bot", "scanner", "automation")):
        return "bot"
    return "rule_match"


# audit.log는 단일 JSON, JSON 배열, 연속 JSON 객체 형식이 섞일 수 있어 모두 순차 파싱한다.
# audit.log가 단일 JSON, JSON 배열, 연속 JSON 객체 형식이어도 순차적으로 읽어낸다.
def _iter_json_entries(path):
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        content = fp.read().strip()

    if not content:
        return

    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            for item in parsed:
                yield item
        else:
            yield parsed
        return
    except json.JSONDecodeError:
        pass

    # Serial 로그처럼 JSON 객체가 연속으로 붙어 있는 경우를 처리한다.
    decoder = json.JSONDecoder()
    idx = 0
    length = len(content)
    while idx < length:
        while idx < length and content[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            item, next_idx = decoder.raw_decode(content, idx)
        except json.JSONDecodeError:
            line_end = content.find("\n", idx)
            idx = length if line_end == -1 else line_end + 1
            continue
        yield item
        idx = next_idx


# audit entry 안에서 실제 룰 매칭 메시지 목록을 꺼낸다.
# audit entry 안에서 실제 WAF 룰 매칭 메시지 목록을 꺼낸다.
def _messages(entry):
    tx = entry.get("transaction") if isinstance(entry, dict) else {}
    tx = tx if isinstance(tx, dict) else {}
    messages = entry.get("messages") if isinstance(entry, dict) else []
    if tx.get("messages"):
        messages = tx.get("messages")
    return messages if isinstance(messages, list) else []


# ModSecurity 로그 1건과 메시지 1개를 security_events 저장 형식으로 변환한다.
# ModSecurity 로그 1건과 메시지 1개를 security_events 저장 형식으로 변환한다.
def _build_event(entry, message, index):
    tx = entry.get("transaction") if isinstance(entry, dict) else {}
    tx = tx if isinstance(tx, dict) else {}
    request = tx.get("request") if isinstance(tx.get("request"), dict) else {}
    response = tx.get("response") if isinstance(tx.get("response"), dict) else {}
    details = message.get("details") if isinstance(message.get("details"), dict) else {}

    rule_id = _text(details.get("ruleId") or details.get("rule_id") or message.get("rule_id"))
    msg = _text(message.get("message") or details.get("message") or "WAF rule matched")
    tags = details.get("tags") or message.get("tags") or []
    if not isinstance(tags, list):
        tags = [tags]

    method = request.get("method") or tx.get("request_method")
    path = request.get("uri") or request.get("path") or tx.get("request_uri")
    client_ip = tx.get("client_ip") or tx.get("remote_addr") or entry.get("client_ip")
    status_code = response.get("http_code") or response.get("status") or tx.get("response_code")
    payload = details.get("data") or details.get("match") or request.get("body") or path
    unique_id = tx.get("unique_id") or entry.get("unique_id")
    raw = json.dumps({"transaction": tx, "message": message}, ensure_ascii=False, default=str)
    # unique_id가 없는 로그도 중복 저장을 피하도록 raw 내용 기반 event_id를 만든다.
    fallback = hashlib.sha1(f"{raw}:{index}".encode("utf-8", errors="ignore")).hexdigest()
    event_id = f"waf:{unique_id}:{rule_id}:{index}" if unique_id else f"waf:{fallback}"

    try:
        status_code = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status_code = None

    return {
        "source": "waf",
        "event_type": _event_type(msg, tags, rule_id),
        "severity": _normalize_severity(details.get("severity") or message.get("severity")),
        "action": "block" if status_code == 403 else "detect",
        "ip": _clip(client_ip, 128),
        "method": _clip(method, 16),
        "path": _clip(path, 500),
        "payload_sample": _clip(payload, 500),
        "reason": _clip(msg, 500),
        "rule_id": _clip(rule_id, 64),
        "status_code": status_code,
        "event_id": event_id,
        "raw_json": raw,
    }


# audit.log를 DB에 적재하고, high/critical 이벤트는 SOAR 대응 로그를 추가로 남긴다.
# audit.log를 DB에 적재하고, high/critical 이벤트는 SOAR 대응 로그를 추가로 남긴다.
def ingest_waf_audit_log(path=WAF_AUDIT_LOG_PATH):
    ingested = 0
    responded = 0

    for entry in _iter_json_entries(path) or []:
        for index, message in enumerate(_messages(entry)):
            if not isinstance(message, dict):
                continue
            event = _build_event(entry, message, index)
            if not log_security_event(**event):
                continue

            ingested += 1
            if event["severity"] in {"high", "critical"}:
                response_event = dict(event)
                response_event.update(
                    {
                        "source": "soar",
                        "action": "respond",
                        "reason": "High WAF event recorded, admin review required",
                        "event_id": f"soar:{event['event_id']}",
                    }
                )
                if log_security_event(**response_event):
                    responded += 1

    return {"ingested": ingested, "responded": responded, "path": path}
