"""
IDS/IPS detection rules

SLS 서비스로 들어오는 HTTP 요청에서 공격 의심 패턴을 탐지하기 위한 룰입니다.
초기 버전은 웹 공격에서 자주 보이는 문자열/정규식 기반 탐지로 구성합니다.
"""

from dataclasses import dataclass
import re
from typing import Pattern


@dataclass(frozen=True)
class IDSRule:
    name: str
    attack_type: str
    severity: str
    pattern: Pattern[str]
    description: str


def _rule(
    name: str,
    attack_type: str,
    severity: str,
    regex: str,
    description: str,
) -> IDSRule:
    return IDSRule(
        name=name,
        attack_type=attack_type,
        severity=severity,
        pattern=re.compile(regex, re.IGNORECASE),
        description=description,
    )


IDS_RULES: list[IDSRule] = [
    # SQL Injection
    _rule(
        "sqli_or_true",
        "SQL Injection",
        "high",
        r"('|%27)?\s*(or|and)\s+('|%27)?[a-zA-Z0-9_]+('|%27)?\s*=\s*('|%27)?[a-zA-Z0-9_]+('|%27)?",
        "OR/AND true 조건을 이용한 SQL Injection 의심 패턴",
    ),
    _rule(
        "sqli_union_select",
        "SQL Injection",
        "high",
        r"(union\s+select|union%20select)",
        "UNION SELECT 기반 SQL Injection 의심 패턴",
    ),
    _rule(
        "sqli_comment",
        "SQL Injection",
        "medium",
        r"(--|#|/\*)",
        "SQL 주석을 이용한 Injection 의심 패턴",
    ),
    _rule(
        "sqli_time_based",
        "SQL Injection",
        "high",
        r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
        "Time-based SQL Injection 의심 패턴",
    ),
    _rule(
        "sqli_information_schema",
        "SQL Injection",
        "high",
        r"information_schema",
        "DB 메타데이터 접근 의심 패턴",
    ),

    # XSS
    _rule(
        "xss_script_tag",
        "XSS",
        "high",
        r"(<|%3c)\s*script",
        "script 태그 기반 XSS 의심 패턴",
    ),
    _rule(
        "xss_javascript_uri",
        "XSS",
        "medium",
        r"javascript\s*:",
        "javascript URI 기반 XSS 의심 패턴",
    ),
    _rule(
        "xss_event_handler",
        "XSS",
        "medium",
        r"on(error|load|click|mouseover)\s*=",
        "HTML 이벤트 핸들러 기반 XSS 의심 패턴",
    ),
    _rule(
        "xss_alert",
        "XSS",
        "low",
        r"alert\s*\(",
        "alert 함수 호출 기반 XSS 테스트 의심 패턴",
    ),

    # Path Traversal
    _rule(
        "path_traversal_dotdot",
        "Path Traversal",
        "high",
        r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)",
        "상위 디렉터리 접근을 시도하는 Path Traversal 의심 패턴",
    ),
    _rule(
        "path_traversal_sensitive_file",
        "Path Traversal",
        "high",
        r"(/etc/passwd|boot\.ini|win\.ini)",
        "민감 시스템 파일 접근 의심 패턴",
    ),

    # Command Injection
    _rule(
        "cmd_injection_pipe",
        "Command Injection",
        "high",
        r"(\|\s*(whoami|id|cat|ls|pwd|curl|wget))",
        "파이프를 이용한 명령 실행 의심 패턴",
    ),
    _rule(
        "cmd_injection_chain",
        "Command Injection",
        "high",
        r"(&&|\|\||;\s*(whoami|id|cat|ls|pwd|curl|wget))",
        "명령 연결 연산자를 이용한 Command Injection 의심 패턴",
    ),
    _rule(
        "cmd_injection_backtick",
        "Command Injection",
        "medium",
        r"`[^`]+`",
        "백틱을 이용한 명령 실행 의심 패턴",
    ),

    # Bot / Scanner / Recon
    _rule(
        "bot_env_probe",
        "Bot/Scanner",
        "medium",
        r"(\.env|\.git/config|config\.json|backup\.zip|dump\.sql)",
        "환경파일/백업파일 탐색 봇 요청 의심 패턴",
    ),
    _rule(
        "bot_wp_probe",
        "Bot/Scanner",
        "low",
        r"(wp-admin|wp-login|xmlrpc\.php)",
        "WordPress 경로 탐색 봇 요청 의심 패턴",
    ),
    _rule(
        "bot_hnap_probe",
        "Bot/Scanner",
        "medium",
        r"(HNAP1|/mcp|/sse|/mcp-sse)",
        "네트워크 장비/관리 인터페이스 탐색 의심 패턴",
    ),
]
