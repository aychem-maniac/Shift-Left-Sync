import os
from dotenv import load_dotenv

load_dotenv()

# ── ZAP 데몬 연결 설정 ─────────────────────────────────────────
ZAP_ADDRESS = os.getenv("ZAP_ADDRESS", "127.0.0.1")
ZAP_PORT    = os.getenv("ZAP_PORT",    "8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

# ── 위험도 정렬 기준 ───────────────────────────────────────────
RISK_ORDER = {
    "Critical":      0,
    "High":          1,
    "Medium":        2,
    "Low":           3,
    "Informational": 4,
    "Info":          4,
    "Unknown":       5,
}

# ── OWASP Top 10 2021 키워드 매핑 ─────────────────────────────
OWASP_MAP = {
    "sql injection":           "A03:2021 - Injection",
    "cross site script":       "A03:2021 - Injection",
    "xss":                     "A03:2021 - Injection",
    "command injection":       "A03:2021 - Injection",
    "ldap injection":          "A03:2021 - Injection",
    "x-frame-options":         "A05:2021 - Security Misconfiguration",
    "content security policy": "A05:2021 - Security Misconfiguration",
    "strict-transport":        "A05:2021 - Security Misconfiguration",
    "x-content-type":          "A05:2021 - Security Misconfiguration",
    "directory browsing":      "A05:2021 - Security Misconfiguration",
    "server leaks":            "A05:2021 - Security Misconfiguration",
    "timestamp disclosure":    "A05:2021 - Security Misconfiguration",
    "application error":       "A05:2021 - Security Misconfiguration",
    "missing security header": "A05:2021 - Security Misconfiguration",
    "cors":                    "A05:2021 - Security Misconfiguration",
    "cookie without secure":   "A02:2021 - Cryptographic Failures",
    "cookie without httponly": "A02:2021 - Cryptographic Failures",
    "ssl":                     "A02:2021 - Cryptographic Failures",
    "tls":                     "A02:2021 - Cryptographic Failures",
    "https not enforced":      "A02:2021 - Cryptographic Failures",
    "subresource integrity":   "A08:2021 - Software and Data Integrity Failures",
    "path traversal":          "A01:2021 - Broken Access Control",
    "directory traversal":     "A01:2021 - Broken Access Control",
    "access control":          "A01:2021 - Broken Access Control",
    "authentication":          "A07:2021 - Identification and Authentication Failures",
    "session":                 "A07:2021 - Identification and Authentication Failures",
    "ssrf":                    "A10:2021 - Server-Side Request Forgery",
    "outdated":                "A06:2021 - Vulnerable and Outdated Components",
    "cve":                     "A06:2021 - Vulnerable and Outdated Components",
}

# ── 스캔 강도별 설정 ───────────────────────────────────────────
SCAN_STRENGTH = {
    "low": {
        "spider_recurse": False,
        "ajax_timeout":   30,
        "ascan_strength": "LOW",
    },
    "medium": {
        "spider_recurse": True,
        "ajax_timeout":   60,
        "ascan_strength": "MEDIUM",
    },
    "high": {
        "spider_recurse": True,
        "ajax_timeout":   90,
        "ascan_strength": "HIGH",
    },
}

# ZAP ascan 강도 숫자 매핑
ZAP_STRENGTH_MAP = {
    "low":    2,
    "medium": 3,
    "high":   4,
}
