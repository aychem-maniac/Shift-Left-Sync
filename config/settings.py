import os
from dotenv import load_dotenv

load_dotenv()

# ── ZAP 데몬 연결 설정 ─────────────────────────────────────────
ZAP_ADDRESS = os.getenv("ZAP_ADDRESS", "127.0.0.1")
ZAP_PORT    = os.getenv("ZAP_PORT",    "8090")
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

# ── OWASP Top 10 2025 키워드 매핑 ─────────────────────────────
OWASP_MAP = {
    "sql injection":                      "A05:2025 - Injection",
    "cross site script":                  "A05:2025 - Injection",
    "xss":                                "A05:2025 - Injection",
    "command injection":                  "A05:2025 - Injection",
    "ldap injection":                     "A05:2025 - Injection",
    "x-frame-options":                    "A02:2025 - Security Misconfiguration",
    "content security policy":            "A02:2025 - Security Misconfiguration",
    "strict-transport":                   "A02:2025 - Security Misconfiguration",
    "x-content-type":                     "A02:2025 - Security Misconfiguration",
    "directory browsing":                 "A02:2025 - Security Misconfiguration",
    "server leaks":                       "A02:2025 - Security Misconfiguration",
    "timestamp disclosure":               "A02:2025 - Security Misconfiguration",
    "application error":                  "A10:2025 - Mishandling of Exceptional Conditions",
    "missing security header":            "A02:2025 - Security Misconfiguration",
    "missing anti-clickjacking header":   "A02:2025 - Security Misconfiguration",
    "cross-domain misconfiguration":      "A02:2025 - Security Misconfiguration",
    "suggested security header missing":  "A02:2025 - Security Misconfiguration",
    "access-control-allow-origin header": "A02:2025 - Security Misconfiguration",
    ".env information leak":              "A02:2025 - Security Misconfiguration",
    ".htaccess information leak":         "A02:2025 - Security Misconfiguration",
    ".htpasswd":                          "A02:2025 - Security Misconfiguration",
    ".bash_history":                      "A02:2025 - Security Misconfiguration",
    ".sh_history":                        "A02:2025 - Security Misconfiguration",
    "elmah information leak":             "A02:2025 - Security Misconfiguration",
    "trace.axd information leak":         "A02:2025 - Security Misconfiguration",
    "private ip disclosure":              "A02:2025 - Security Misconfiguration",
    "prometheus metrics":                 "A02:2025 - Security Misconfiguration",
    "cors":                               "A02:2025 - Security Misconfiguration",
    "cookie without secure":              "A04:2025 - Cryptographic Failures",
    "cookie without httponly":            "A04:2025 - Cryptographic Failures",
    "ssl":                                "A04:2025 - Cryptographic Failures",
    "tls":                                "A04:2025 - Cryptographic Failures",
    "https not enforced":                 "A04:2025 - Cryptographic Failures",
    "subresource integrity":              "A08:2025 - Software or Data Integrity Failures",
    "path traversal":                     "A01:2025 - Broken Access Control",
    "directory traversal":                "A01:2025 - Broken Access Control",
    "access control":                     "A01:2025 - Broken Access Control",
    "authentication":                     "A07:2025 - Authentication Failures",
    "session":                            "A07:2025 - Authentication Failures",
    "ssrf":                               "A01:2025 - Broken Access Control",
    "outdated":                           "A03:2025 - Software Supply Chain Failures",
    "cve":                                "A03:2025 - Software Supply Chain Failures",
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
