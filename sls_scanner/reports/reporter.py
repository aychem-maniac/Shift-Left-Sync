# sls_scanner/reports/reporter.py
# CSV / JSON / HTML 리포트 생성 — 타겟+타임스탬프 기반 파일명

import csv, json, os, re
from datetime import datetime
from collections import Counter
from config import RISK_ORDER

FIELDS = [
    "tool", "vuln_id", "name", "risk", "poc_status",
    "url", "param", "cwe", "owasp",
    "evidence", "description", "solution", "timestamp"
]


def _safe_target(target: str) -> str:
    """URL을 파일명에 쓸 수 있는 문자열로 변환"""
    s = re.sub(r'https?://', '', target)
    s = re.sub(r'[^\w\-.]', '_', s)
    return s.strip('_')


def make_paths(target: str, timestamp: str, out_dir: str = "results/reports") -> dict:
    """타겟 + 타임스탬프 기반 경로 딕셔너리 반환"""
    os.makedirs(out_dir, exist_ok=True)
    base = f"{_safe_target(target)}_{timestamp}"
    return {
        "csv_confirmed":     os.path.join(out_dir, f"{base}_confirmed.csv"),
        "csv_false_positive":os.path.join(out_dir, f"{base}_false_positive.csv"),
        "csv_unverified":    os.path.join(out_dir, f"{base}_unverified.csv"),
        "csv_full":          os.path.join(out_dir, f"{base}_full.csv"),
        "json_full":         os.path.join(out_dir, f"{base}_full.json"),
        "html":              os.path.join(out_dir, f"{base}_report.html"),
    }


def _sort(vulns: list) -> list:
    return sorted(vulns, key=lambda v: RISK_ORDER.get(v.get("risk", ""), 99))


def export_csv(vulns: list, path: str):
    if not vulns:
        print(f"  [리포트] 건너뜀 (0건): {os.path.basename(path)}")
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(_sort(vulns))
    print(f"  [리포트] CSV 저장: {path}  ({len(vulns)}건)")


def export_json(vulns: list, path: str):
    if not vulns:
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_sort(vulns), f, ensure_ascii=False, indent=2)
    print(f"  [리포트] JSON 저장: {path}  ({len(vulns)}건)")


def export_html(target: str, vulns: list, port_info: list, path: str, timestamp: str):
    severity_counts = Counter(v.get("risk", "Unknown") for v in vulns)
    confirmed   = [v for v in vulns if v.get("poc_status") == "CONFIRMED"]
    unverified  = [v for v in vulns if v.get("poc_status") == "UNVERIFIED"]
    false_pos   = [v for v in vulns if v.get("poc_status") == "FALSE_POSITIVE"]
    pending     = [v for v in vulns if v.get("poc_status") == "PENDING"]

    def sev_class(sev):
        return {
            "High": "severity-high", "Critical": "severity-critical",
            "Medium": "severity-medium", "Low": "severity-low",
            "Informational": "severity-info", "Info": "severity-info",
        }.get(sev, "severity-unknown")

    port_rows = "".join(
        f"<tr><td>{p.get('host','')}</td><td>{p.get('port','')}</td>"
        f"<td>{p.get('protocol','')}</td><td>{p.get('service','')}</td>"
        f"<td>{p.get('state','')}</td><td>{p.get('product','')}</td>"
        f"<td>{p.get('version','')}</td></tr>"
        for p in port_info
    ) or "<tr><td colspan='7'>포트 스캔 결과 없음</td></tr>"

    finding_rows = "".join(
        f"<tr><td>{v.get('tool','')}</td><td>{v.get('name','')}</td>"
        f"<td class='{sev_class(v.get('risk',''))}'>{v.get('risk','')}</td>"
        f"<td>{v.get('poc_status','')}</td><td>{v.get('url','')}</td>"
        f"<td>{v.get('owasp','')}</td><td>{v.get('evidence','')}</td>"
        f"<td>{v.get('solution','')}</td></tr>"
        for v in _sort(vulns)
    ) or "<tr><td colspan='8'>취약점 결과 없음</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<title>Shift-Left-Sync — {target}</title>
<style>
body{{font-family:Arial,sans-serif;margin:30px;background:#f5f5f5}}
h1,h2{{color:#222}}
.summary{{background:#fff;padding:15px;border-radius:8px;margin-bottom:20px;border:1px solid #ddd}}
.summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:15px}}
.summary-card{{background:#fafafa;border:1px solid #ddd;border-radius:6px;padding:10px;text-align:center}}
table{{width:100%;border-collapse:collapse;background:#fff;margin-bottom:30px}}
th,td{{border:1px solid #ddd;padding:8px;font-size:13px;vertical-align:top}}
th{{background:#222;color:#fff}}
.severity-critical{{color:#fff;background:#8b0000;font-weight:bold;text-align:center}}
.severity-high{{color:#fff;background:#d9534f;font-weight:bold;text-align:center}}
.severity-medium{{color:#fff;background:#f0ad4e;font-weight:bold;text-align:center}}
.severity-low{{color:#fff;background:#5bc0de;font-weight:bold;text-align:center}}
.severity-info,.severity-unknown{{color:#fff;background:#5cb85c;font-weight:bold;text-align:center}}
</style></head><body>
<h1>Shift-Left-Sync Scan Report</h1>
<div class="summary">
  <p><strong>Target:</strong> {target}</p>
  <p><strong>Generated At:</strong> {timestamp}</p>
  <p><strong>Total Findings:</strong> {len(vulns)}</p>
  <div class="summary-grid">
    <div class="summary-card"><strong>High/Critical</strong><br>{severity_counts.get('High',0)+severity_counts.get('Critical',0)}</div>
    <div class="summary-card"><strong>Medium</strong><br>{severity_counts.get('Medium',0)}</div>
    <div class="summary-card"><strong>Low</strong><br>{severity_counts.get('Low',0)}</div>
    <div class="summary-card"><strong>Confirmed</strong><br>{len(confirmed)}</div>
    <div class="summary-card"><strong>Need Review</strong><br>{len(unverified)+len(pending)}</div>
  </div>
</div>
<h2>Nmap Port Scan Results</h2>
<table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>State</th><th>Product</th><th>Version</th></tr></thead>
<tbody>{port_rows}</tbody></table>
<h2>Security Findings</h2>
<table><thead><tr><th>Tool</th><th>Name</th><th>Severity</th><th>PoC Status</th><th>URL</th><th>OWASP</th><th>Evidence</th><th>Solution</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [리포트] HTML 저장: {path}")


def print_summary(vulns: list):
    confirmed  = [v for v in vulns if v.get("poc_status") == "CONFIRMED"]
    false_pos  = [v for v in vulns if v.get("poc_status") == "FALSE_POSITIVE"]
    unverified = [v for v in vulns if v.get("poc_status") in ("UNVERIFIED", "PENDING")]
    counts     = {}
    for v in confirmed:
        counts[v["risk"]] = counts.get(v["risk"], 0) + 1
    icons = {"High": "🔴", "Medium": "🟠", "Low": "🟡", "Informational": "🔵"}
    print(f"\n{'='*55}")
    print(f"  전체 탐지:    {len(vulns):>3}건")
    print(f"  확정 취약점:  {len(confirmed):>3}건")
    print(f"  오탐 제외:    {len(false_pos):>3}건")
    print(f"  수동 검토:    {len(unverified):>3}건")
    print(f"  {'─'*38}")
    for risk in ["High", "Medium", "Low", "Informational"]:
        if risk in counts:
            print(f"  {icons.get(risk,'⚪')} {risk:<13}: {counts[risk]}건")
    print(f"{'='*55}")
