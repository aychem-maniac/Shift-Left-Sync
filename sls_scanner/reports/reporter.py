# sls_scanner/reports/reporter.py
# 기술 리포트(전문가용) + 비기술 리포트(일반인용) 동시 생성

import csv, json, os, re
from datetime import datetime
from collections import Counter

try:
    from config import RISK_ORDER
except Exception:
    RISK_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4,"Info":4,"Unknown":5}

FIELDS = [
    "tool","vuln_id","name","risk","poc_status",
    "url","param","cwe","owasp",
    "evidence","description","solution","timestamp"
]

# ── 비기술 리포트용 취약점 설명 ───────────────────────────────
PLAIN_MAP = {
    # 키워드: (제목, 위험 이유(쉬운 말), 해결 방법(쉬운 말))
    "sql injection": (
        "데이터베이스 해킹 가능",
        "공격자가 웹사이트의 검색창이나 로그인 폼에 특수 문자를 입력해 데이터베이스에 저장된 모든 정보(회원 ID·비밀번호·개인정보)를 빼내거나 삭제할 수 있습니다.",
        "개발자에게 '파라미터화 쿼리(Prepared Statement) 적용'을 요청하세요. 즉시 해당 기능의 입력 필드를 점검해야 합니다."
    ),
    "cross site script": (
        "악성 스크립트 삽입 가능 (XSS)",
        "공격자가 악성 코드를 웹페이지에 심어 놓으면, 이 페이지를 방문한 이용자의 로그인 정보나 쿠키가 도난당할 수 있습니다.",
        "개발자에게 '입력값 HTML 이스케이프 처리'를 요청하세요. Content-Security-Policy 헤더도 추가해야 합니다."
    ),
    "xss": (
        "악성 스크립트 삽입 가능 (XSS)",
        "공격자가 악성 코드를 웹페이지에 심어 놓으면, 이 페이지를 방문한 이용자의 로그인 정보나 쿠키가 도난당할 수 있습니다.",
        "개발자에게 '입력값 HTML 이스케이프 처리'를 요청하세요."
    ),
    "content security policy": (
        "보안 정책 헤더 누락 (CSP)",
        "웹사이트에 '어떤 스크립트만 실행 가능하다'는 규칙이 없습니다. 악성 스크립트가 삽입되면 브라우저가 이를 막지 못합니다.",
        "웹 서버 담당자에게 'Content-Security-Policy 헤더 추가'를 요청하세요. Express.js라면 helmet() 미들웨어를 적용하면 됩니다."
    ),
    "x-frame-options": (
        "클릭재킹 공격 가능",
        "공격자가 우리 웹사이트를 투명하게 다른 페이지 위에 올려놓고, 이용자가 버튼을 클릭하는 척 속여 본인 의지와 다른 행동을 하게 만들 수 있습니다.",
        "웹 서버 담당자에게 'X-Frame-Options: SAMEORIGIN 헤더 추가'를 요청하세요."
    ),
    "strict-transport": (
        "암호화 통신 강제 설정 누락 (HSTS)",
        "이용자가 처음 접속할 때 암호화되지 않은 HTTP로 연결될 수 있어, 중간에서 누군가 정보를 훔쳐볼 수 있습니다.",
        "웹 서버 담당자에게 'Strict-Transport-Security 헤더 추가'를 요청하세요."
    ),
    "x-content-type": (
        "파일 유형 위장 공격 가능",
        "브라우저가 서버에서 보낸 파일 유형을 무시하고 임의로 해석할 수 있어, 악성 파일이 정상 파일로 실행될 수 있습니다.",
        "웹 서버 담당자에게 'X-Content-Type-Options: nosniff 헤더 추가'를 요청하세요."
    ),
    "cors": (
        "다른 웹사이트에서 정보 접근 허용됨 (CORS)",
        "어떤 웹사이트든 우리 서버의 정보를 마음대로 가져갈 수 있도록 설정되어 있습니다. 개인정보나 인증 정보가 유출될 수 있습니다.",
        "개발자에게 'Access-Control-Allow-Origin 값을 허용된 도메인만 지정'하도록 요청하세요. 와일드카드(*)를 제거해야 합니다."
    ),
    "cookie": (
        "쿠키(로그인 정보) 보호 설정 부족",
        "로그인 상태를 유지하는 쿠키가 안전하게 보호되지 않아 공격자가 이용자의 쿠키를 훔쳐 계정을 탈취할 수 있습니다.",
        "개발자에게 '쿠키에 Secure, HttpOnly, SameSite 속성 추가'를 요청하세요."
    ),
    "ftp": (
        "파일 저장소 외부 접근 가능 (/ftp/)",
        "/ftp/ 폴더가 인터넷에 공개되어 있습니다. 이 폴더에 서버 설정 파일, 비밀번호, 개인키 등 중요한 파일이 저장되어 있을 수 있습니다.",
        "웹 서버 담당자에게 '/ftp/ 경로를 외부에서 접근하지 못하도록 차단'해달라고 요청하세요. robots.txt에서도 해당 항목을 제거해야 합니다."
    ),
    "directory": (
        "내부 폴더 외부 접근 가능",
        "서버 내부 폴더가 인터넷에 공개되어 있습니다. 내부 파일이 외부에 노출될 수 있습니다.",
        "웹 서버 담당자에게 해당 경로의 외부 접근을 차단해달라고 요청하세요."
    ),
    "etag": (
        "서버 내부 파일 정보 노출",
        "서버가 파일의 내부 식별자를 외부에 알려주고 있습니다. 공격자가 서버 구조를 파악하는 데 활용할 수 있습니다.",
        "웹 서버 담당자에게 'ETag 헤더에서 inode 정보를 제거'해달라고 요청하세요."
    ),
}

def _plain_desc(name: str):
    """취약점명에서 비기술 설명 반환"""
    nl = name.lower()
    for kw, (title, why, fix) in PLAIN_MAP.items():
        if kw in nl:
            return title, why, fix
    return name, "보안 전문가의 추가 검토가 필요한 항목입니다.", "담당 개발팀 또는 보안 담당자에게 해당 취약점을 전달하고 조치를 요청하세요."


def _safe_target(target: str) -> str:
    s = re.sub(r'https?://', '', target)
    return re.sub(r'[^\w\-.]', '_', s).strip('_')


def make_paths(target: str, timestamp: str, out_dir: str = "results/reports") -> dict:
    os.makedirs(out_dir, exist_ok=True)
    base = f"{_safe_target(target)}_{timestamp}"
    return {
        "csv_confirmed":      os.path.join(out_dir, f"{base}_confirmed.csv"),
        "csv_false_positive": os.path.join(out_dir, f"{base}_false_positive.csv"),
        "csv_unverified":     os.path.join(out_dir, f"{base}_unverified.csv"),
        "csv_full":           os.path.join(out_dir, f"{base}_full.csv"),
        "json_full":          os.path.join(out_dir, f"{base}_full.json"),
        "html":               os.path.join(out_dir, f"{base}_report.html"),
        "html_plain":         os.path.join(out_dir, f"{base}_report_simple.html"),
    }


def _sort(vulns: list) -> list:
    return sorted(vulns, key=lambda v: RISK_ORDER.get(v.get("risk",""), 99))


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


# ── 전문가용 HTML ─────────────────────────────────────────────
def export_html(target: str, vulns: list, port_info: list, path: str, timestamp: str):
    sc = Counter(v.get("risk","") for v in vulns)
    confirmed  = [v for v in vulns if v.get("poc_status") == "CONFIRMED"]
    unverified = [v for v in vulns if v.get("poc_status") == "UNVERIFIED"]
    false_pos  = [v for v in vulns if v.get("poc_status") == "FALSE_POSITIVE"]
    pending    = [v for v in vulns if v.get("poc_status") == "PENDING"]

    def sc_cls(sev):
        return {"High":"severity-high","Critical":"severity-critical",
                "Medium":"severity-medium","Low":"severity-low"}.get(sev,"severity-info")

    port_rows = "".join(
        f"<tr><td>{p.get('host','')}</td><td>{p.get('port','')}</td>"
        f"<td>{p.get('protocol','')}</td><td>{p.get('service','')}</td>"
        f"<td>{p.get('state','')}</td><td>{p.get('product','')} {p.get('version','')}</td></tr>"
        for p in port_info
    ) or "<tr><td colspan='6'>포트 스캔 결과 없음</td></tr>"

    finding_rows = "".join(
        f"<tr><td>{v.get('tool','')}</td>"
        f"<td>{v.get('name','')}</td>"
        f"<td class='{sc_cls(v.get('risk',''))}'>{v.get('risk','')}</td>"
        f"<td>{v.get('poc_status','')}</td>"
        f"<td style='word-break:break-all;font-size:11px'>{v.get('url','')}</td>"
        f"<td>{v.get('cwe','')}</td>"
        f"<td style='font-size:11px'>{v.get('owasp','')}</td>"
        f"<td style='font-size:11px'>{str(v.get('evidence',''))[:80]}</td>"
        f"<td style='font-size:11px'>{str(v.get('solution',''))[:80]}</td></tr>"
        for v in _sort(vulns)
    ) or "<tr><td colspan='9'>취약점 없음</td></tr>"

    simple_link = os.path.basename(path).replace("_report.html","_report_simple.html")

    html = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<title>[전문가용] Shift-Left-Sync — {target}</title>
<style>
body{{font-family:Arial,sans-serif;margin:30px;background:#f5f5f5;font-size:13px}}
h1{{color:#1F4E79;font-size:22px}} h2{{color:#2E75B6;font-size:16px;margin-top:24px}}
.banner{{background:#1F4E79;color:white;padding:10px 16px;border-radius:8px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center}}
.banner a{{color:#90CAF9;font-size:12px}}
.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px}}
.sum-card{{background:white;padding:12px;border-radius:8px;text-align:center;border:1px solid #ddd}}
.sum-n{{font-size:24px;font-weight:bold}} .sum-l{{font-size:11px;color:#666;margin-top:2px}}
table{{width:100%;border-collapse:collapse;background:white;margin-bottom:24px;font-size:12px}}
th{{background:#1F4E79;color:white;padding:7px 8px;text-align:left}}
td{{border:1px solid #ddd;padding:6px 8px;vertical-align:top}}
tr:nth-child(even){{background:#f9f9f9}}
.severity-critical{{background:#8b0000;color:white;font-weight:bold;text-align:center}}
.severity-high{{background:#d9534f;color:white;font-weight:bold;text-align:center}}
.severity-medium{{background:#f0ad4e;color:white;font-weight:bold;text-align:center}}
.severity-low{{background:#5bc0de;color:white;font-weight:bold;text-align:center}}
.severity-info{{background:#5cb85c;color:white;font-weight:bold;text-align:center}}
</style></head><body>
<div class="banner">
  <div><strong>🔒 Shift-Left-Sync 보안 스캔 리포트 [전문가용]</strong> &nbsp;|&nbsp; {target} &nbsp;|&nbsp; {timestamp}</div>
  <a href="{simple_link}">📄 비전문가용 간편 리포트 보기 →</a>
</div>
<div class="summary">
  <div class="sum-card"><div class="sum-n">{len(vulns)}</div><div class="sum-l">전체 탐지</div></div>
  <div class="sum-card"><div class="sum-n" style="color:#d9534f">{len(confirmed)}</div><div class="sum-l">확정 취약점</div></div>
  <div class="sum-card"><div class="sum-n" style="color:#5cb85c">{len(false_pos)}</div><div class="sum-l">오탐 제거</div></div>
  <div class="sum-card"><div class="sum-n" style="color:#f0ad4e">{len(unverified)+len(pending)}</div><div class="sum-l">수동 검토</div></div>
  <div class="sum-card"><div class="sum-n">{sc.get('High',0)+sc.get('Critical',0)}</div><div class="sum-l">High 이상</div></div>
</div>
<h2>Nmap 포트 스캔</h2>
<table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>State</th><th>Product/Version</th></tr></thead>
<tbody>{port_rows}</tbody></table>
<h2>전체 취약점 목록</h2>
<table><thead><tr><th>Tool</th><th>Name</th><th>Severity</th><th>PoC Status</th><th>URL</th><th>CWE</th><th>OWASP</th><th>Evidence</th><th>Solution</th></tr></thead>
<tbody>{finding_rows}</tbody></table>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [리포트] HTML 저장 (전문가용): {path}")


# ── 비전문가용 HTML ───────────────────────────────────────────
def export_html_plain(target: str, vulns: list, path: str, timestamp: str):
    """보안을 모르는 사람도 이해하고 바로 조치할 수 있는 리포트"""
    confirmed = [v for v in _sort(vulns) if v.get("poc_status") == "CONFIRMED"]
    unverified= [v for v in _sort(vulns) if v.get("poc_status") in ("UNVERIFIED","PENDING")]

    RISK_KO   = {"High":"🔴 높음", "Critical":"🔴 매우 높음",
                 "Medium":"🟠 중간", "Low":"🟡 낮음", "Informational":"🔵 정보"}
    RISK_DESC = {
        "High":    "즉시 조치 필요 — 개인정보·시스템이 위험에 노출되어 있습니다.",
        "Critical":"매우 긴급 — 서비스 전체가 위협받을 수 있습니다.",
        "Medium":  "조속히 조치 필요 — 방치하면 더 큰 피해로 이어질 수 있습니다.",
        "Low":     "여유 있게 조치 — 단독으로는 피해가 크지 않지만 개선이 필요합니다.",
        "Informational":"참고 사항 — 필수 조치는 아니지만 보안 수준 향상에 도움이 됩니다.",
    }

    def card(v, idx):
        title, why, fix = _plain_desc(v.get("name",""))
        risk  = v.get("risk","")
        rdesc = RISK_DESC.get(risk, "")
        rko   = RISK_KO.get(risk, risk)
        bg    = {"High":"#FFF0F0","Critical":"#FFE0E0",
                 "Medium":"#FFF8E8","Low":"#F0F8FF"}.get(risk,"#F9F9F9")
        border= {"High":"#d9534f","Critical":"#8b0000",
                 "Medium":"#f0ad4e","Low":"#5bc0de"}.get(risk,"#ccc")
        url   = v.get("url","")
        return f"""
<div style="background:{bg};border-left:4px solid {border};border-radius:0 10px 10px 0;
     padding:14px 18px;margin-bottom:14px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">
    <div style="font-size:15px;font-weight:bold;color:#222">📌 {idx}. {title}</div>
    <div style="font-size:12px;font-weight:bold;padding:3px 10px;background:{border};
         color:white;border-radius:12px;white-space:nowrap">{rko}</div>
  </div>
  <div style="font-size:12px;color:#555;margin-bottom:4px">{rdesc}</div>
  <div style="margin:10px 0 6px;font-size:13px">
    <strong>🤔 왜 위험한가요?</strong><br>
    <span style="color:#333;line-height:1.7">{why}</span>
  </div>
  <div style="margin:6px 0;font-size:13px">
    <strong>✅ 어떻게 해결하나요?</strong><br>
    <span style="color:#333;line-height:1.7">{fix}</span>
  </div>
  <div style="margin-top:8px;font-size:11px;color:#888;font-family:monospace;
       background:rgba(0,0,0,0.05);padding:4px 8px;border-radius:4px;word-break:break-all">
    발견 위치: {url if url else "전체 페이지"}
  </div>
</div>"""

    high_cards   = "".join(card(v,i+1) for i,v in enumerate([x for x in confirmed if x.get("risk") in ("High","Critical")]))
    medium_cards = "".join(card(v,i+1) for i,v in enumerate([x for x in confirmed if x.get("risk") == "Medium"][:10]))
    low_cards    = "".join(card(v,i+1) for i,v in enumerate([x for x in confirmed if x.get("risk") == "Low"][:5]))

    h_cnt = len([x for x in confirmed if x.get("risk") in ("High","Critical")])
    m_cnt = len([x for x in confirmed if x.get("risk") == "Medium"])
    l_cnt = len([x for x in confirmed if x.get("risk") == "Low"])

    tech_link = os.path.basename(path).replace("_report_simple.html","_report.html")

    html = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<title>[간편] 보안 점검 결과 — {target}</title>
<style>
body{{font-family:'Apple SD Gothic Neo','Malgun Gothic',Arial,sans-serif;
     margin:0;background:#f0f2f5;color:#222}}
.header{{background:linear-gradient(135deg,#1F4E79,#2E75B6);
         color:white;padding:28px 32px}}
.header h1{{margin:0 0 6px;font-size:22px}}
.header p{{margin:0;font-size:13px;opacity:.85}}
.content{{max-width:820px;margin:0 auto;padding:24px 16px}}
.summary-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:28px}}
.sum-card{{background:white;border-radius:12px;padding:16px;text-align:center;
           box-shadow:0 2px 8px rgba(0,0,0,.08)}}
.sum-n{{font-size:32px;font-weight:bold;margin-bottom:4px}}
.sum-l{{font-size:12px;color:#666}}
.section-title{{font-size:17px;font-weight:bold;margin:24px 0 12px;
                padding-left:10px;border-left:4px solid #1F4E79}}
.notice{{background:#E8F4FD;border:1px solid #2E75B6;border-radius:10px;
         padding:14px 18px;margin-bottom:20px;font-size:13px;line-height:1.7}}
.footer{{text-align:center;padding:20px;font-size:11px;color:#999}}
.tech-link{{display:inline-block;margin-top:8px;color:#2E75B6;font-size:12px}}
</style></head><body>
<div class="header">
  <h1>🛡️ 보안 점검 결과 보고서</h1>
  <p>대상: {target} &nbsp;|&nbsp; 점검 일시: {timestamp}<br>
  이 보고서는 보안 전문 지식 없이도 이해하고 조치할 수 있도록 작성되었습니다.</p>
  <a href="{tech_link}" class="tech-link">🔧 전문가용 상세 리포트 보기 →</a>
</div>
<div class="content">
  <div class="notice">
    💡 <strong>이 보고서 읽는 법:</strong> 아래 항목들은 자동화 도구가 발견한 보안 취약점입니다.
    각 항목에는 <strong>왜 위험한지</strong>와 <strong>어떻게 해결하는지</strong>가 담겨 있습니다.
    🔴 높음 항목부터 먼저 개발팀에 전달해 조치를 요청하세요.
  </div>
  <div class="summary-grid">
    <div class="sum-card">
      <div class="sum-n" style="color:{'#d9534f' if h_cnt > 0 else '#5cb85c'}">{h_cnt}</div>
      <div class="sum-l">🔴 즉시 조치 필요<br>(높음/매우 높음)</div>
    </div>
    <div class="sum-card">
      <div class="sum-n" style="color:{'#f0ad4e' if m_cnt > 0 else '#5cb85c'}">{m_cnt}</div>
      <div class="sum-l">🟠 조속히 조치 필요<br>(중간)</div>
    </div>
    <div class="sum-card">
      <div class="sum-n" style="color:#5bc0de">{l_cnt}</div>
      <div class="sum-l">🟡 여유 있게 조치<br>(낮음)</div>
    </div>
  </div>
  {'<div class="section-title">🔴 즉시 조치가 필요한 항목</div>' + high_cards if h_cnt > 0 else ''}
  {'<div class="section-title">🟠 조속히 조치가 필요한 항목 (상위 10건)</div>' + medium_cards if m_cnt > 0 else ''}
  {'<div class="section-title">🟡 여유 있게 조치할 항목 (상위 5건)</div>' + low_cards if l_cnt > 0 else ''}
  <div class="notice" style="margin-top:24px;background:#F0FFF0;border-color:#5cb85c">
    ✅ <strong>조치 완료 후:</strong> 개발팀이 수정을 완료하면 동일한 스캔을 다시 실행해
    해당 항목이 사라졌는지 확인하세요. 항목이 사라지면 취약점이 해결된 것입니다.
  </div>
</div>
<div class="footer">Shift-Left-Sync 자동 보안 스캔 | {timestamp}</div>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [리포트] HTML 저장 (비전문가용): {path}")


def print_summary(vulns: list):
    confirmed  = [v for v in vulns if v.get("poc_status") == "CONFIRMED"]
    false_pos  = [v for v in vulns if v.get("poc_status") == "FALSE_POSITIVE"]
    unverified = [v for v in vulns if v.get("poc_status") in ("UNVERIFIED","PENDING")]
    counts = {}
    for v in confirmed:
        counts[v["risk"]] = counts.get(v["risk"],0) + 1
    icons = {"High":"🔴","Medium":"🟠","Low":"🟡","Informational":"🔵"}
    print(f"\n{'='*55}")
    print(f"  전체 탐지:    {len(vulns):>3}건")
    print(f"  확정 취약점:  {len(confirmed):>3}건")
    print(f"  오탐 제외:    {len(false_pos):>3}건")
    print(f"  수동 검토:    {len(unverified):>3}건")
    print(f"  {'─'*38}")
    for risk in ["High","Medium","Low","Informational"]:
        if risk in counts:
            print(f"  {icons.get(risk,'⚪')} {risk:<13}: {counts[risk]}건")
    print(f"{'='*55}")