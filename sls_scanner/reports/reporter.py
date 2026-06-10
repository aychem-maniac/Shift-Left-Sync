# sls_scanner/reports/reporter.py
import csv, json, os, re
from datetime import datetime
from collections import Counter

try:
    from config import RISK_ORDER
except Exception:
    RISK_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4,"Info":4,"Unknown":5}

FIELDS = [
    "tool","vuln_id","name","risk","poc_status","poc_reason",
    "cve_id","cvss_score","cvss_severity","cvss_vector","patch_url",
    "url","param","cwe","owasp",
    "evidence","description","solution","timestamp"
]

PLAIN_MAP = {
    "sql injection": (
        "데이터베이스 해킹 가능",
        "공격자가 웹사이트의 검색창이나 로그인 폼에 특수 문자를 입력해 데이터베이스에 저장된 모든 정보를 빼내거나 삭제할 수 있습니다.",
        "개발자에게 '파라미터화 쿼리(Prepared Statement) 적용'을 요청하세요."
    ),
    "cross site script": (
        "악성 스크립트 삽입 가능 (XSS)",
        "공격자가 악성 코드를 웹페이지에 심어 놓으면, 이 페이지를 방문한 이용자의 로그인 정보나 쿠키가 도난당할 수 있습니다.",
        "개발자에게 '입력값 HTML 이스케이프 처리'를 요청하세요."
    ),
    "xss": (
        "악성 스크립트 삽입 가능 (XSS)",
        "공격자가 악성 코드를 웹페이지에 심어 놓으면, 방문자의 로그인 정보나 쿠키가 도난당할 수 있습니다.",
        "개발자에게 '입력값 HTML 이스케이프 처리'를 요청하세요."
    ),
    "content security policy": (
        "보안 정책 헤더 누락 (CSP)",
        "웹사이트에 어떤 스크립트만 실행 가능하다는 규칙이 없습니다. 악성 스크립트가 삽입되면 브라우저가 이를 막지 못합니다.",
        "웹 서버 담당자에게 'Content-Security-Policy 헤더 추가'를 요청하세요."
    ),
    "x-frame-options": (
        "클릭재킹 공격 가능",
        "공격자가 우리 웹사이트를 투명하게 다른 페이지 위에 올려놓고 이용자를 속일 수 있습니다.",
        "웹 서버 담당자에게 'X-Frame-Options: SAMEORIGIN 헤더 추가'를 요청하세요."
    ),
    "strict-transport": (
        "암호화 통신 강제 설정 누락 (HSTS)",
        "이용자가 처음 접속할 때 암호화되지 않은 HTTP로 연결될 수 있어 정보가 도청될 수 있습니다.",
        "웹 서버 담당자에게 'Strict-Transport-Security 헤더 추가'를 요청하세요."
    ),
    "x-content-type": (
        "파일 유형 위장 공격 가능",
        "브라우저가 서버에서 보낸 파일 유형을 무시하고 임의로 해석할 수 있어 악성 파일이 실행될 수 있습니다.",
        "웹 서버 담당자에게 'X-Content-Type-Options: nosniff 헤더 추가'를 요청하세요."
    ),
    "cors": (
        "다른 웹사이트에서 정보 접근 허용됨 (CORS)",
        "어떤 웹사이트든 우리 서버의 정보를 마음대로 가져갈 수 있도록 설정되어 있습니다.",
        "개발자에게 'Access-Control-Allow-Origin 값을 허용된 도메인만 지정'하도록 요청하세요."
    ),
    "cookie": (
        "쿠키(로그인 정보) 보호 설정 부족",
        "로그인 상태를 유지하는 쿠키가 안전하게 보호되지 않아 공격자가 계정을 탈취할 수 있습니다.",
        "개발자에게 '쿠키에 Secure, HttpOnly, SameSite 속성 추가'를 요청하세요."
    ),
    "ftp": (
        "파일 저장소 외부 접근 가능",
        "/ftp/ 폴더가 인터넷에 공개되어 있습니다. 서버 설정 파일, 비밀번호 등 중요 파일이 노출될 수 있습니다.",
        "웹 서버 담당자에게 '/ftp/ 경로를 외부에서 접근하지 못하도록 차단'해달라고 요청하세요."
    ),
    "directory": (
        "내부 폴더 외부 접근 가능",
        "서버 내부 폴더가 인터넷에 공개되어 있습니다.",
        "웹 서버 담당자에게 해당 경로의 외부 접근을 차단해달라고 요청하세요."
    ),
    "etag": (
        "서버 내부 파일 정보 노출",
        "서버가 파일의 내부 식별자를 외부에 알려주고 있습니다.",
        "웹 서버 담당자에게 'ETag 헤더에서 inode 정보를 제거'해달라고 요청하세요."
    ),
}

def _plain_desc(name):
    nl = name.lower()
    for kw, (title, why, fix) in PLAIN_MAP.items():
        if kw in nl:
            return title, why, fix
    return name, "보안 전문가의 추가 검토가 필요한 항목입니다.", "담당 개발팀 또는 보안 담당자에게 해당 취약점을 전달하고 조치를 요청하세요."

def _safe_target(target):
    s = re.sub(r'https?://', '', target)
    return re.sub(r'[^\w\-.]', '_', s).strip('_')

def make_paths(target, timestamp, out_dir="results/reports"):
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

def _sort(vulns):
    return sorted(vulns, key=lambda v: RISK_ORDER.get(v.get("risk",""), 99))

def export_csv(vulns, path):
    if not vulns:
        print(f"  [리포트] 건너뜀 (0건): {os.path.basename(path)}")
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(_sort(vulns))
    print(f"  [리포트] CSV 저장: {path}  ({len(vulns)}건)")

def export_json(vulns, path):
    if not vulns:
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_sort(vulns), f, ensure_ascii=False, indent=2)
    print(f"  [리포트] JSON 저장: {path}  ({len(vulns)}건)")


# ── 전문가용 HTML (시각화 강화) ──────────────────────────────
def export_html(target, vulns, port_info, path, timestamp):

    sc        = Counter(v.get("risk","") for v in vulns)
    by_tool   = Counter(v.get("tool","") for v in vulns)
    poc_cnt   = Counter(v.get("poc_status","") for v in vulns)
    confirmed  = [v for v in vulns if v.get("poc_status") == "CONFIRMED"]
    unverified = [v for v in vulns if v.get("poc_status") in ("UNVERIFIED","PENDING")]
    false_pos  = [v for v in vulns if v.get("poc_status") == "FALSE_POSITIVE"]

    # ── 위험도 점수 계산 (0~100) ──────────────────────────────
    risk_score = min(100, (
        sc.get("Critical", 0) * 25 +
        sc.get("High",     0) * 15 +
        sc.get("Medium",   0) * 5  +
        sc.get("Low",      0) * 1
    ))
    score_color = (
        "#8b0000" if risk_score >= 75 else
        "#d9534f" if risk_score >= 50 else
        "#f0ad4e" if risk_score >= 25 else
        "#5cb85c"
    )
    score_label = (
        "매우 위험" if risk_score >= 75 else
        "위험"     if risk_score >= 50 else
        "주의"     if risk_score >= 25 else
        "양호"
    )

    # ── Chart.js 데이터 (JSON으로 분리 — f-string 충돌 방지) ──
    severity_labels = ["Critical", "High", "Medium", "Low", "Informational"]
    severity_data   = [sc.get(k, 0) for k in severity_labels]
    severity_colors = ["#8b0000", "#d9534f", "#f0ad4e", "#5bc0de", "#5cb85c"]

    tool_labels = list(by_tool.keys())
    tool_data   = list(by_tool.values())
    tool_colors = ["#2E75B6","#1F4E79","#70AD47","#ED7D31","#9DC3E6","#A9D18E"]

    poc_labels = ["CONFIRMED", "UNVERIFIED", "FALSE_POSITIVE"]
    poc_data   = [poc_cnt.get(k, 0) for k in poc_labels]
    poc_colors = ["#d9534f", "#f0ad4e", "#5cb85c"]

    chart_data_json = json.dumps({
        "severity": {"labels": severity_labels, "data": severity_data, "colors": severity_colors},
        "tool":     {"labels": tool_labels,     "data": tool_data,     "colors": tool_colors},
        "poc":      {"labels": poc_labels,      "data": poc_data,      "colors": poc_colors},
        "score":    risk_score,
        "scoreColor": score_color,
    })

    # ── 포트 테이블 ───────────────────────────────────────────
    port_rows = ""
    for p in port_info:
        state = p.get("state","")
        state_badge = (
            '<span style="background:#5cb85c;color:white;padding:2px 8px;border-radius:10px;font-size:11px">open</span>'
            if state == "open" else
            '<span style="background:#888;color:white;padding:2px 8px;border-radius:10px;font-size:11px">' + state + '</span>'
        )
        port_rows += (
            "<tr>"
            "<td>" + str(p.get("host","")) + "</td>"
            "<td><strong>" + str(p.get("port","")) + "</strong></td>"
            "<td>" + str(p.get("protocol","")) + "</td>"
            "<td>" + str(p.get("service","")) + "</td>"
            "<td>" + state_badge + "</td>"
            "<td>" + str(p.get("product","")) + " " + str(p.get("version","")) + "</td>"
            "</tr>"
        )
    if not port_rows:
        port_rows = "<tr><td colspan='6' style='text-align:center;color:#999'>포트 스캔 결과 없음</td></tr>"

    # ── 취약점 테이블 (JSON으로 렌더링) ──────────────────────
    vuln_json = json.dumps([{
        "tool":       v.get("tool",""),
        "name":       v.get("name",""),
        "risk":       v.get("risk",""),
        "poc_status": v.get("poc_status",""),
        "poc_reason": str(v.get("poc_reason",""))[:300],
        "cve_id":       v.get("cve_id",""),
        "cvss_score":   v.get("cvss_score",""),
        "cvss_severity":v.get("cvss_severity",""),
        "cvss_vector":  v.get("cvss_vector",""),
        "patch_url":    v.get("patch_url",""),
        "url":        v.get("url",""),
        "cwe":        v.get("cwe",""),
        "owasp":      v.get("owasp",""),
        "evidence":   str(v.get("evidence",""))[:120],
        "solution":   str(v.get("solution",""))[:120],
        "description":str(v.get("description",""))[:200],
    } for v in _sort(vulns)], ensure_ascii=False)

    simple_link = os.path.basename(path).replace("_report.html","_report_simple.html")

    # ── HTML 헤더 (f-string — JS 없음) ───────────────────────
    html_head = (
        '<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">'
        '<title>[전문가] SLS Report — ' + target + '</title>'
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>'
        '<style>'
        '*{box-sizing:border-box;margin:0;padding:0}'
        'body{font-family:Arial,sans-serif;background:#1a1d27;color:#e0e0e0;font-size:13px}'
        '.header{background:linear-gradient(135deg,#1F4E79,#2d3561);padding:20px 32px;'
        'display:flex;justify-content:space-between;align-items:center}'
        '.header h1{color:#90CAF9;font-size:20px;font-weight:bold}'
        '.header-meta{font-size:11px;color:#aaa;text-align:right;line-height:1.8}'
        '.header-meta a{color:#64b5f6}'
        '.container{max-width:1200px;margin:0 auto;padding:20px}'
        '.section{margin-bottom:28px}'
        '.section-title{font-size:15px;color:#64b5f6;font-weight:bold;margin-bottom:14px;'
        'padding-bottom:8px;border-bottom:1px solid #2d3561}'
        '.card-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}'
        '.card{background:#1a1f2e;border:1px solid #2d3561;border-radius:10px;'
        'padding:14px;text-align:center}'
        '.card-n{font-size:28px;font-weight:bold;margin-bottom:4px}'
        '.card-l{font-size:11px;color:#888}'
        '.chart-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px}'
        '.chart-box{background:#1a1f2e;border:1px solid #2d3561;border-radius:10px;padding:16px}'
        '.chart-box h3{font-size:12px;color:#888;margin-bottom:10px;text-align:center}'
        '.gauge-box{background:#1a1f2e;border:1px solid #2d3561;border-radius:10px;'
        'padding:16px;display:flex;flex-direction:column;align-items:center;justify-content:center}'
        'table{width:100%;border-collapse:collapse;background:#1a1f2e;font-size:12px}'
        'th{background:#0f1117;color:#64b5f6;padding:8px 10px;text-align:left;'
        'border-bottom:2px solid #2d3561;position:sticky;top:0}'
        'td{padding:7px 10px;border-bottom:1px solid #111827;vertical-align:top}'
        'tr:hover td{background:#111827}'
        '.badge{display:inline-block;font-size:11px;font-weight:bold;'
        'padding:2px 8px;border-radius:10px;white-space:nowrap}'
        '.r-critical{background:#8b0000;color:white}'
        '.r-high{background:#d9534f;color:white}'
        '.r-medium{background:#f0ad4e;color:#222}'
        '.r-low{background:#5bc0de;color:#222}'
        '.r-informational,.r-info{background:#5cb85c;color:white}'
        '.r-unknown{background:#555;color:white}'
        '.p-confirmed{background:#d9534f;color:white}'
        '.p-unverified{background:#f0ad4e;color:#222}'
        '.p-false_positive{background:#5cb85c;color:white}'
        '.filter-bar{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}'
        '.filter-btn{background:#2d3561;color:#aaa;border:none;padding:4px 12px;'
        'border-radius:6px;cursor:pointer;font-size:12px}'
        '.filter-btn.active{background:#1565c0;color:white}'
        '.expand-btn{background:none;border:none;color:#64b5f6;cursor:pointer;font-size:11px}'
        '.detail-row{background:#0f1117}'
        '.detail-cell{padding:10px 14px;font-size:11px;color:#aaa;line-height:1.6}'
        '.tbl-wrap{max-height:520px;overflow-y:auto;border-radius:8px;border:1px solid #2d3561}'
        '.search-box{background:#0f1117;border:1px solid #2d3561;color:#e0e0e0;'
        'padding:7px 12px;border-radius:8px;font-size:12px;width:220px}'
        '</style>'
        '</head><body>'
    )

    # ── 헤더 배너 ─────────────────────────────────────────────
    html_banner = (
        '<div class="header">'
        '<div><h1>🛡️ Shift-Left-Sync 보안 스캔 리포트</h1>'
        '<div style="font-size:12px;color:#aaa;margin-top:4px">'
        '대상: ' + target + ' &nbsp;|&nbsp; 점검 일시: ' + timestamp +
        '</div></div>'
        '<div class="header-meta">'
        '<a href="' + simple_link + '">📄 비전문가용 간편 리포트 →</a><br>'
        '전체 탐지: ' + str(len(vulns)) + '건 &nbsp;|&nbsp; 확정: ' + str(len(confirmed)) + '건 &nbsp;|&nbsp; 수동검토: ' + str(len(unverified)) + '건'
        '</div></div>'
        '<div class="container">'
    )

    # ── 요약 카드 ─────────────────────────────────────────────
    html_summary = (
        '<div class="section">'
        '<div class="section-title">📊 요약</div>'
        '<div class="card-grid">'
        '<div class="card"><div class="card-n" style="color:#64b5f6">' + str(len(vulns)) + '</div><div class="card-l">전체 탐지</div></div>'
        '<div class="card"><div class="card-n" style="color:#d9534f">' + str(len(confirmed)) + '</div><div class="card-l">확정 취약점</div></div>'
        '<div class="card"><div class="card-n" style="color:#5cb85c">' + str(len(false_pos)) + '</div><div class="card-l">오탐 제거</div></div>'
        '<div class="card"><div class="card-n" style="color:#f0ad4e">' + str(len(unverified)) + '</div><div class="card-l">수동 검토</div></div>'
        '<div class="card"><div class="card-n" style="color:' + score_color + '">' + str(risk_score) + '</div><div class="card-l">위험 점수 (' + score_label + ')</div></div>'
        '</div></div>'
    )

    # ── 차트 영역 ─────────────────────────────────────────────
    html_charts = (
        '<div class="section">'
        '<div class="section-title">📈 시각화 분석</div>'
        '<div class="chart-row">'
        '<div class="chart-box"><h3>위험도 분포</h3>'
        '<canvas id="chartSeverity" height="200"></canvas></div>'
        '<div class="chart-box"><h3>도구별 탐지 건수</h3>'
        '<canvas id="chartTool" height="200"></canvas></div>'
        '<div class="chart-box"><h3>PoC 검증 상태</h3>'
        '<canvas id="chartPoc" height="200"></canvas></div>'
        '</div></div>'
    )

    # ── 포트 스캔 테이블 ──────────────────────────────────────
    html_ports = (
        '<div class="section">'
        '<div class="section-title">🔌 Nmap 포트 스캔 결과 (' + str(len(port_info)) + '건)</div>'
        '<div class="tbl-wrap"><table>'
        '<thead><tr><th>Host</th><th>Port</th><th>Protocol</th>'
        '<th>Service</th><th>State</th><th>Product / Version</th></tr></thead>'
        '<tbody>' + port_rows + '</tbody>'
        '</table></div></div>'
    )

    # ── 취약점 테이블 (JS로 렌더링) ──────────────────────────
    html_vuln_wrap = (
        '<div class="section">'
        '<div class="section-title">🐛 취약점 상세 목록 (' + str(len(vulns)) + '건)</div>'
        '<div class="filter-bar">'
        '<input class="search-box" id="searchBox" type="text" placeholder="검색 (이름·URL·도구)">'
        '<button class="filter-btn active" onclick="filterRisk(\'ALL\')">전체</button>'
        '<button class="filter-btn" onclick="filterRisk(\'Critical\')">Critical</button>'
        '<button class="filter-btn" onclick="filterRisk(\'High\')">High</button>'
        '<button class="filter-btn" onclick="filterRisk(\'Medium\')">Medium</button>'
        '<button class="filter-btn" onclick="filterRisk(\'Low\')">Low</button>'
        '<button class="filter-btn" onclick="filterPoc(\'CONFIRMED\')">확정</button>'
        '<button class="filter-btn" onclick="filterPoc(\'UNVERIFIED\')">수동검토</button>'
        '</div>'
        '<div class="tbl-wrap"><table id="vulnTable">'
        '<thead><tr>'
        '<th></th><th onclick="sortBy(\'tool\')" style="cursor:pointer">도구 ↕</th>'
        '<th onclick="sortBy(\'name\')" style="cursor:pointer">취약점명 ↕</th>'
        '<th onclick="sortBy(\'risk\')" style="cursor:pointer">위험도 ↕</th>'
        '<th>PoC 상태</th><th>URL</th><th>CWE</th><th>OWASP</th>'
        '</tr></thead>'
        '<tbody id="vulnBody"></tbody>'
        '</table></div></div>'
        '</div>'  # container
        '</body>'
    )

    # ── JavaScript (순수 문자열 — f-string 없음) ──────────────
    js_block = (
        '<script>'
        'var SLS_DATA = ' + chart_data_json + ';'
        'var SLS_VULNS = ' + vuln_json + ';'
        'var currentFilter = {risk: "ALL", poc: "", q: ""};'
        'var sortKey = "risk"; var sortAsc = true;'

        'function riskClass(r){'
        '  var m={"Critical":"r-critical","High":"r-high","Medium":"r-medium",'
        '         "Low":"r-low","Informational":"r-informational","Info":"r-info"};'
        '  return m[r]||"r-unknown";'
        '}'
        'function pocClass(p){'
        '  var m={"CONFIRMED":"p-confirmed","UNVERIFIED":"p-unverified","FALSE_POSITIVE":"p-false_positive"};'
        '  return m[p]||"r-unknown";'
        '}'

        'function renderTable(){'
        '  var rows = SLS_VULNS.filter(function(v){'
        '    if(currentFilter.risk !== "ALL" && v.risk !== currentFilter.risk) return false;'
        '    if(currentFilter.poc && v.poc_status !== currentFilter.poc) return false;'
        '    if(currentFilter.q){'
        '      var q=currentFilter.q.toLowerCase();'
        '      if(!((v.name||"").toLowerCase().includes(q)||(v.url||"").toLowerCase().includes(q)||(v.tool||"").toLowerCase().includes(q))) return false;'
        '    }'
        '    return true;'
        '  });'
        '  rows.sort(function(a,b){'
        '    var av=a[sortKey]||"", bv=b[sortKey]||"";'
        '    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);'
        '  });'
        '  var html="";'
        '  rows.forEach(function(v,i){'
        '    var rid="row-"+i;'
        '    html += "<tr id=\'" + rid + "\'>"'
        '      + "<td><button class=\'expand-btn\' onclick=\'toggle(\\\""+ rid +"\\\")\'>▶</button></td>"'
        '      + "<td>" + (v.tool||"") + "</td>"'
        '      + "<td>" + (v.name||"") + "</td>"'
        '      + "<td><span class=\'badge " + riskClass(v.risk) + "\'>" + (v.risk||"") + "</span></td>"'
        '      + "<td><span class=\'badge " + pocClass(v.poc_status) + "\'>" + (v.poc_status||"") + "</span></td>"'
        '      + "<td style=\'word-break:break-all;max-width:180px;font-size:11px\'>" + (v.url||"") + "</td>"'
        '      + "<td>" + (v.cwe||"") + "</td>"'
        '      + "<td style=\'font-size:11px\'>" + (v.owasp||"") + "</td>"'
        '      + "</tr>";'
        '    html += "<tr id=\'" + rid + "-detail\' class=\'detail-row\' style=\'display:none\'>"'
        '      + "<td colspan=\'8\' class=\'detail-cell\'>"'
        '      + "<strong>설명:</strong> " + (v.description||"-") + "<br>"'
        '      + "<strong>PoC 검증 근거:</strong> " + (v.poc_reason||v.evidence||"-") + "<br>"'
        '      + (v.cve_id ? "<strong>CVE:</strong> <a href=\\"https://nvd.nist.gov/vuln/detail/" + v.cve_id + "\\" target=\\"_blank\\">" + v.cve_id + "</a>&nbsp;&nbsp;" : "")'
        '      + (v.cvss_score ? "<strong>CVSS:</strong> " + v.cvss_score + " (" + (v.cvss_severity||"") + ")&nbsp;&nbsp;" : "")'
        '      + (v.cvss_vector ? "<span style=\\"font-size:11px;color:#666\\">" + v.cvss_vector + "</span><br>" : (v.cve_id ? "<br>" : ""))'
        '      + (v.patch_url ? "<strong>패치/참고:</strong> <a href=\\"" + v.patch_url + "\\" target=\\"_blank\\">" + v.patch_url.substring(0,80) + "...</a><br>" : "")'
        '      + "<strong>해결책:</strong> " + (v.solution||"-")'
        '      + "</td></tr>";'
        '  });'
        '  document.getElementById("vulnBody").innerHTML = html;'
        '}'

        'function toggle(id){'
        '  var d=document.getElementById(id+"-detail");'
        '  var b=document.querySelector("#"+id+" .expand-btn");'
        '  if(d.style.display==="none"){d.style.display="";b.textContent="▼";}'
        '  else{d.style.display="none";b.textContent="▶";}'
        '}'

        'function filterRisk(r){'
        '  currentFilter.risk=r;'
        '  document.querySelectorAll(".filter-btn").forEach(function(b){'
        '    b.classList.remove("active");'
        '    if(b.textContent===r||(r==="ALL"&&b.textContent==="전체")) b.classList.add("active");'
        '  });'
        '  renderTable();'
        '}'

        'function filterPoc(p){'
        '  currentFilter.poc = (currentFilter.poc===p)?"":p;'
        '  renderTable();'
        '}'

        'function sortBy(k){'
        '  if(sortKey===k){sortAsc=!sortAsc;}else{sortKey=k;sortAsc=true;}'
        '  renderTable();'
        '}'

        'document.getElementById("searchBox").addEventListener("input",function(){'
        '  currentFilter.q=this.value; renderTable();'
        '});'

        'renderTable();'

        'var cfg = {responsive:true, plugins:{legend:{labels:{color:"#aaa",font:{size:11}}}}};'

        'new Chart(document.getElementById("chartSeverity"),{'
        '  type:"doughnut",'
        '  data:{labels:SLS_DATA.severity.labels,'
        '    datasets:[{data:SLS_DATA.severity.data,backgroundColor:SLS_DATA.severity.colors,borderWidth:2,borderColor:"#1a1d27"}]},'
        '  options:Object.assign({},cfg,{cutout:"60%"})'
        '});'

        'new Chart(document.getElementById("chartTool"),{'
        '  type:"bar",'
        '  data:{labels:SLS_DATA.tool.labels,'
        '    datasets:[{data:SLS_DATA.tool.data,backgroundColor:SLS_DATA.tool.colors,borderRadius:4}]},'
        '  options:Object.assign({},cfg,{indexAxis:"y",'
        '    plugins:Object.assign({},cfg.plugins,{legend:{display:false}}),'
        '    scales:{x:{ticks:{color:"#aaa"},grid:{color:"#2d3561"}},'
        '            y:{ticks:{color:"#aaa"},grid:{display:false}}}})'
        '});'

        'new Chart(document.getElementById("chartPoc"),{'
        '  type:"pie",'
        '  data:{labels:SLS_DATA.poc.labels,'
        '    datasets:[{data:SLS_DATA.poc.data,backgroundColor:SLS_DATA.poc.colors,borderWidth:2,borderColor:"#1a1d27"}]},'
        '  options:cfg'
        '});'

        '</script></html>'
    )

    html = html_head + html_banner + html_summary + html_charts + html_ports + html_vuln_wrap + js_block

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [리포트] HTML 저장 (전문가용): {path}")


# ── 비전문가용 HTML ───────────────────────────────────────────
def export_html_plain(target, vulns, path, timestamp):
    confirmed  = [v for v in _sort(vulns) if v.get("poc_status") == "CONFIRMED"]
    unverified = [v for v in _sort(vulns) if v.get("poc_status") in ("UNVERIFIED","PENDING")]

    RISK_KO   = {"High":"🔴 높음","Critical":"🔴 매우 높음",
                 "Medium":"🟠 중간","Low":"🟡 낮음","Informational":"🔵 정보"}
    RISK_DESC = {
        "High":    "즉시 조치 필요 — 개인정보·시스템이 위험에 노출되어 있습니다.",
        "Critical":"매우 긴급 — 서비스 전체가 위협받을 수 있습니다.",
        "Medium":  "조속히 조치 필요 — 방치하면 더 큰 피해로 이어질 수 있습니다.",
        "Low":     "여유 있게 조치 — 단독으로는 피해가 크지 않지만 개선이 필요합니다.",
        "Informational": "참고 사항 — 보안 수준 향상에 도움이 됩니다.",
    }

    def card(v, idx):
        title, why, fix = _plain_desc(v.get("name",""))
        risk  = v.get("risk","")
        rdesc = RISK_DESC.get(risk, "")
        rko   = RISK_KO.get(risk, risk)
        bg    = {"High":"#FFF0F0","Critical":"#FFE0E0","Medium":"#FFF8E8","Low":"#F0F8FF"}.get(risk,"#F9F9F9")
        border= {"High":"#d9534f","Critical":"#8b0000","Medium":"#f0ad4e","Low":"#5bc0de"}.get(risk,"#ccc")
        url   = v.get("url","")
        return (
            '<div style="background:' + bg + ';border-left:4px solid ' + border + ';'
            'border-radius:0 10px 10px 0;padding:14px 18px;margin-bottom:14px">'
            '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">'
            '<div style="font-size:15px;font-weight:bold;color:#222">📌 ' + str(idx) + '. ' + title + '</div>'
            '<div style="font-size:12px;font-weight:bold;padding:3px 10px;background:' + border + ';'
            'color:white;border-radius:12px;white-space:nowrap">' + rko + '</div>'
            '</div>'
            '<div style="font-size:12px;color:#555;margin-bottom:4px">' + rdesc + '</div>'
            '<div style="margin:10px 0 6px;font-size:13px">'
            '<strong>🤔 왜 위험한가요?</strong><br>'
            '<span style="color:#333;line-height:1.7">' + why + '</span>'
            '</div>'
            '<div style="margin:6px 0;font-size:13px">'
            '<strong>✅ 어떻게 해결하나요?</strong><br>'
            '<span style="color:#333;line-height:1.7">' + fix + '</span>'
            '</div>'
            '<div style="margin-top:8px;font-size:11px;color:#888;font-family:monospace;'
            'background:rgba(0,0,0,0.05);padding:4px 8px;border-radius:4px;word-break:break-all">'
            '발견 위치: ' + (url if url else "전체 페이지") + '</div>'
            '</div>'
        )

    high_list   = [x for x in confirmed if x.get("risk") in ("High","Critical")]
    medium_list = [x for x in confirmed if x.get("risk") == "Medium"][:10]
    low_list    = [x for x in confirmed if x.get("risk") == "Low"][:5]

    high_cards   = "".join(card(v, i+1) for i, v in enumerate(high_list))
    medium_cards = "".join(card(v, i+1) for i, v in enumerate(medium_list))
    low_cards    = "".join(card(v, i+1) for i, v in enumerate(low_list))

    h_cnt = len(high_list)
    m_cnt = len(medium_list)
    l_cnt = len(low_list)

    # 차트 데이터
    sc = Counter(v.get("risk","") for v in confirmed)
    chart_json = json.dumps({
        "labels": ["High/Critical","Medium","Low"],
        "data":   [h_cnt, m_cnt, l_cnt],
        "colors": ["#d9534f","#f0ad4e","#5bc0de"],
    })

    tech_link = os.path.basename(path).replace("_report_simple.html","_report.html")

    html_css = (
        '<style>'
        '*{box-sizing:border-box;margin:0;padding:0}'
        "body{font-family:'Apple SD Gothic Neo','Malgun Gothic',Arial,sans-serif;"
        'background:#f0f2f5;color:#222}'
        '.header{background:linear-gradient(135deg,#1F4E79,#2E75B6);color:white;padding:28px 32px}'
        '.header h1{margin:0 0 6px;font-size:22px}'
        '.header p{margin:0;font-size:13px;opacity:.85}'
        '.content{max-width:820px;margin:0 auto;padding:24px 16px}'
        '.top-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:24px}'
        '.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}'
        '.sum-card{background:white;border-radius:12px;padding:16px;text-align:center;'
        'box-shadow:0 2px 8px rgba(0,0,0,.08)}'
        '.sum-n{font-size:32px;font-weight:bold;margin-bottom:4px}'
        '.sum-l{font-size:12px;color:#666}'
        '.chart-card{background:white;border-radius:12px;padding:16px;'
        'box-shadow:0 2px 8px rgba(0,0,0,.08);display:flex;flex-direction:column;align-items:center}'
        '.chart-card h3{font-size:13px;color:#555;margin-bottom:12px}'
        '.section-title{font-size:17px;font-weight:bold;margin:24px 0 12px;'
        'padding-left:10px;border-left:4px solid #1F4E79}'
        '.notice{background:#E8F4FD;border:1px solid #2E75B6;border-radius:10px;'
        'padding:14px 18px;margin-bottom:20px;font-size:13px;line-height:1.7}'
        '.footer{text-align:center;padding:20px;font-size:11px;color:#999}'
        '.tech-link{display:inline-block;margin-top:8px;color:rgba(255,255,255,.8);font-size:12px}'
        '</style>'
    )

    html_body = (
        '<div class="header">'
        '<h1>🛡️ 보안 점검 결과 보고서</h1>'
        '<p>대상: ' + target + ' &nbsp;|&nbsp; 점검 일시: ' + timestamp + '<br>'
        '이 보고서는 보안 전문 지식 없이도 이해하고 조치할 수 있도록 작성되었습니다.</p>'
        '<a href="' + tech_link + '" class="tech-link">🔧 전문가용 상세 리포트 →</a>'
        '</div>'
        '<div class="content">'
        '<div class="notice">'
        '💡 <strong>이 보고서 읽는 법:</strong> 아래 항목들은 자동화 도구가 발견한 보안 취약점입니다. '
        '각 항목에는 <strong>왜 위험한지</strong>와 <strong>어떻게 해결하는지</strong>가 담겨 있습니다. '
        '🔴 높음 항목부터 먼저 개발팀에 전달해 조치를 요청하세요.'
        '</div>'
        '<div class="top-grid">'
        '<div class="summary-grid">'
        '<div class="sum-card">'
        '<div class="sum-n" style="color:' + ('#d9534f' if h_cnt > 0 else '#5cb85c') + '">' + str(h_cnt) + '</div>'
        '<div class="sum-l">🔴 즉시 조치 필요<br>(높음/매우 높음)</div>'
        '</div>'
        '<div class="sum-card">'
        '<div class="sum-n" style="color:' + ('#f0ad4e' if m_cnt > 0 else '#5cb85c') + '">' + str(m_cnt) + '</div>'
        '<div class="sum-l">🟠 조속히 조치 필요<br>(중간)</div>'
        '</div>'
        '<div class="sum-card">'
        '<div class="sum-n" style="color:#5bc0de">' + str(l_cnt) + '</div>'
        '<div class="sum-l">🟡 여유 있게 조치<br>(낮음)</div>'
        '</div>'
        '</div>'
        '<div class="chart-card"><h3>확정 취약점 분포</h3>'
        '<canvas id="plainChart" width="160" height="160"></canvas>'
        '</div>'
        '</div>'
        + ('<div class="section-title">🔴 즉시 조치가 필요한 항목</div>' + high_cards if h_cnt > 0 else '')
        + ('<div class="section-title">🟠 조속히 조치가 필요한 항목</div>' + medium_cards if m_cnt > 0 else '')
        + ('<div class="section-title">🟡 여유 있게 조치할 항목</div>' + low_cards if l_cnt > 0 else '')
        + '<div class="notice" style="margin-top:24px;background:#F0FFF0;border-color:#5cb85c">'
        '✅ <strong>조치 완료 후:</strong> 개발팀이 수정을 완료하면 동일한 스캔을 다시 실행해 '
        '해당 항목이 사라졌는지 확인하세요.'
        '</div>'
        '</div>'
        '<div class="footer">Shift-Left-Sync 자동 보안 스캔 | ' + timestamp + '</div>'
    )

    html_js = (
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>'
        '<script>'
        'var pd = ' + chart_json + ';'
        'new Chart(document.getElementById("plainChart"),{'
        '  type:"doughnut",'
        '  data:{labels:pd.labels,datasets:[{data:pd.data,backgroundColor:pd.colors,borderWidth:2}]},'
        '  options:{responsive:false,cutout:"55%",'
        '    plugins:{legend:{position:"bottom",labels:{font:{size:10},color:"#666"}}}}'
        '});'
        '</script>'
    )

    html = (
        '<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">'
        '<title>[간편] 보안 점검 결과 — ' + target + '</title>'
        + html_css +
        '</head><body>'
        + html_body + html_js +
        '</body></html>'
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [리포트] HTML 저장 (비전문가용): {path}")


def print_summary(vulns):
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
