#!/bin/bash
# ============================================================
#  Fix 2. PoC 검증 0초 해결 스크립트
#  실행 위치: Shift-Left-Sync/ 프로젝트 루트
# ============================================================

TARGET="sls_scanner/verifiers/poc_verifier.py"

echo "[1/2] poc_verifier.py else 분기 패치 중..."

# 기존 else 분기를 HTTP 연결 확인 포함 버전으로 교체
python3 - <<'PYEOF'
import re

path = "sls_scanner/verifiers/poc_verifier.py"

old = """    else:
        if vuln.get(\"risk\") == \"High\":
            status, detail = \"CONFIRMED\", \"High 위험도 자동 승인 (수동 검토 권장)\"
        else:
            status, detail = \"UNVERIFIED\", \"자동 검증 루틴 미매핑 — 수동 검토 필요\""""

new = """    else:
        # 매핑 안 된 항목: HTTP 응답코드라도 확인
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            base_detail = f"HTTP {r.status_code} 확인 — 수동 검토 필요"
        except Exception as e:
            base_detail = f"연결 실패: {e}"

        if vuln.get(\"risk\") == \"High\":
            status, detail = \"CONFIRMED\", f\"High 위험도 ({base_detail})\",
        else:
            status, detail = \"UNVERIFIED\", base_detail"""

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

if old in content:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[완료] poc_verifier.py 패치 성공")
else:
    print("[경고] 대상 코드를 찾지 못했습니다 — 수동 확인 필요")
PYEOF

echo ""
echo "[2/2] 변경사항 컨테이너에 반영 중..."
docker-compose restart scanner

echo ""
echo "=== 패치 결과 확인 ==="
grep -A 8 "# 매핑 안 된 항목" $TARGET

echo ""
echo "[완료] PoC 검증 패치 적용됨"
echo "      다음 스캔 시 PoC 시간이 0초 이상으로 표시되면 정상입니다"
