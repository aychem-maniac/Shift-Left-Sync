#!/bin/bash
# ============================================================
#  Fix 1. Nikto 미작동 해결 스크립트
#  실행 위치: Shift-Left-Sync/ 프로젝트 루트
# ============================================================

echo "[1/3] Dockerfile 수정 중..."

# perl 라인을 perl + 필요 모듈로 교체
sed -i 's/    perl \\/    perl \\\n    libnet-ssleay-perl \\\n    libio-socket-ssl-perl \\\n    liburi-perl \\\n    libwww-perl \\/' Dockerfile

echo "[완료] Dockerfile 수정됨"

echo ""
echo "[2/3] Docker 이미지 재빌드 중... (수 분 소요)"
docker-compose build --no-cache scanner

echo ""
echo "[3/3] 컨테이너 재시작 중..."
docker-compose up -d

echo ""
echo "=== 설치 확인 ==="
sleep 5
docker exec sls_scanner nikto -Version 2>&1 | head -3

echo ""
echo "[완료] Nikto 설치 확인 완료"
