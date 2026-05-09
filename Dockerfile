# Ubuntu + Docker 환경 최적화
FROM python:3.12-slim

# 시스템 도구 설치
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    curl \
    wget \
    unzip \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Nuclei 최신 바이너리 설치 (Linux amd64)
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4 | sed 's/v//') \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
    -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# Nuclei 템플릿 다운로드 (빌드 시 1회)
RUN nuclei -update-templates -silent || true

WORKDIR /app

# Python 패키지 (캐시 레이어 활용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 복사
COPY . .

RUN mkdir -p results/reports

# Docker 내부에서는 ZAP 컨테이너명으로 연결
ENV ZAP_ADDRESS=zap
ENV ZAP_PORT=8080
ENV ZAP_API_KEY=

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
