FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    unzip \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    liburi-perl \
    libwww-perl \
    libjson-perl \
    libxml-writer-perl \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

RUN NUCLEI_VER=3.8.0 \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
    -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

RUN nuclei -update-templates -silent || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p results/reports

ENV ZAP_ADDRESS=zap
ENV ZAP_PORT=8080
ENV ZAP_API_KEY=

EXPOSE 8000
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
