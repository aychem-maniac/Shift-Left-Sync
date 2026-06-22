# Shift-Left-Sync (SLS)

> 웹 애플리케이션 보안 취약점을 자동으로 스캔하고 PoC 검증까지 수행하는 통합 보안 점검 플랫폼

---

## 목차

- [프로젝트 개요](#프로젝트-개요)
- [아키텍처](#아키텍처)
- [환경 구성 — Ubuntu VM 초기 세팅](#환경-구성--ubuntu-vm-초기-세팅)
- [설치 및 실행](#설치-및-실행)
- [환경 변수 설정](#환경-변수-설정)
- [접속 및 사용법](#접속-및-사용법)
- [WAF 및 보안 이벤트 관리](#waf-및-보안-이벤트-관리)
- [Observability](#observability)
- [소유권 검증 (Ownership Verification)](#소유권-검증-ownership-verification)
- [디렉토리 구조](#디렉토리-구조)
- [주의 사항](#주의-사항)

---

## 프로젝트 개요

Shift-Left-Sync는 6가지 오픈소스 보안 스캐너(OWASP ZAP, Nmap, SQLMap, Nikto, Nuclei, Header Scanner)를 하나의 파이프라인으로 통합하고, 탐지된 취약점에 대해 PoC 자동 검증까지 수행하는 플랫폼입니다.

**주요 기능**

- OWASP ZAP / Nmap / SQLMap / Nikto / Nuclei / Header Scanner 통합 스캔
- 스캔 전 타겟 소유권 검증 (파일 업로드 / 메타태그 방식)
- 취약점 결과를 OWASP Top 10 2025 카테고리로 자동 매핑
- XSS canary 반사, SQLi 에러/시간 기반, CORS, 쿠키 속성 등 PoC 자동 검증
- 결과를 `CONFIRMED / UNVERIFIED / FALSE_POSITIVE`로 분류
- CSV, JSON, HTML 멀티 포맷 리포트 자동 생성
- FastAPI 기반 웹 대시보드 (스캔 요청, 결과 조회, 관리자 페이지)
- OWASP ModSecurity CRS 기반 WAF 프록시와 보안 이벤트 관리 화면
- Loki / Alloy / Grafana 기반 WAF 로그 관측 대시보드
- CLI 모드 지원 (`python main.py scan --target <URL>`)

---

## 아키텍처

```
[사용자]
   │
   ├─ Web UI / API
   │     http://<HOST>:8088
   │     WAF 프록시(OWASP ModSecurity CRS)
   │
   └─ CLI (main.py)
           │
     [Web UI 전용] 소유권 검증 (pending_verify)
     └─ 파일 업로드 또는 메타태그 삽입으로 타겟 소유권 확인
     └─ 검증 통과 후 스캔 큐 진입
           │
     scanner FastAPI (:8000, compose 내부 expose)
           │
     core/pipeline.py
           │
     ┌─────┴──────┐
     │  병렬 스캔  │  (ThreadPoolExecutor)
     │  Nmap      │
     │  SQLMap    │
     │  Header    │
     │  Nikto     │
     │  Nuclei    │
     └─────┬──────┘
           │  + ZAP (sls_zap 컨테이너)
           │
     normalizers/   ← 이종 결과 → Vuln 데이터클래스 통합
           │
     verifiers/     ← PoC 자동 검증
           │
     reports/       ← CSV / JSON / HTML 출력
           │
     SQLite (data/sls.db)
           │
     admin/security ← WAF 로그, 차단 IP, 보안 이벤트 관리
```

**Docker Compose 구성**

| 컨테이너 | 이미지 | 호스트 포트 | 역할 |
|---|---|---:|---|
| `sls_waf` | `owasp/modsecurity-crs:nginx` | 8088 | FastAPI 앞단 WAF 프록시 |
| `sls_scanner` | `./Dockerfile` (python:3.12-slim) | 내부 expose 8000 | FastAPI 웹 서버 + 스캐너 |
| `sls_zap` | `ghcr.io/zaproxy/zaproxy:stable` | 8091 | OWASP ZAP 데몬 상태 확인/API |
| `juice-shop` | `bkimminich/juice-shop:v20.0.0` | 3000 | 테스트 대상 애플리케이션 |
| `sls_waf_log_init` | `busybox:1.36` | - | WAF audit log 파일 초기화 |

**Observability 구성**

| 컨테이너 | 이미지 | 호스트 포트 | 역할 |
|---|---|---:|---|
| `sls_loki` | `grafana/loki:3.7.2` | - | WAF 로그 저장소 |
| `sls_alloy` | `grafana/alloy:v1.16.3` | - | WAF audit log 수집 |
| `sls_grafana` | `grafana/grafana:13.0.2` | 3001 | WAF 보안 대시보드 |

---

## 환경 구성 — Ubuntu VM 초기 세팅

> VMware에 Ubuntu 22.04 / 24.04를 새로 설치한 상태 기준

### 1단계 — 시스템 패키지 업데이트

```bash
sudo apt update && sudo apt upgrade -y
```

### 2단계 — 기본 도구 설치

```bash
sudo apt install -y \
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    build-essential
```

### 3단계 — Docker 설치

```bash
# Docker 공식 GPG 키 추가
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Docker 레포지토리 등록
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Docker Engine + Compose 설치
sudo apt update
sudo apt install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# sudo 없이 docker 명령 사용 (재로그인 필요)
sudo usermod -aG docker $USER
newgrp docker

# 설치 확인
docker --version
docker compose version
```

### 4단계 — Git 설정 (클론 전 필요 시)

```bash
git config --global user.name "이름"
git config --global user.email "이메일@example.com"
```

---

## 설치 및 실행

### 1. 레포지토리 클론

```bash
git clone --branch feature/sls-waf-api \
    https://github.com/aychem-maniac/Shift-Left-Sync.git
cd Shift-Left-Sync
```

### 2. 환경 변수 파일 생성

```bash
cp .env.example .env
# 필요 시 .env 내용 수정 (아래 환경 변수 섹션 참고)
```

### 3. 결과/데이터/로그 디렉토리 생성

```bash
mkdir -p results/reports data logs/waf
```

### 4. 기본 Docker Compose 빌드 및 실행

```bash
# 최초 실행 (이미지 빌드 포함)
docker compose up --build -d

# 이후 재실행 시
docker compose up -d
```

### 5. Observability 포함 실행

WAF 로그를 Grafana에서 확인하려면 observability compose 파일을 함께 올립니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up --build -d
```

### 6. 컨테이너 상태 확인

```bash
docker compose ps
```

정상 실행 시 주요 컨테이너가 아래와 같이 표시됩니다.

```
NAME                 STATUS
sls_zap              running (healthy)
sls_scanner          running
sls_waf              running
sls_waf_log_init     exited (0)
```

Observability를 함께 실행한 경우:

```
sls_loki             running
sls_alloy            running
sls_grafana          running
```

> `sls_scanner`는 `sls_zap`의 헬스체크가 통과된 이후 자동으로 시작됩니다.  
> ZAP 초기화에 약 40~60초 소요될 수 있습니다.

### 7. 로그 확인

```bash
# 전체 로그
docker compose logs -f

# 스캐너만
docker compose logs -f scanner

# ZAP만
docker compose logs -f zap

# WAF만
docker compose logs -f waf

# WAF audit log
tail -f logs/waf/audit.log
```

### 8. 종료

```bash
docker compose down
```

Observability까지 함께 실행한 경우:

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml down
```

---

## 환경 변수 설정

`.env` 파일 또는 `docker-compose.yml`의 `environment` 항목에서 설정합니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ZAP_ADDRESS` | `zap` | ZAP 데몬 호스트 (컨테이너 내부 서비스명) |
| `ZAP_PORT` | `8080` | ZAP 데몬 포트 |
| `ZAP_API_KEY` | `sls-secret-2026` | ZAP API 키 |
| `DB_PATH` | `data/sls.db` | SQLite DB 경로 |
| `API_KEY` | `sls-secret-2026` | Web API 인증 키 |
| `TZ` | `Asia/Seoul` | 컨테이너 시간대 |
| `MAX_CONCURRENT_SCANS` | `3` | 동시 스캔 제한 |
| `WAF_AUDIT_LOG_PATH` | `/app/logs/waf/audit.log` | scanner가 읽는 WAF audit log 경로 |
| `WAF_RULE_ENGINE` | `DetectionOnly` | WAF 룰 엔진 모드 |
| `WAF_BLOCKLIST_RULE_PATH` | `/app/config/waf/ip-blocklist.conf` | WAF IP 차단 룰 파일 경로 |
| `WAF_RELOAD_COMMAND` | `docker exec sls_waf nginx -s reload` | WAF 설정 재적용 명령 |

---

## 접속 및 사용법

### 웹 대시보드

WAF를 통해 접속합니다.

```
http://<VM_IP>:8088
```

로컬 실행 기준:

```
http://localhost:8088
```

기본 관리자 계정

| 항목 | 값 |
|---|---|
| ID | `admin` |
| PW | `admin1234` |

> 최초 접속 후 반드시 비밀번호를 변경하세요.

### 주요 접속 포트

| 주소 | 설명 |
|---|---|
| `http://localhost:8088` | WAF를 통한 SLS 웹/API 접근 |
| `http://localhost:8091` | ZAP API 상태 확인용 |
| `http://localhost:3000` | Juice Shop 직접 접근 |
| `http://localhost:3001` | Grafana |

### CLI 모드 (컨테이너 내부)

```bash
# 단일 타겟
docker exec -it sls_scanner python main.py scan --target http://example.com

# 복수 타겟 + 스캔 강도 지정 (low / medium / high)
docker exec -it sls_scanner python main.py scan \
    --target http://target1.com \
    --target http://target2.com \
    --strength high
```

### 결과 파일 위치

스캔 완료 후 `results/reports/` 디렉토리에 아래 형식으로 저장됩니다.

```
results/reports/
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_confirmed.csv
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_unverified.csv
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_false_positive.csv
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_full.csv
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_full.json
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_report.html
└── <IP>_<PORT>_<YYYYMMDD>_<HHMMSS>_report_simple.html
```

---

## WAF 및 보안 이벤트 관리

현재 브랜치는 FastAPI 앞단에 OWASP ModSecurity CRS 기반 WAF 프록시를 둡니다. 기본 WAF 모드는 `DetectionOnly`이며, 차단 전 탐지 로그를 먼저 확인하는 구성을 기본으로 합니다.

### 관리자 화면

```
http://<VM_IP>:8088/admin/security
```

`/admin/security` 화면에서 확인할 수 있는 항목:

- WAF 탐지 이벤트
- 대응/요약 로그
- IP 차단 목록
- WAF 룰 재적용
- 이벤트 필터링 및 통계

### WAF / 보안 이벤트 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/api/waf/blocklist` | IP 차단 목록 조회 |
| `POST` | `/api/waf/blocklist` | IP 차단 추가 |
| `POST` | `/api/waf/blocklist/remove` | IP 차단 해제 |
| `POST` | `/api/waf/blocklist/{ip}` | 특정 IP 차단 |
| `DELETE` | `/api/waf/blocklist/{ip}` | 특정 IP 차단 삭제 |
| `POST` | `/api/waf/reload` | WAF reload 실행 |
| `POST` | `/api/waf/reload/apply` | WAF 룰 적용 후 reload |
| `GET` | `/api/security/events` | 보안 이벤트 목록 조회 |
| `GET` | `/api/security/stats` | 보안 이벤트 통계 조회 |

### 관련 DB 테이블

| 테이블 | 설명 |
|---|---|
| `security_events` | WAF/SOAR 보안 이벤트 저장 |
| `waf_ip_blocklist` | WAF IP 차단 목록 저장 |

### 관련 파일

| 경로 | 설명 |
|---|---|
| `logs/waf/audit.log` | WAF JSON audit log |
| `config/waf/ip-blocklist.conf` | IP 차단 룰 |
| `config/waf/sls-custom-rules.conf` | SLS 커스텀 WAF 룰 |
| `config/waf/nginx-hardening.sh` | WAF nginx 기본 응답 하드닝 |
| `templates/admin/security.html` | 보안 이벤트 관리자 화면 |

---

## Observability

WAF 로그 관측은 Loki, Alloy, Grafana로 구성합니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up --build -d
```

로그 흐름:

```
logs/waf/audit.log
   ↓
sls_alloy
   ↓
sls_loki
   ↓
sls_grafana
```

Grafana 접속:

```
http://localhost:3001
```

기본 계정:

| 항목 | 값 |
|---|---|
| ID | `admin` |
| PW | `admin1234` |

관련 대시보드:

```
observability/grafana/dashboards/waf-security.json
```

---

## 소유권 검증 (Ownership Verification)

Web UI를 통해 스캔을 요청하면 **스캔 실행 전 타겟 서버의 소유권을 먼저 확인**합니다.  
허가되지 않은 대상에 대한 무단 스캔을 방지하기 위한 단계입니다.

> CLI 모드(`python main.py scan`)는 소유권 검증 없이 즉시 스캔을 시작합니다.

### 전체 흐름

```
1. 스캔 요청 (POST /api/scan)
   └─ 고유 토큰 발급: SLS-VERIFY-XXXXXXXXXXXXXXXX
   └─ job status → "pending_verify" (스캔 대기)

2. 소유권 인증 방법 안내 (대시보드 자동 표시)
   ├─ 방법 1 — 파일 업로드
   │     http://타겟URL/.well-known/sls-verify.txt
   │     파일 내용: 발급된 토큰 문자열
   │
   └─ 방법 2 — 메타태그 삽입
         홈페이지 <head> 안에 아래 태그 추가
         <meta name="sls-verify" content="SLS-VERIFY-XXXXXXXXXXXXXXXX">

3. 소유권 확인 버튼 클릭 (POST /api/scan/{job_id}/verify)
   └─ 서버가 파일 URL 또는 루트 페이지 메타태그 토큰 포함 여부 자동 확인
   └─ 검증 성공 → job status → "queued" → 스캔 자동 시작
   └─ 검증 실패 → 재시도 안내 (파일/메타태그 확인 후 재시도)
```

### 인증 상태값

| 상태 | 설명 |
|---|---|
| `pending_verify` | 소유권 인증 대기 중 (스캔 미시작) |
| `verified` | 인증 완료 |
| `failed` | 인증 실패 (토큰 미확인) |
| `queued` | 인증 완료 후 스캔 대기 중 |

---

## 디렉토리 구조

```
Shift-Left-Sync/
├── api.py                  # FastAPI 웹 서버 (라우터, 대시보드)
├── main.py                 # CLI 진입점
├── database.py             # SQLite CRUD
├── Dockerfile
├── docker-compose.yml
├── docker-compose.observability.yml
├── requirements.txt
│
├── config/
│   ├── settings.py         # ZAP 연결, OWASP 매핑, 스캔 강도 설정
│   └── waf/                # WAF 차단 룰, 커스텀 룰, nginx 하드닝
│
├── sls_scanner/
│   ├── cli/runner.py       # CLI argparse 처리
│   ├── core/pipeline.py    # 스캔 → 정규화 → PoC → 리포트 파이프라인
│   ├── scanners/           # ZAP / Nmap / SQLMap / Header / Nikto / Nuclei
│   ├── normalizers/        # 스캐너별 결과 → Vuln 데이터클래스 통합
│   ├── verifiers/          # PoC 자동 검증 (XSS / SQLi / Header / Cookie 등)
│   ├── reports/            # CSV, JSON, HTML 리포트 생성
│   └── evaluators/         # 위험도 점수 평가
│
├── templates/
│   └── admin/security.html # WAF/보안 이벤트 관리자 화면
├── static/                 # CSS, JS
├── data/                   # SQLite DB (sls.db)
├── logs/waf/               # WAF audit log
├── results/                # 스캔 결과 파일 저장
├── observability/          # Loki / Alloy / Grafana 설정
│   └── grafana/dashboards/
│       └── waf-security.json
└── docs/
```

---

## 주의 사항

- **반드시 허가된 대상에만 스캔을 수행하세요.** 무단 스캔은 법적 책임이 따릅니다.
- Web UI 스캔은 소유권 검증 통과 후에만 실행됩니다. 타겟 서버에 파일 업로드 또는 메타태그 삽입 권한이 없으면 스캔을 진행할 수 없습니다.
- CLI 모드는 소유권 검증을 거치지 않으므로 내부망 점검 등 허가된 환경에서만 사용하세요.
- 외부 사용자는 기본적으로 WAF 포트 `8088`을 통해 접근합니다. `scanner`의 `8000` 포트는 compose 내부 서비스로 유지합니다.
- 기본 WAF 모드는 `DetectionOnly`입니다. 차단 모드로 바꾸기 전 `/admin/security`와 Grafana에서 탐지 로그를 먼저 확인하세요.
- ZAP 컨테이너(`sls_zap`)가 `healthy` 상태가 되기 전에 스캔을 시작하면 ZAP 결과가 누락될 수 있습니다.
- `data/sls.db`, `results/`, `logs/waf/` 디렉토리는 볼륨 마운트로 컨테이너 재시작 시에도 데이터가 유지됩니다.
- `ghcr.io/zaproxy/zaproxy:stable`과 `owasp/modsecurity-crs:nginx`는 고정 버전 태그가 아니므로 이미지 갱신 시 동작 차이가 생길 수 있습니다.
- Nuclei 바이너리는 `3.8.0`으로 고정되어 있지만, `nuclei -update-templates -silent`은 빌드 시점의 최신 템플릿을 가져옵니다.
