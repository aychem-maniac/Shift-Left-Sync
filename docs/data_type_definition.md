# 데이터 타입 정의 문서

##  GPT 사용 시 데이터 타입 요청 프롬프트

팀원이 GPT에게 코드를 요청할 때는 아래 프롬프트를 함께 사용할 수 있다.

~~~text
나는 Shift-Left-Sync 프로젝트를 개발하고 있다.

이 프로젝트의 데이터 타입 기준은 다음과 같다.

1. target
- 타입: str
- 의미: 점검 대상 URL 또는 IP

2. port_result
- 타입: dict
- 필드:
  - host: str
  - port: int
  - protocol: str
  - service: str
  - state: str
  - product: str
  - version: str

3. port_results
- 타입: list[dict]
- 의미: 여러 개의 포트 스캔 결과 목록

4. finding
- 타입: dict
- 필드:
  - id: str
  - source: str
  - name: str
  - severity: str
  - confidence: str
  - description: str
  - url: str
  - evidence: str
  - solution: str
  - reference: str

5. findings
- 타입: list[dict]
- 의미: 여러 개의 취약점 결과 목록

6. severity 허용 값:
- Critical
- High
- Medium
- Low
- Info
- Unknown

현재 작업 파일:
[여기에 파일 경로 작성]

구현할 함수:
[여기에 함수 이름 작성]

입력값:
[여기에 입력값 작성]

반환값:
[여기에 반환값 작성]

요청 사항:
위 데이터 타입 기준을 반드시 지켜서 코드를 작성해줘.
반환되는 dict의 필드명도 위 기준과 동일하게 맞춰줘.
주요 코드에는 한국어 주석을 작성해줘.
~~~

---



## 1. 문서 목적

이 문서는 `Shift-Left-Sync` 프로젝트에서 사용하는 주요 데이터 구조를 정의하기 위한 문서이다.

프로젝트는 Nmap 포트 스캔, OWASP ZAP 웹 취약점 스캔, 결과 정규화, 위험도 평가, 리포트 생성을 단계별로 수행한다.

각 단계에서 주고받는 데이터 형식이 서로 다르면 기능 통합 과정에서 오류가 발생할 수 있다.  
따라서 본 문서는 팀원들이 동일한 데이터 구조를 기준으로 개발할 수 있도록 공통 데이터 타입을 정의한다.

---

## 2. 전체 데이터 흐름

프로젝트의 기본 데이터 흐름은 다음과 같다.

~~~text
사용자 입력 target
        ↓
대상 검증 결과 target_info
        ↓
Nmap 원시 결과 raw_nmap_result
        ↓
Nmap 정규화 결과 port_results
        ↓
OWASP ZAP 원시 결과 raw_zap_result
        ↓
ZAP 정규화 결과 findings
        ↓
위험도 평가 결과 evaluated_findings
        ↓
HTML / CSV 리포트 report_result
~~~

---

## 3. 기본 타입 기준

프로젝트에서 사용하는 기본 타입 기준은 다음과 같다.

~~~text
str        → 문자열 데이터
int        → 숫자 데이터
bool       → 참 또는 거짓
list       → 여러 개의 데이터를 순서대로 담는 구조
dict       → key-value 형태의 데이터 구조
list[dict] → 여러 개의 딕셔너리를 담는 리스트
None       → 반환값이 없음을 의미
~~~

Python 타입 힌트 예시는 다음과 같다.

~~~python
target: str
is_valid: bool
port: int
findings: list[dict]
raw_result: dict
~~~

---

## 4. `target` 데이터 정의

`target`은 사용자가 입력한 점검 대상 URL 또는 IP 주소를 의미한다.

### 4.1 타입

~~~python
target: str
~~~

### 4.2 예시

~~~python
target = "http://example.com"
target = "https://example.com"
target = "192.168.0.1"
~~~

### 4.3 허용 형식

~~~text
- http:// 로 시작하는 URL
- https:// 로 시작하는 URL
- IPv4 주소
- IPv6 주소
~~~

### 4.4 허용하지 않는 형식

~~~text
- 빈 문자열
- 단순 문자열
- 공백만 있는 문자열
- URL 스킴이 없는 도메인
~~~

예시는 다음과 같다.

~~~python
target = ""
target = "example"
target = "example.com"
target = "   "
~~~

---

## 5. `target_info` 데이터 정의

`target_info`는 대상 검증 이후 사용할 수 있는 대상 정보를 정리한 데이터이다.

초기 버전에서는 반드시 구현하지 않아도 되지만, 이후 확장을 고려해 기준을 정의한다.

### 5.1 타입

~~~python
target_info: dict
~~~

### 5.2 구조

~~~python
target_info = {
    "target": "http://example.com",
    "target_type": "url",
    "is_valid": True
}
~~~

### 5.3 필드 설명

| 필드명         | 타입   | 설명                   |
|---            |---:   |---                     |
| `target`      | `str` | 사용자가 입력한 원본 대상 |
| `target_type` | `str` | 대상 종류               |
| `is_valid`    | `bool`| 대상 형식 검증 결과       |

### 5.4 `target_type` 허용 값

~~~text
url
ipv4
ipv6
unknown
~~~

---

## 6. `raw_nmap_result` 데이터 정의

`raw_nmap_result`는 Nmap 실행 후 수집한 원시 결과를 의미한다.

이 데이터는 Nmap 실행 함수에서 반환되며, 아직 프로젝트 표준 형식으로 정리되지 않은 상태이다.

### 6.1 타입

~~~python
raw_nmap_result: dict
~~~

### 6.2 예시 구조

~~~python
raw_nmap_result = {
    "host": "192.168.0.10",
    "scan_result": {
        "tcp": {
            80: {
                "state": "open",
                "name": "http",
                "product": "nginx"
            },
            443: {
                "state": "open",
                "name": "https",
                "product": "nginx"
            }
        }
    }
}
~~~

### 6.3 사용 위치

~~~text
생성 위치:
- sls_scanner/scanners/nmap_scanner.py

사용 위치:
- sls_scanner/normalizers/nmap_normalizer.py
~~~

### 6.4 주의 사항

`raw_nmap_result`는 외부 도구의 결과에 가까운 데이터이므로, 리포트 생성 단계에서 직접 사용하지 않는다.

리포트 생성 단계에서는 반드시 정규화된 `port_results`를 사용한다.

---

## 7. `port_result` 데이터 정의

`port_result`는 하나의 포트 스캔 결과를 의미한다.

### 7.1 타입

~~~python
port_result: dict
~~~

### 7.2 구조

~~~python
port_result = {
    "host": "192.168.0.10",
    "port": 80,
    "protocol": "tcp",
    "service": "http",
    "state": "open",
    "product": "nginx",
    "version": ""
}
~~~

### 7.3 필드 설명

| 필드명 | 타입 | 필수 여부 | 설명 |
|---|---:|---:|---|
| `host` | `str` | 필수 | 스캔 대상 호스트 |
| `port` | `int` | 필수 | 포트 번호 |
| `protocol` | `str` | 필수 | 프로토콜 |
| `service` | `str` | 필수 | 서비스 이름 |
| `state` | `str` | 필수 | 포트 상태 |
| `product` | `str` | 선택 | 서비스 제품명 |
| `version` | `str` | 선택 | 서비스 버전 |

### 7.4 허용 값 예시

`protocol` 예시는 다음과 같다.

~~~text
tcp
udp
~~~

`state` 예시는 다음과 같다.

~~~text
open
closed
filtered
unknown
~~~

---

## 8. `port_results` 데이터 정의

`port_results`는 여러 개의 포트 스캔 결과를 담는 리스트이다.

### 8.1 타입

~~~python
port_results: list[dict]
~~~

### 8.2 구조

~~~python
port_results = [
    {
        "host": "192.168.0.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "state": "open",
        "product": "nginx",
        "version": ""
    },
    {
        "host": "192.168.0.10",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "state": "open",
        "product": "nginx",
        "version": ""
    }
]
~~~

### 8.3 사용 위치

~~~text
생성 위치:
- sls_scanner/normalizers/nmap_normalizer.py

사용 위치:
- sls_scanner/core/pipeline.py
- sls_scanner/reports/html_report.py
~~~

---

## 9. `raw_zap_result` 데이터 정의

`raw_zap_result`는 OWASP ZAP 실행 후 수집한 원시 결과를 의미한다.

이 데이터는 ZAP 실행 함수에서 반환되며, 아직 프로젝트 표준 취약점 형식으로 정리되지 않은 상태이다.

### 9.1 타입

~~~python
raw_zap_result: dict
~~~

### 9.2 예시 구조

~~~python
raw_zap_result = {
    "alerts": [
        {
            "name": "Missing Anti-clickjacking Header",
            "risk": "Medium",
            "confidence": "Medium",
            "description": "The response does not include X-Frame-Options header.",
            "url": "http://example.com",
            "solution": "Include the X-Frame-Options header.",
            "reference": "https://developer.mozilla.org/"
        }
    ]
}
~~~

### 9.3 사용 위치

~~~text
생성 위치:
- sls_scanner/scanners/zap_scanner.py

사용 위치:
- sls_scanner/normalizers/zap_normalizer.py
~~~

### 9.4 주의 사항

`raw_zap_result`는 외부 도구 결과에 가까운 데이터이므로, 위험도 평가와 리포트 생성 단계에서 직접 사용하지 않는다.

위험도 평가와 리포트 생성 단계에서는 반드시 정규화된 `findings`를 사용한다.

---

## 10. `finding` 데이터 정의

`finding`은 하나의 취약점 또는 보안 점검 결과를 의미한다.

### 10.1 타입

~~~python
finding: dict
~~~

### 10.2 구조

~~~python
finding = {
    "id": "ZAP-001",
    "source": "zap",
    "name": "Missing Anti-clickjacking Header",
    "severity": "Medium",
    "confidence": "Medium",
    "description": "The response does not include X-Frame-Options header.",
    "url": "http://example.com",
    "evidence": "",
    "solution": "Include the X-Frame-Options header.",
    "reference": "https://developer.mozilla.org/"
}
~~~

### 10.3 필드 설명

| 필드명 | 타입 | 필수 여부 | 설명 |
|---|---:|---:|---|
| `id` | `str` | 선택 | 취약점 또는 점검 항목 식별자 |
| `source` | `str` | 필수 | 결과를 생성한 도구 또는 모듈 |
| `name` | `str` | 필수 | 취약점 또는 점검 항목 이름 |
| `severity` | `str` | 필수 | 위험도 등급 |
| `confidence` | `str` | 선택 | 탐지 신뢰도 |
| `description` | `str` | 필수 | 취약점 설명 |
| `url` | `str` | 필수 | 취약점이 탐지된 URL |
| `evidence` | `str` | 선택 | 탐지 근거 |
| `solution` | `str` | 선택 | 조치 방안 |
| `reference` | `str` | 선택 | 참고 자료 |

---

## 11. `findings` 데이터 정의

`findings`는 여러 개의 취약점 결과를 담는 리스트이다.

### 11.1 타입

~~~python
findings: list[dict]
~~~

### 11.2 구조

~~~python
findings = [
    {
        "id": "ZAP-001",
        "source": "zap",
        "name": "Missing Anti-clickjacking Header",
        "severity": "Medium",
        "confidence": "Medium",
        "description": "The response does not include X-Frame-Options header.",
        "url": "http://example.com",
        "evidence": "",
        "solution": "Include the X-Frame-Options header.",
        "reference": "https://developer.mozilla.org/"
    },
    {
        "id": "ZAP-002",
        "source": "zap",
        "name": "Cookie Without Secure Flag",
        "severity": "Low",
        "confidence": "High",
        "description": "A cookie was set without the Secure attribute.",
        "url": "http://example.com",
        "evidence": "Set-Cookie: sessionid=abc123",
        "solution": "Set the Secure attribute on cookies.",
        "reference": ""
    }
]
~~~

### 11.3 사용 위치

~~~text
생성 위치:
- sls_scanner/normalizers/zap_normalizer.py
- 이후 추가될 보안 헤더 점검 모듈
- 이후 추가될 쿠키 점검 모듈
- 이후 추가될 HTML 폼 탐지 모듈

사용 위치:
- sls_scanner/evaluators/risk_evaluator.py
- sls_scanner/reports/html_report.py
- sls_scanner/reports/csv_report.py
~~~

---

## 12. `severity` 데이터 정의

`severity`는 취약점 또는 점검 결과의 위험도 등급을 의미한다.

### 12.1 타입

~~~python
severity: str
~~~

### 12.2 허용 값

~~~text
Critical
High
Medium
Low
Info
Unknown
~~~

### 12.3 설명

| 등급 | 설명 |
|---|---|
| `Critical` | 즉시 조치가 필요한 매우 높은 위험 |
| `High` | 빠른 조치가 필요한 높은 위험 |
| `Medium` | 점검 후 조치가 필요한 중간 위험 |
| `Low` | 보안 개선이 필요한 낮은 위험 |
| `Info` | 참고용 정보 |
| `Unknown` | 위험도를 판단할 수 없음 |

### 12.4 주의 사항

위험도 값은 대소문자를 통일한다.

좋은 예시는 다음과 같다.

~~~python
severity = "Medium"
~~~

피해야 할 예시는 다음과 같다.

~~~python
severity = "medium"
severity = "MEDIUM"
severity = "med"
~~~

---

## 13. `confidence` 데이터 정의

`confidence`는 탐지 결과의 신뢰도를 의미한다.

### 13.1 타입

~~~python
confidence: str
~~~

### 13.2 허용 값

~~~text
High
Medium
Low
Unknown
~~~

### 13.3 설명

| 등급 | 설명 |
|---|---|
| `High` | 탐지 결과의 신뢰도가 높음 |
| `Medium` | 추가 확인이 필요함 |
| `Low` | 오탐 가능성이 있음 |
| `Unknown` | 신뢰도를 판단할 수 없음 |

---

## 14. `evaluated_finding` 데이터 정의

`evaluated_finding`은 위험도 평가가 적용된 취약점 결과를 의미한다.

초기 버전에서는 기존 `finding`에 평가 정보를 추가하는 방식으로 사용한다.

### 14.1 타입

~~~python
evaluated_finding: dict
~~~

### 14.2 구조

~~~python
evaluated_finding = {
    "id": "ZAP-001",
    "source": "zap",
    "name": "Missing Anti-clickjacking Header",
    "severity": "Medium",
    "confidence": "Medium",
    "description": "The response does not include X-Frame-Options header.",
    "url": "http://example.com",
    "evidence": "",
    "solution": "Include the X-Frame-Options header.",
    "reference": "https://developer.mozilla.org/",
    "cvss_score": None,
    "risk_score": 5,
    "is_critical": False
}
~~~

### 14.3 추가 필드 설명

| 필드명 | 타입 | 설명 |
|---|---:|---|
| `cvss_score` | `float` 또는 `None` | CVSS 점수 |
| `risk_score` | `int` | 프로젝트 내부 위험도 점수 |
| `is_critical` | `bool` | Critical 등급 여부 |

---

## 15. `evaluated_findings` 데이터 정의

`evaluated_findings`는 위험도 평가가 적용된 취약점 결과 목록이다.

### 15.1 타입

~~~python
evaluated_findings: list[dict]
~~~

### 15.2 사용 위치

~~~text
생성 위치:
- sls_scanner/evaluators/risk_evaluator.py

사용 위치:
- sls_scanner/reports/html_report.py
- sls_scanner/reports/csv_report.py
~~~

### 15.3 주의 사항

리포트 생성 단계에서는 가능하면 `findings`보다 `evaluated_findings`를 사용하는 것을 기준으로 한다.

단, 초기 개발 단계에서는 `findings`를 그대로 리포트에 전달할 수 있다.

---

## 16. `report_path` 데이터 정의

`report_path`는 생성된 리포트 파일 경로를 의미한다.

### 16.1 타입

~~~python
report_path: str
~~~

### 16.2 예시

~~~python
html_report_path = "results/reports/report.html"
csv_report_path = "results/reports/findings.csv"
~~~

### 16.3 사용 위치

~~~text
생성 위치:
- sls_scanner/reports/html_report.py
- sls_scanner/reports/csv_report.py

사용 위치:
- sls_scanner/core/pipeline.py
- sls_scanner/cli/runner.py
~~~

---

## 17. `report_result` 데이터 정의

`report_result`는 생성된 리포트 결과 정보를 묶어서 표현하는 데이터이다.

초기 버전에서는 반드시 구현하지 않아도 되지만, 이후 확장을 고려해 기준을 정의한다.

### 17.1 타입

~~~python
report_result: dict
~~~

### 17.2 구조

~~~python
report_result = {
    "html_report_path": "results/reports/report.html",
    "csv_report_path": "results/reports/findings.csv",
    "generated": True
}
~~~

### 17.3 필드 설명

| 필드명 | 타입 | 설명 |
|---|---:|---|
| `html_report_path` | `str` | HTML 리포트 파일 경로 |
| `csv_report_path` | `str` | CSV 리포트 파일 경로 |
| `generated` | `bool` | 리포트 생성 성공 여부 |

---

## 18. `pipeline_result` 데이터 정의

`pipeline_result`는 전체 파이프라인 실행 결과를 하나로 묶은 데이터이다.

초기 버전에서는 `run_pipeline()` 함수가 `None`을 반환해도 되지만, 이후 결과 확인과 API 연동을 고려하면 `dict` 반환 구조로 확장할 수 있다.

### 18.1 타입

~~~python
pipeline_result: dict
~~~

### 18.2 구조

~~~python
pipeline_result = {
    "target": "http://example.com",
    "port_results": [
        {
            "host": "192.168.0.10",
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "state": "open",
            "product": "nginx",
            "version": ""
        }
    ],
    "findings": [
        {
            "id": "ZAP-001",
            "source": "zap",
            "name": "Missing Anti-clickjacking Header",
            "severity": "Medium",
            "confidence": "Medium",
            "description": "The response does not include X-Frame-Options header.",
            "url": "http://example.com",
            "evidence": "",
            "solution": "Include the X-Frame-Options header.",
            "reference": ""
        }
    ],
    "report_result": {
        "html_report_path": "results/reports/report.html",
        "csv_report_path": "results/reports/findings.csv",
        "generated": True
    }
}
~~~

### 18.3 사용 위치

~~~text
생성 위치:
- sls_scanner/core/pipeline.py

사용 위치:
- sls_scanner/cli/runner.py
- 이후 추가될 FastAPI API 응답
~~~

---

## 19. 함수별 입력값과 반환값 기준

주요 함수의 입력값과 반환값 기준은 다음과 같다.

| 파일 | 함수 | 입력값 | 반환값 |
|---|---|---|---|
| `core/target.py` | `validate_target()` | `target: str` | `bool` |
| `scanners/nmap_scanner.py` | `run_nmap_scan()` | `target: str` | `dict` |
| `scanners/zap_scanner.py` | `run_zap_scan()` | `target: str` | `dict` |
| `normalizers/nmap_normalizer.py` | `normalize_nmap_result()` | `raw_result: dict` | `list[dict]` |
| `normalizers/zap_normalizer.py` | `normalize_zap_result()` | `raw_result: dict` | `list[dict]` |
| `evaluators/risk_evaluator.py` | `evaluate_risk()` | `findings: list[dict]` | `list[dict]` |
| `reports/html_report.py` | `generate_html_report()` | `target: str`, `port_results: list[dict]`, `findings: list[dict]` | `str` |
| `reports/csv_report.py` | `generate_csv_report()` | `findings: list[dict]` | `str` |
| `core/pipeline.py` | `run_pipeline()` | `target: str` | `None` 또는 `dict` |

---

## 20. 파일 저장 경로 기준

결과 파일 저장 경로는 다음 기준을 따른다.

~~~text
results/raw/
→ 외부 스캐너 원시 결과 저장

results/normalized/
→ 정규화된 결과 저장

results/reports/
→ 최종 리포트 저장
~~~

예시는 다음과 같다.

~~~text
results/raw/nmap_raw.json
results/raw/zap_raw.json
results/normalized/ports.json
results/normalized/findings.json
results/reports/report.html
results/reports/findings.csv
~~~

---

## 21. JSON 저장 기준

JSON 파일로 저장할 때는 다음 기준을 따른다.

~~~python
import json

with open("results/normalized/findings.json", "w", encoding="utf-8") as file:
    json.dump(findings, file, ensure_ascii=False, indent=2)
~~~

기준은 다음과 같다.

~~~text
- encoding="utf-8" 사용
- ensure_ascii=False 사용
- indent=2 사용
~~~

---

## 22. CSV 저장 기준

CSV 파일로 저장할 때는 취약점 결과의 주요 필드를 컬럼으로 사용한다.

기본 컬럼 예시는 다음과 같다.

~~~text
id,source,name,severity,confidence,url,description,solution,reference
~~~

CSV 한 행은 하나의 `finding`을 의미한다.

---

## 23. HTML 리포트 데이터 기준

HTML 리포트에는 최소한 다음 데이터가 포함되어야 한다.

~~~text
- 점검 대상 target
- 열린 포트 목록 port_results
- 취약점 목록 findings 또는 evaluated_findings
- 위험도 요약
- 리포트 생성 시간
~~~

초기 버전에서는 간단한 HTML 구조로 시작하고, 이후 디자인과 시각화 요소를 추가한다.

---

## 24. 필수 필드 누락 처리 기준

정규화 과정에서 필수 필드가 누락된 경우 기본값을 사용한다.

기본값 기준은 다음과 같다.

~~~python
default_finding = {
    "id": "",
    "source": "unknown",
    "name": "Unknown Finding",
    "severity": "Unknown",
    "confidence": "Unknown",
    "description": "",
    "url": "",
    "evidence": "",
    "solution": "",
    "reference": ""
}
~~~

포트 결과 기본값은 다음과 같다.

~~~python
default_port_result = {
    "host": "",
    "port": 0,
    "protocol": "tcp",
    "service": "unknown",
    "state": "unknown",
    "product": "",
    "version": ""
}
~~~

---

## 25. 데이터 타입 사용 시 주의 사항

데이터 타입을 사용할 때는 다음 사항을 지킨다.

~~~text
- 같은 의미의 필드는 같은 이름을 사용한다.
- severity 값은 정해진 허용 값만 사용한다.
- 포트 번호는 문자열이 아니라 int로 저장한다.
- URL은 str로 저장한다.
- 여러 결과는 list[dict] 형식으로 저장한다.
- 원시 결과와 정규화 결과를 구분한다.
- 리포트 생성 단계에서는 원시 결과를 직접 사용하지 않는다.
~~~

---



