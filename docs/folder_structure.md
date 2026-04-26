# 프로젝트 폴더 구조 문서

## 개발 시 기본 작업 흐름

개발 시 참고 흐름

이 프로젝트의 실제 개발 절차와 브랜치 사용 규칙은 `docs/team_development_guide.md` 문서를 기준으로 따른다.

`folder_structure.md`에서는 폴더와 파일의 위치 및 역할을 확인하고, 실제 작업 순서와 협업 규칙은 팀 개발 가이드 문서에서 확인한다.

기본적인 작업 흐름은 다음과 같다.

~~~text
1. 폴더 구조 문서를 확인하여 작업할 파일 위치를 파악한다.
2. 팀 개발 가이드 문서를 확인하여 브랜치와 커밋 규칙을 확인한다.
3. 작업 브랜치에서 기능 또는 문서를 수정한다.
4. 테스트 또는 기본 확인을 수행한다.
5. Pull Request를 생성하여 dev 브랜치에 병합한다.
~~~

---

## 1. 문서 목적

이 문서는 `Shift-Left-Sync` 프로젝트의 기본 폴더 구조와 각 파일의 역할을 정리하기 위한 문서이다.

프로젝트를 개발할 때 팀원들이 어느 위치에 어떤 코드를 작성해야 하는지 쉽게 파악할 수 있도록 하고, 기능별 역할 분담과 유지보수를 수월하게 만드는 것을 목적으로 한다.

---

## 2. 전체 폴더 구조

~~~text
Shift-Left-Sync/
│
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── README.md
│
├── docs/
│   ├── folder_structure.md
│   ├── team_development_guide.md
│   ├── data_type_definition.md
│   └── development_rules.md
│
├── sls_scanner/
│   ├── __init__.py
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   └── runner.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── target.py
│   │   └── exceptions.py
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── nmap_scanner.py
│   │   └── zap_scanner.py
│   │
│   ├── normalizers/
│   │   ├── __init__.py
│   │   ├── nmap_normalizer.py
│   │   └── zap_normalizer.py
│   │
│   ├── evaluators/
│   │   ├── __init__.py
│   │   └── risk_evaluator.py
│   │
│   └── reports/
│       ├── __init__.py
│       ├── html_report.py
│       └── csv_report.py
│
├── results/
│   ├── raw/
│   ├── normalized/
│   └── reports/
│
└── tests/
    ├── __init__.py
    ├── test_target.py
    ├── test_pipeline.py
    └── test_normalizer.py
~~~

---

## 3. 최상위 파일 설명

## 3.1 `main.py`

`main.py`는 프로젝트 실행 진입점 파일이다.

사용자가 터미널에서 명령어를 실행하면 가장 먼저 실행되는 파일이며, 내부적으로 CLI 명령어 처리 로직을 호출한다.

예시 실행 명령어는 다음과 같다.

~~~bash
python main.py scan --target http://example.com
~~~

위 명령어를 실행하면 `main.py`가 CLI 실행 파일인 `sls_scanner/cli/runner.py`를 호출하고, 이후 전체 스캔 파이프라인으로 작업이 넘어간다.

---

## 3.2 `requirements.txt`

`requirements.txt`는 프로젝트 실행에 필요한 기본 라이브러리 목록을 관리하는 파일이다.

프로젝트를 실행하는 데 반드시 필요한 외부 라이브러리를 작성한다.

예시로 들어갈 수 있는 항목은 다음과 같다.

~~~text
requests
python-nmap
zaproxy
~~~

팀원이 새 환경에서 프로젝트를 실행할 때는 다음 명령어로 필요한 라이브러리를 설치할 수 있다.

~~~bash
pip install -r requirements.txt
~~~

---

## 3.3 `requirements-dev.txt`

`requirements-dev.txt`는 개발 과정에서 필요한 라이브러리 목록을 관리하는 파일이다.

프로그램 실행에는 필수는 아니지만, 테스트나 코드 품질 관리를 위해 필요한 도구들이 들어간다.

예시로 들어갈 수 있는 항목은 다음과 같다.

~~~text
pytest
black
flake8
~~~

개발용 라이브러리는 다음 명령어로 설치할 수 있다.

~~~bash
pip install -r requirements-dev.txt
~~~

---

## 3.4 `README.md`

`README.md`는 프로젝트 소개 문서이다.

프로젝트의 목적, 설치 방법, 실행 방법, 주요 기능, 사용 예시 등을 정리한다.

팀원이나 외부 사용자가 프로젝트를 처음 확인할 때 가장 먼저 읽는 문서이다.

---

## 4. `docs/` 폴더 설명

`docs/` 폴더는 프로젝트 문서를 관리하는 공간이다.

개발 규칙, 폴더 구조, 데이터 타입 정의, 팀 작업 방식 등을 문서화한다.

코드를 작성하기 전에 팀원들이 공통 기준을 확인할 수 있도록 하는 역할을 한다.

---

## 4.1 `docs/folder_structure.md`

프로젝트 폴더 구조를 설명하는 문서이다.

각 폴더와 파일이 어떤 역할을 하는지 정리한다.

현재 이 문서가 바로 `folder_structure.md`에 해당한다.

---

## 4.2 `docs/team_development_guide.md`

팀원들이 개발할 때 따라야 할 작업 방식을 정리하는 문서이다.

포함될 수 있는 내용은 다음과 같다.

~~~text
- 브랜치 사용 규칙
- 커밋 메시지 규칙
- Pull Request 작성 규칙
- 코드 리뷰 방식
- 작업 순서
- 기능별 역할 분담 기준
~~~

---

## 4.3 `docs/data_type_definition.md`

프로젝트에서 사용하는 데이터 타입을 정의하는 문서이다.

스캔 결과, 정규화 결과, 취약점 결과, 리포트 데이터 구조 등을 정리한다.

예시 항목은 다음과 같다.

~~~text
- target: 점검 대상 URL 또는 IP
- port_results: 포트 스캔 결과 목록
- findings: 취약점 탐지 결과 목록
- severity: 위험도 등급
- report_path: 생성된 리포트 파일 경로
~~~

이 문서를 미리 작성해두면 팀원들이 서로 다른 형식의 데이터를 만들지 않고, 공통된 데이터 구조를 기준으로 개발할 수 있다.

---

## 4.4 `docs/development_rules.md`

개발 규칙을 정리하는 문서이다.

포함될 수 있는 내용은 다음과 같다.

~~~text
- 파일 이름 규칙
- 함수 이름 규칙
- 주석 작성 규칙
- 예외 처리 규칙
- 테스트 작성 규칙
- 코드 작성 스타일
~~~

이 문서는 코드 품질을 일정하게 유지하고, 팀원 간 코드 스타일 차이를 줄이기 위해 사용한다.

---

## 5. `sls_scanner/` 폴더 설명

`sls_scanner/` 폴더는 실제 프로젝트의 핵심 소스코드를 관리하는 폴더이다.

`SLS`는 `Shift-Left-Sync`의 약자로 사용한다.

이 폴더 안에는 CLI 처리, 스캔 실행, 결과 정규화, 위험도 평가, 리포트 생성 코드가 기능별로 나누어져 있다.

---

## 6. `sls_scanner/cli/` 폴더 설명

`cli/` 폴더는 CLI 명령어 처리를 담당하는 폴더이다.

CLI는 Command Line Interface의 약자로, 터미널에서 명령어를 입력해 프로그램을 실행하는 방식을 의미한다.

예시 명령어는 다음과 같다.

~~~bash
python main.py scan --target http://example.com
python main.py report --file result.json
python main.py version
~~~

---

## 6.1 `sls_scanner/cli/runner.py`

`runner.py`는 사용자가 입력한 명령어를 해석하는 파일이다.

주요 역할은 다음과 같다.

~~~text
- scan 명령어 처리
- report 명령어 처리
- version 명령어 처리
- 사용자가 입력한 옵션 확인
- core 파이프라인 호출
~~~

예를 들어 사용자가 다음 명령어를 입력한다고 가정한다.

~~~bash
python main.py scan --target http://example.com
~~~

이 경우 `runner.py`는 `scan` 명령어와 `--target` 옵션을 해석한 뒤, 실제 스캔 실행을 담당하는 `core/pipeline.py`로 작업을 넘긴다.

---

## 7. `sls_scanner/core/` 폴더 설명

`core/` 폴더는 프로젝트의 핵심 실행 흐름을 담당하는 폴더이다.

사용자 입력 검증, 전체 파이프라인 실행, 공통 예외 처리 등이 이 폴더에 들어간다.

---

## 7.1 `sls_scanner/core/pipeline.py`

`pipeline.py`는 전체 스캔 흐름을 관리하는 파일이다.

주요 실행 흐름은 다음과 같다.

~~~text
1. 대상 URL 또는 IP 입력값 검증
2. Nmap 포트 스캔 실행
3. OWASP ZAP 취약점 스캔 실행
4. 스캔 결과 정규화
5. 위험도 평가
6. HTML / CSV 리포트 생성
~~~

이 파일은 각 기능을 직접 모두 구현하는 파일이 아니라, 여러 모듈을 순서대로 연결하는 역할을 한다.

즉, 프로젝트의 전체 흐름을 조립하는 중심 파일이다.

---

## 7.2 `sls_scanner/core/target.py`

`target.py`는 사용자가 입력한 대상 URL 또는 IP가 올바른 형식인지 검증하는 파일이다.

올바른 입력 예시는 다음과 같다.

~~~text
http://example.com
https://example.com
192.168.0.1
~~~

올바르지 않은 입력 예시는 다음과 같다.

~~~text
example
abc
빈 문자열
~~~

이 파일을 통해 잘못된 대상이 스캐너로 전달되는 것을 막을 수 있다.

---

## 7.3 `sls_scanner/core/exceptions.py`

`exceptions.py`는 프로젝트에서 사용할 사용자 정의 예외를 모아두는 파일이다.

예시 예외는 다음과 같다.

~~~text
InvalidTargetError
ScannerExecutionError
ReportGenerationError
~~~

이 파일을 사용하면 오류 상황을 더 명확하게 구분할 수 있다.

예를 들어 대상 URL이 잘못된 경우에는 `InvalidTargetError`를 사용하고, 스캐너 실행 중 문제가 발생한 경우에는 `ScannerExecutionError`를 사용할 수 있다.

---

## 8. `sls_scanner/scanners/` 폴더 설명

`scanners/` 폴더는 외부 스캐너 실행 코드를 관리하는 폴더이다.

현재 구조에서는 Nmap과 OWASP ZAP 스캐너를 분리해서 관리한다.

스캐너별 실행 방식과 결과 형식이 다르기 때문에 파일을 나누어 관리한다.

---

## 8.1 `sls_scanner/scanners/nmap_scanner.py`

`nmap_scanner.py`는 Nmap을 이용한 포트 스캔 기능을 담당하는 파일이다.

주요 역할은 다음과 같다.

~~~text
- 대상 IP 또는 URL을 기준으로 포트 스캔 실행
- 열린 포트 정보 수집
- 서비스 정보 수집
- Nmap 원시 스캔 결과 반환
~~~

이 파일은 포트 스캔 단계만 담당한다.

결과를 프로젝트 내부 표준 형식으로 바꾸는 작업은 `normalizers/nmap_normalizer.py`에서 처리한다.

---

## 8.2 `sls_scanner/scanners/zap_scanner.py`

`zap_scanner.py`는 OWASP ZAP을 이용한 웹 취약점 스캔 기능을 담당하는 파일이다.

주요 역할은 다음과 같다.

~~~text
- OWASP ZAP API 연결
- 대상 URL 스캔 실행
- 탐지된 취약점 후보 수집
- ZAP 원시 스캔 결과 반환
~~~

이 파일은 ZAP을 실행하고 결과를 받아오는 역할만 담당한다.

결과를 프로젝트 내부 표준 형식으로 바꾸는 작업은 `normalizers/zap_normalizer.py`에서 처리한다.

---

## 9. `sls_scanner/normalizers/` 폴더 설명

`normalizers/` 폴더는 스캐너별로 다른 결과 형식을 프로젝트 내부 표준 형식으로 변환하는 폴더이다.

Nmap 결과와 ZAP 결과는 출력 구조가 다르기 때문에, 이를 그대로 사용하면 리포트 생성이나 위험도 평가가 어려워진다.

따라서 정규화 과정을 통해 일정한 형식으로 변환한다.

---

## 9.1 `sls_scanner/normalizers/nmap_normalizer.py`

`nmap_normalizer.py`는 Nmap 원시 결과를 프로젝트 표준 포트 결과 형식으로 변환하는 파일이다.

예시 변환 결과는 다음과 같다.

~~~json
[
  {
    "host": "192.168.0.10",
    "port": 80,
    "protocol": "tcp",
    "service": "http",
    "state": "open"
  }
]
~~~

이렇게 변환하면 이후 단계에서 Nmap 결과를 일정한 형식으로 사용할 수 있다.

---

## 9.2 `sls_scanner/normalizers/zap_normalizer.py`

`zap_normalizer.py`는 OWASP ZAP 원시 결과를 프로젝트 표준 취약점 결과 형식으로 변환하는 파일이다.

예시 변환 결과는 다음과 같다.

~~~json
[
  {
    "name": "Missing Security Header",
    "severity": "Medium",
    "description": "X-Frame-Options header is missing",
    "url": "http://example.com"
  }
]
~~~

이렇게 변환하면 이후 위험도 평가와 리포트 생성 단계에서 같은 형식으로 취약점 정보를 처리할 수 있다.

---

## 10. `sls_scanner/evaluators/` 폴더 설명

`evaluators/` 폴더는 정규화된 결과를 기준으로 위험도를 평가하는 폴더이다.

스캐너가 탐지한 결과를 그대로 보여주는 것이 아니라, 프로젝트 기준에 맞게 위험도를 분류하는 역할을 한다.

---

## 10.1 `sls_scanner/evaluators/risk_evaluator.py`

`risk_evaluator.py`는 취약점 결과를 기준으로 위험도 등급을 평가하는 파일이다.

예시 위험도 등급은 다음과 같다.

~~~text
Critical
High
Medium
Low
Info
~~~

주요 역할은 다음과 같다.

~~~text
- 취약점별 위험도 분류
- CVSS 기준 적용 가능성 검토
- Critical 또는 High 등급 탐지 여부 확인
- 리포트에 표시할 위험도 데이터 생성
~~~

이 파일은 나중에 CVSS 점수 계산이나 팀 내부 위험도 기준을 추가할 때 확장할 수 있다.

---

## 11. `sls_scanner/reports/` 폴더 설명

`reports/` 폴더는 스캔 결과를 사용자가 확인할 수 있는 리포트 형태로 변환하는 폴더이다.

HTML 리포트와 CSV 리포트를 각각 분리해서 관리한다.

---

## 11.1 `sls_scanner/reports/html_report.py`

`html_report.py`는 HTML 리포트를 생성하는 파일이다.

주요 역할은 다음과 같다.

~~~text
- 대상 정보 출력
- 포트 스캔 결과 출력
- 취약점 결과 출력
- 위험도 요약 출력
- HTML 파일 경로 반환
~~~

HTML 리포트는 사람이 보기 좋은 형태의 결과물을 만드는 데 사용한다.

---

## 11.2 `sls_scanner/reports/csv_report.py`

`csv_report.py`는 CSV 리포트를 생성하는 파일이다.

주요 역할은 다음과 같다.

~~~text
- 취약점 결과를 표 형식으로 변환
- CSV 파일 생성
- CSV 파일 경로 반환
~~~

CSV 리포트는 표 기반 분석, 엑셀 정리, 다른 시스템 연동 등에 사용할 수 있다.

---

## 12. `results/` 폴더 설명

`results/` 폴더는 스캔 실행 결과와 리포트 결과물을 저장하는 폴더이다.

스캐너 원본 결과, 정규화된 결과, 최종 리포트를 단계별로 나누어 저장한다.

---

## 12.1 `results/raw/`

`raw/` 폴더는 스캐너에서 수집한 원시 결과를 저장하는 폴더이다.

예시는 다음과 같다.

~~~text
- Nmap 원본 결과
- OWASP ZAP 원본 결과
~~~

원시 결과를 따로 저장하면 나중에 정규화 과정에서 문제가 생겼을 때 원본 데이터를 다시 확인할 수 있다.

---

## 12.2 `results/normalized/`

`normalized/` 폴더는 정규화된 결과를 저장하는 폴더이다.

예시는 다음과 같다.

~~~text
- 표준화된 포트 스캔 결과
- 표준화된 취약점 결과
~~~

이 폴더의 데이터는 위험도 평가와 리포트 생성 단계에서 사용된다.

---

## 12.3 `results/reports/`

`reports/` 폴더는 최종 리포트 파일을 저장하는 폴더이다.

예시는 다음과 같다.

~~~text
- report.html
- findings.csv
~~~

사용자가 최종적으로 확인하는 결과물이 이 폴더에 저장된다.

---

## 13. `tests/` 폴더 설명

`tests/` 폴더는 테스트 코드를 관리하는 폴더이다.

각 기능이 정상적으로 동작하는지 확인하기 위한 테스트 파일을 작성한다.

테스트 코드는 기능 수정 후 문제가 생겼는지 빠르게 확인하는 데 사용한다.

---

## 13.1 `tests/test_target.py`

`test_target.py`는 대상 URL 또는 IP 검증 기능을 테스트하는 파일이다.

테스트 예시는 다음과 같다.

~~~text
- http://example.com 입력 시 True 반환
- https://example.com 입력 시 True 반환
- 192.168.0.1 입력 시 True 반환
- 잘못된 문자열 입력 시 False 반환
~~~

---

## 13.2 `tests/test_pipeline.py`

`test_pipeline.py`는 전체 파이프라인 실행 흐름을 테스트하는 파일이다.

테스트 예시는 다음과 같다.

~~~text
- 올바른 대상 입력 시 파이프라인이 실행되는지 확인
- 잘못된 대상 입력 시 예외가 발생하는지 확인
- 스캐너 결과가 다음 단계로 전달되는지 확인
~~~

---

## 13.3 `tests/test_normalizer.py`

`test_normalizer.py`는 스캐너 결과 정규화 기능을 테스트하는 파일이다.

테스트 예시는 다음과 같다.

~~~text
- Nmap 결과가 표준 포트 결과 형식으로 변환되는지 확인
- ZAP 결과가 표준 취약점 결과 형식으로 변환되는지 확인
~~~

---

## 14. `__init__.py` 파일 설명

`__init__.py` 파일은 해당 폴더를 Python 패키지로 인식하게 만드는 파일이다.

예를 들어 다음과 같은 import 구문을 사용하려면 각 폴더에 `__init__.py` 파일이 필요하다.

~~~python
from sls_scanner.core.pipeline import run_pipeline
~~~

현재 프로젝트에서는 다음 폴더에 `__init__.py` 파일을 둔다.

~~~text
sls_scanner/
sls_scanner/cli/
sls_scanner/core/
sls_scanner/scanners/
sls_scanner/normalizers/
sls_scanner/evaluators/
sls_scanner/reports/
tests/
~~~

---



## 15. 현재 구조의 핵심 기준

현재 폴더 구조는 다음 기준으로 나누었다.

~~~text
cli         → 사용자가 입력한 명령어 처리
core        → 전체 실행 흐름과 공통 로직 관리
scanners    → 외부 스캐너 실행
normalizers → 스캐너 결과 표준화
evaluators  → 위험도 평가
reports     → 리포트 생성
docs        → 프로젝트 문서 관리
results     → 실행 결과 저장
tests       → 테스트 코드 관리
~~~

각 폴더는 하나의 역할에 집중하도록 분리되어 있다.

이렇게 나누면 기능을 수정하거나 추가할 때 관련 파일을 쉽게 찾을 수 있다.

---

