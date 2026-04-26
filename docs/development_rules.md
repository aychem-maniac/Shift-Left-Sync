# 개발 규칙 문서

## GPT 사용 시 공통 규칙

팀원이 GPT를 사용할 때는 프로젝트 구조와 개발 규칙을 함께 알려주어야 한다.

GPT에게 단순히 “코드 만들어줘”라고 요청하면 프로젝트 구조와 맞지 않는 코드가 나올 수 있다.

따라서 GPT에게 요청할 때는 다음 내용을 포함한다.

~~~text
- 현재 작업 중인 파일 경로
- 해당 파일의 역할
- 입력값과 출력값
- 사용해야 하는 함수 이름
- 프로젝트 폴더 구조
- 예외 처리 기준
- 반환값 형식
- 주석 작성 방식
- 테스트 필요 여부
~~~

---

## GPT 공통 프롬프트 템플릿

팀원들은 GPT에게 코드 작성이나 수정 요청을 할 때 아래 프롬프트 형식을 사용한다.

~~~text
나는 Shift-Left-Sync 프로젝트를 개발하고 있다.

이 프로젝트는 웹 취약점 점검 및 결과 리포트 시스템이다.

현재 프로젝트 구조는 다음 기준을 따른다.

- cli 폴더: 사용자가 입력한 CLI 명령어 처리
- core 폴더: 전체 실행 흐름, 대상 검증, 공통 예외 처리
- scanners 폴더: Nmap, OWASP ZAP 등 외부 스캐너 실행
- normalizers 폴더: 스캐너 원시 결과를 프로젝트 표준 형식으로 변환
- evaluators 폴더: 정규화된 결과를 기준으로 위험도 평가
- reports 폴더: HTML, CSV 리포트 생성
- tests 폴더: 테스트 코드 작성

현재 작업 파일:
[여기에 파일 경로 작성]

이 파일의 역할:
[여기에 파일 역할 작성]

구현하려는 기능:
[여기에 구현할 기능 작성]

입력값:
[여기에 입력값 작성]

출력값:
[여기에 출력값 작성]

작성해야 할 함수 이름:
[여기에 함수 이름 작성]

코드 작성 규칙:
- 함수 이름은 소문자와 언더스코어를 사용한다.
- 타입 힌트를 작성한다.
- 주요 코드에는 한국어 주석을 작성한다.
- 예외 상황은 명확하게 처리한다.
- 반환값 형식은 다음 단계에서 사용할 수 있도록 명확하게 유지한다.
- 외부 도구 실행, 정규화, 리포트 생성 코드는 서로 섞지 않는다.

요청 사항:
위 조건에 맞게 코드를 작성해줘.
그리고 코드 아래에 각 줄 또는 주요 블록별 설명도 함께 작성해줘.
~~~

---

## GPT 코드 수정 요청 프롬프트 템플릿

기존 코드를 수정할 때는 아래 형식을 사용한다.

~~~text
나는 Shift-Left-Sync 프로젝트를 개발하고 있다.

현재 수정하려는 파일은 다음과 같다.

파일 경로:
[여기에 파일 경로 작성]

현재 코드:
[여기에 현재 코드 붙여넣기]

문제 상황:
[여기에 오류 메시지 또는 수정하려는 이유 작성]

원하는 수정 방향:
[여기에 원하는 결과 작성]

프로젝트 규칙:
- 함수 이름은 소문자와 언더스코어를 사용한다.
- 타입 힌트를 유지한다.
- 주요 코드에는 한국어 주석을 작성한다.
- 예외 상황은 무시하지 않는다.
- 기존 프로젝트 폴더 구조에 맞게 import 경로를 작성한다.
- 불필요하게 다른 파일의 구조를 바꾸지 않는다.

요청 사항:
위 코드를 프로젝트 규칙에 맞게 수정해줘.
수정한 전체 코드를 보여주고, 변경된 부분을 설명해줘.
~~~

---

## GPT 오류 해결 요청 프롬프트 템플릿

실행 중 오류가 발생했을 때는 아래 형식을 사용한다.

~~~text
나는 Shift-Left-Sync 프로젝트를 개발하고 있다.

실행한 명령어:
[여기에 실행한 명령어 작성]

발생한 오류 메시지:
[여기에 오류 메시지 전체 붙여넣기]

관련 파일 경로:
[여기에 관련 파일 경로 작성]

관련 코드:
[여기에 관련 코드 붙여넣기]

현재 브랜치:
[여기에 현재 브랜치 이름 작성]

프로젝트 규칙:
- import 경로는 현재 폴더 구조를 기준으로 확인한다.
- 함수 이름과 실제 정의된 이름이 일치해야 한다.
- 파일을 수정할 때는 원인을 먼저 설명한 뒤 수정 방향을 제시한다.
- 수정 명령어가 필요한 경우 각 명령어에 주석을 붙인다.

요청 사항:
오류 원인을 분석해주고, 어떤 파일의 어느 부분을 수정해야 하는지 단계별로 설명해줘.
필요한 명령어가 있으면 PowerShell 기준으로 주석과 함께 작성해줘.
~~~

---

## GPT 문서 작성 요청 프롬프트 템플릿

문서 작업을 할 때는 아래 형식을 사용한다.

~~~text
나는 Shift-Left-Sync 프로젝트 문서를 작성하고 있다.

작성할 문서 파일:
[여기에 문서 파일 경로 작성]

문서 목적:
[여기에 문서 목적 작성]

문서에 포함할 내용:
[여기에 포함할 항목 작성]

작성 스타일:
- 보고서형 문체로 작성한다.
- 팀원이 복사해서 붙여넣기 좋게 Markdown 형식으로 작성한다.
- 항목별 제목을 명확하게 작성한다.
- 예시 코드나 명령어가 필요한 경우 코드블록으로 작성한다.
- 문장 끝은 가능한 한 “~한다” 형태로 통일한다.

요청 사항:
위 조건에 맞게 문서 내용을 작성해줘.
Markdown 파일에 바로 붙여넣을 수 있는 형태로 만들어줘.
~~~

---

## GPT 테스트 코드 작성 요청 프롬프트 템플릿

테스트 코드를 작성할 때는 아래 형식을 사용한다.

~~~text
나는 Shift-Left-Sync 프로젝트를 개발하고 있다.

테스트할 기능:
[여기에 테스트할 기능 작성]

대상 파일:
[여기에 테스트 대상 파일 경로 작성]

테스트 파일:
[여기에 테스트 파일 경로 작성]

현재 함수 코드:
[여기에 함수 코드 붙여넣기]

테스트해야 할 조건:
[여기에 테스트 조건 작성]

프로젝트 테스트 규칙:
- 테스트 파일은 tests/ 폴더에 작성한다.
- 테스트 파일 이름은 test_기능명.py 형식으로 작성한다.
- 테스트 함수 이름은 test_로 시작한다.
- 정상 입력과 비정상 입력을 모두 테스트한다.
- pytest 기준으로 작성한다.

요청 사항:
위 조건에 맞게 pytest 테스트 코드를 작성해줘.
그리고 각 테스트가 무엇을 확인하는지 설명해줘.
~~~

---

## GPT 사용 시 피해야 할 요청 방식

다음과 같은 요청은 피한다.

~~~text
코드 만들어줘.
이거 고쳐줘.
스캐너 만들어줘.
오류 해결해줘.
문서 만들어줘.
~~~

이런 요청은 정보가 부족해서 프로젝트 구조와 맞지 않는 답변이 나올 가능성이 높다.

대신 다음처럼 요청한다.

~~~text
sls_scanner/core/target.py 파일에서 validate_target(target: str) -> bool 함수를 작성하려고 한다.
입력값은 URL 또는 IP 문자열이고, 반환값은 올바른 형식이면 True, 아니면 False이다.
프로젝트 규칙에 맞게 타입 힌트와 한국어 주석을 포함해서 작성해줘.
~~~

---

## 코드 작성 완료 후 확인 사항

코드 작성이 끝나면 다음 항목을 확인한다.

~~~text
- 파일 위치가 프로젝트 구조에 맞는가
- 함수 이름이 역할을 명확히 나타내는가
- 타입 힌트가 작성되어 있는가
- 주요 코드에 필요한 주석이 있는가
- 반환값 형식이 다음 단계와 맞는가
- 예외 상황을 무시하지 않았는가
- import 경로가 올바른가
- 테스트 또는 기본 실행 확인을 했는가
~~~

---






## 1. 문서 목적

이 문서는 `Shift-Left-Sync` 프로젝트의 코드 작성 규칙을 정리하기 위한 문서이다.

팀원들이 각자 다른 방식으로 코드를 작성하면 파일 구조, 함수 이름, 반환값, 예외 처리 방식이 달라져서 이후 통합 과정에서 문제가 발생할 수 있다.

따라서 본 문서는 프로젝트의 코드 작성 기준을 통일하고, 팀원이 GPT를 사용할 때도 같은 기준으로 답변을 받을 수 있도록 하는 것을 목적으로 한다.

---

## 2. 기본 개발 원칙

프로젝트 코드는 다음 원칙을 기준으로 작성한다.

~~~text
1. 하나의 파일은 하나의 주요 역할을 담당한다.
2. 하나의 함수는 하나의 기능만 담당한다.
3. 입력값과 반환값은 가능한 한 명확하게 작성한다.
4. 외부 도구 실행 코드와 결과 정리 코드는 분리한다.
5. 예외 상황은 무시하지 않고 명확하게 처리한다.
6. 스캐너별 결과 형식은 normalizers 단계에서 표준 형식으로 변환한다.
7. 리포트 생성 코드는 스캔 실행 코드와 분리한다.
8. 공통으로 사용할 데이터 구조는 docs/data_type_definition.md 기준을 따른다.
9. 코드 수정 후에는 최소 실행 테스트를 수행한다.
~~~

---

## 3. 파일 이름 규칙

파일 이름은 소문자와 언더스코어를 사용한다.

좋은 예시는 다음과 같다.

~~~text
nmap_scanner.py
zap_scanner.py
risk_evaluator.py
html_report.py
csv_report.py
target.py
pipeline.py
~~~

피해야 할 예시는 다음과 같다.

~~~text
NmapScanner.py
zapScanner.py
risk-evaluator.py
HTMLReport.py
test file.py
~~~

파일 이름은 파일의 역할이 드러나도록 작성한다.

---

## 4. 폴더별 코드 작성 기준

프로젝트의 각 폴더는 다음 역할을 기준으로 사용한다.

~~~text
sls_scanner/cli/
→ 사용자가 입력한 CLI 명령어를 처리한다.

sls_scanner/core/
→ 전체 실행 흐름, 대상 검증, 공통 예외 처리를 담당한다.

sls_scanner/scanners/
→ Nmap, OWASP ZAP 등 외부 스캐너 실행 코드를 작성한다.

sls_scanner/normalizers/
→ 스캐너별 원시 결과를 프로젝트 표준 형식으로 변환한다.

sls_scanner/evaluators/
→ 정규화된 결과를 기준으로 위험도를 평가한다.

sls_scanner/reports/
→ HTML, CSV 등 최종 리포트를 생성한다.

tests/
→ 기능별 테스트 코드를 작성한다.

docs/
→ 프로젝트 문서를 관리한다.
~~~

코드를 작성할 때는 자신이 작업하는 기능이 어느 폴더에 들어가야 하는지 먼저 확인한다.

---

## 5. 함수 이름 규칙

함수 이름은 소문자와 언더스코어를 사용한다.

함수 이름만 봐도 어떤 역할을 하는지 알 수 있어야 한다.

좋은 예시는 다음과 같다.

~~~python
validate_target()
run_nmap_scan()
run_zap_scan()
normalize_nmap_result()
normalize_zap_result()
evaluate_risk()
generate_html_report()
generate_csv_report()
~~~

피해야 할 예시는 다음과 같다.

~~~python
check()
scan()
run()
data()
make()
test()
~~~

단, 아주 짧은 보조 함수가 아니라면 지나치게 모호한 이름은 사용하지 않는다.

---

## 6. 변수 이름 규칙

변수 이름도 소문자와 언더스코어를 사용한다.

좋은 예시는 다음과 같다.

~~~python
target_url = "http://example.com"
port_results = []
raw_zap_result = {}
normalized_findings = []
report_path = "results/reports/report.html"
~~~

피해야 할 예시는 다음과 같다.

~~~python
a = "http://example.com"
data = []
result = {}
x = []
tmp = "report.html"
~~~

단, 반복문에서 짧게 사용하는 임시 변수는 예외적으로 사용할 수 있다.

~~~python
for item in findings:
    print(item)
~~~

---

## 7. 타입 힌트 작성 규칙

함수에는 가능한 한 타입 힌트를 작성한다.

좋은 예시는 다음과 같다.

~~~python
def validate_target(target: str) -> bool:
    return True
~~~

~~~python
def generate_csv_report(findings: list[dict]) -> str:
    return "results/reports/findings.csv"
~~~

~~~python
def run_pipeline(target: str) -> None:
    print(target)
~~~

타입 힌트를 작성하면 함수가 어떤 값을 입력받고 어떤 값을 반환하는지 쉽게 알 수 있다.

---

## 8. 주석 작성 규칙

주석은 코드가 “무엇을 하는지”보다 “왜 필요한지”를 설명하는 데 사용한다.

다만 현재 프로젝트 초기 단계에서는 학습과 팀원 이해를 위해 주요 코드에 설명 주석을 작성한다.

좋은 예시는 다음과 같다.

~~~python
# 사용자가 입력한 대상 URL 또는 IP가 올바른 형식인지 확인한다.
if not validate_target(target):
    raise InvalidTargetError("Invalid target")
~~~

~~~python
# 스캐너별 결과 형식이 다르기 때문에 프로젝트 표준 형식으로 변환한다.
normalized_result = normalize_zap_result(raw_result)
~~~

피해야 할 예시는 다음과 같다.

~~~python
# 변수에 넣음
x = 1

# 함수 실행
run()
~~~

주석은 가능하면 한국어로 작성한다.

---

## 9. 예외 처리 규칙

예외 상황은 단순히 무시하지 않는다.

잘못된 입력, 스캐너 실행 실패, 리포트 생성 실패 등은 명확하게 처리한다.

예시 예외 클래스는 다음과 같다.

~~~python
class InvalidTargetError(Exception):
    pass


class ScannerExecutionError(Exception):
    pass


class ReportGenerationError(Exception):
    pass
~~~

예외 처리 예시는 다음과 같다.

~~~python
if not validate_target(target):
    raise InvalidTargetError("대상 URL 또는 IP 형식이 올바르지 않습니다.")
~~~

피해야 할 예시는 다음과 같다.

~~~python
try:
    run_nmap_scan(target)
except:
    pass
~~~

모든 예외를 무시하면 오류 원인을 찾기 어렵기 때문에 사용하지 않는다.

---

## 10. 반환값 작성 규칙

함수의 반환값은 다음 단계에서 사용할 수 있도록 명확한 형식을 유지한다.

예를 들어 대상 검증 함수는 `True` 또는 `False`를 반환한다.

~~~python
def validate_target(target: str) -> bool:
    if not target:
        return False

    if target.startswith("http://") or target.startswith("https://"):
        return True

    return False
~~~

스캔 실행 함수는 원시 결과를 반환한다.

~~~python
def run_nmap_scan(target: str) -> dict:
    raw_result = {}
    return raw_result
~~~

정규화 함수는 표준 형식의 리스트를 반환한다.

~~~python
def normalize_zap_result(raw_result: dict) -> list[dict]:
    findings = []
    return findings
~~~

리포트 생성 함수는 생성된 파일 경로를 문자열로 반환한다.

~~~python
def generate_html_report(
    target: str,
    port_results: list[dict],
    findings: list[dict]
) -> str:
    return "results/reports/report.html"
~~~

---

## 11. 데이터 구조 작성 규칙

프로젝트에서 사용하는 데이터 구조는 가능한 한 딕셔너리와 리스트 기반으로 통일한다.

포트 스캔 결과 예시는 다음과 같다.

~~~python
port_result = {
    "host": "192.168.0.10",
    "port": 80,
    "protocol": "tcp",
    "service": "http",
    "state": "open"
}
~~~

취약점 결과 예시는 다음과 같다.

~~~python
finding = {
    "name": "Missing Security Header",
    "severity": "Medium",
    "description": "X-Frame-Options header is missing",
    "url": "http://example.com"
}
~~~

데이터 구조의 자세한 기준은 `docs/data_type_definition.md` 문서에서 관리한다.

---

## 12. 외부 도구 실행 코드 작성 규칙

Nmap, OWASP ZAP 같은 외부 도구 실행 코드는 `sls_scanner/scanners/` 폴더에 작성한다.

외부 도구 실행 함수는 다음 역할만 담당한다.

~~~text
- 외부 도구 실행
- 실행 결과 수집
- 원시 결과 반환
~~~

외부 도구 실행 함수 안에서 다음 작업을 함께 처리하지 않는다.

~~~text
- 위험도 평가
- HTML 리포트 생성
- CSV 리포트 생성
- 프로젝트 표준 형식으로 정규화
~~~

즉, 스캐너 실행과 결과 가공은 분리한다.

---

## 13. 정규화 코드 작성 규칙

정규화 코드는 `sls_scanner/normalizers/` 폴더에 작성한다.

정규화 함수는 외부 스캐너의 원시 결과를 프로젝트 내부 표준 형식으로 변환한다.

예시는 다음과 같다.

~~~python
def normalize_nmap_result(raw_result: dict) -> list[dict]:
    port_results = []

    # Nmap 원시 결과에서 필요한 필드만 추출한다.
    return port_results
~~~

~~~python
def normalize_zap_result(raw_result: dict) -> list[dict]:
    findings = []

    # ZAP 원시 결과에서 취약점 정보를 표준 형식으로 변환한다.
    return findings
~~~

---

## 14. 리포트 생성 코드 작성 규칙

리포트 생성 코드는 `sls_scanner/reports/` 폴더에 작성한다.

리포트 생성 함수는 정규화된 결과를 입력받아 파일을 생성하고, 생성된 파일 경로를 반환한다.

예시는 다음과 같다.

~~~python
def generate_csv_report(findings: list[dict]) -> str:
    report_path = "results/reports/findings.csv"

    # findings 데이터를 CSV 형식으로 저장한다.
    return report_path
~~~

리포트 생성 함수 안에서 스캐너를 직접 실행하지 않는다.

---

## 15. 테스트 코드 작성 규칙

테스트 코드는 `tests/` 폴더에 작성한다.

테스트 파일 이름은 `test_기능명.py` 형식으로 작성한다.

좋은 예시는 다음과 같다.

~~~text
test_target.py
test_pipeline.py
test_normalizer.py
test_report.py
~~~

테스트 함수 이름은 `test_`로 시작한다.

~~~python
def test_validate_target_with_http_url():
    assert validate_target("http://example.com") is True
~~~

~~~python
def test_validate_target_with_invalid_value():
    assert validate_target("abc") is False
~~~

---

## 16. 테스트 실행 규칙

기능을 수정한 후에는 가능한 범위에서 테스트를 실행한다.

전체 테스트 실행 명령어는 다음과 같다.

~~~powershell
# 전체 테스트를 실행한다.
pytest
~~~

특정 테스트 파일만 실행하려면 다음과 같이 입력한다.

~~~powershell
# 대상 검증 테스트만 실행한다.
pytest tests/test_target.py
~~~

테스트 코드가 아직 부족한 경우에는 최소한 기본 실행 명령어를 확인한다.

~~~powershell
# 기본 스캔 명령어가 실행되는지 확인한다.
python main.py scan --target http://example.com
~~~

---

## 17. import 작성 규칙

import 문은 파일 상단에 모아서 작성한다.

좋은 예시는 다음과 같다.

~~~python
import ipaddress

from sls_scanner.core.exceptions import InvalidTargetError
from sls_scanner.scanners.nmap_scanner import run_nmap_scan
~~~

피해야 할 예시는 다음과 같다.

~~~python
def run_pipeline(target: str) -> None:
    from sls_scanner.scanners.nmap_scanner import run_nmap_scan
    run_nmap_scan(target)
~~~

특별한 이유가 없다면 함수 내부 import는 사용하지 않는다.

---

## 18. 출력 메시지 작성 규칙

콘솔 출력 메시지는 사용자가 현재 진행 상태를 이해할 수 있도록 작성한다.

좋은 예시는 다음과 같다.

~~~python
print("[INFO] Target validation started")
print("[INFO] Nmap scan completed")
print("[ERROR] Invalid target format")
~~~

출력 메시지 접두사는 다음 기준을 사용한다.

~~~text
[INFO]  → 일반 진행 상황
[WARN]  → 주의가 필요한 상황
[ERROR] → 오류 상황
~~~

---

## 19. 보안 관련 개발 규칙

이 프로젝트는 보안 점검 도구를 만드는 프로젝트이므로 다음 기준을 따른다.

~~~text
- 허가받은 대상에 대해서만 스캔하도록 안내한다.
- 실제 운영 서비스에 무단으로 공격성 테스트를 수행하지 않는다.
- 공격 코드나 악용 목적의 코드는 프로젝트에 포함하지 않는다.
- 스캔 결과는 민감한 정보가 포함될 수 있으므로 외부에 공유하지 않는다.
- 테스트는 로컬 실습 환경 또는 허가된 테스트 환경에서 수행한다.
~~~

---

