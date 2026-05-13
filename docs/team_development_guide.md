# 팀 개발 가이드 문서

## 1. 문서 목적

이 문서는 `Shift-Left-Sync` 프로젝트를 팀 단위로 개발할 때 필요한 작업 규칙과 진행 절차를 정리하기 위한 문서이다.

팀원들이 같은 기준으로 브랜치를 만들고, 코드를 작성하고, 커밋하고, Pull Request를 생성할 수 있도록 하는 것을 목적으로 한다.

---

## 2. 기본 개발 흐름

프로젝트 개발은 다음 흐름을 기준으로 진행한다.

~~~text
1. dev 브랜치를 최신 상태로 가져온다.
2. 작업 목적에 맞는 새 브랜치를 만든다.
3. 맡은 기능 또는 문서를 수정한다.
4. 실행 테스트 또는 기본 확인을 한다.
5. 변경 파일을 확인한다.
6. 커밋을 생성한다.
7. 원격 저장소에 push한다.
8. GitHub에서 Pull Request를 생성한다.
9. 리뷰 후 dev 브랜치에 병합한다.
~~~

---

## 3. 브랜치 사용 규칙

브랜치는 작업 목적에 따라 나누어 사용한다.

~~~text
main   → 최종 안정 버전 관리
dev    → 개발 통합 브랜치
stage  → 배포 전 테스트 또는 검증용 브랜치
docs/* → 문서 작업 브랜치
feat/* → 기능 개발 브랜치
fix/*  → 버그 수정 브랜치
test/* → 테스트 코드 작성 브랜치
~~~

---

## 4. 브랜치 이름 규칙

브랜치 이름은 작업 목적이 드러나도록 작성한다.

### 4.1 문서 작업 브랜치

~~~text
docs/team-development-guide
docs/folder-structure
docs/data-type-definition
~~~

### 4.2 기능 개발 브랜치

~~~text
feat/nmap-scan
feat/zap-scan
feat/report-generator
feat/target-validation
~~~

### 4.3 버그 수정 브랜치

~~~text
fix/import-error
fix/pipeline-error
fix/report-path-error
~~~

### 4.4 테스트 작업 브랜치

~~~text
test/target-validation
test/pipeline
test/normalizer
~~~

---

## 5. 작업 시작 전 확인 사항

작업을 시작하기 전에 반드시 현재 브랜치와 상태를 확인한다.

~~~powershell
# 현재 브랜치를 확인한다.
git branch

# 현재 변경 상태를 확인한다.
git status
~~~

작업 브랜치를 만들기 전에 `dev` 브랜치로 이동한다.

~~~powershell
# dev 브랜치로 이동한다.
git checkout dev
~~~

원격 저장소의 최신 내용을 가져온다.

~~~powershell
# 원격 dev 브랜치의 최신 내용을 가져온다.
git pull origin dev
~~~

작업 목적에 맞는 새 브랜치를 만든다.

~~~powershell
# 문서 작업용 브랜치를 만들고 이동한다.
git checkout -b docs/team-development-guide
~~~

---

## 6. 작업 중 기본 규칙

작업 중에는 다음 규칙을 따른다.

~~~text
- 하나의 브랜치에서는 하나의 목적을 가진 작업만 진행한다.
- 문서 작업과 기능 개발 작업을 같은 브랜치에서 섞지 않는다.
- 기능을 수정한 경우 관련 테스트도 함께 확인한다.
- 파일을 삭제하거나 구조를 바꿀 때는 팀원에게 공유한다.
- 공통 파일을 수정할 때는 충돌 가능성을 고려한다.
~~~

예를 들어 `docs/team_development_guide.md`를 작성하는 브랜치에서는 문서 작업만 진행하고, `pipeline.py` 같은 기능 코드는 수정하지 않는다.

---

## 7. 파일 수정 후 확인 명령어

파일을 수정한 후에는 변경 상태를 확인한다.

~~~powershell
# 어떤 파일이 수정되었는지 확인한다.
git status
~~~

수정 내용을 자세히 확인한다.

~~~powershell
# 수정된 내용을 확인한다.
git diff
~~~

특정 파일만 확인하려면 다음과 같이 입력한다.

~~~powershell
# 특정 파일의 수정 내용을 확인한다.
git diff docs/team_development_guide.md
~~~

---

## 8. 커밋 규칙

커밋은 작업 단위가 명확할 때 생성한다.

커밋 메시지는 다음 형식을 사용한다.

~~~text
타입: 작업 내용 요약
~~~

예시는 다음과 같다.

~~~text
docs: 팀 개발 가이드 문서 추가
feat: nmap 스캔 실행 함수 추가
fix: pipeline import 오류 수정
test: target 검증 테스트 추가
refactor: 리포트 생성 로직 정리
~~~

---

## 9. 커밋 타입 기준

커밋 타입은 다음 기준으로 사용한다.

~~~text
docs     → 문서 작성 또는 수정
feat     → 새로운 기능 추가
fix      → 버그 수정
test     → 테스트 코드 추가 또는 수정
refactor → 기능 변화 없이 코드 구조 개선
chore    → 설정 파일, 폴더 정리, 기타 작업
style    → 코드 포맷 수정
~~~

---

## 10. 커밋 생성 방법

변경 파일을 스테이징한다.

~~~powershell
# 수정한 문서 파일을 스테이징한다.
git add docs/team_development_guide.md
~~~

커밋을 생성한다.

~~~powershell
# 팀 개발 가이드 문서 추가 커밋을 생성한다.
git commit -m "docs: 팀 개발 가이드 문서 추가"
~~~

현재 상태를 다시 확인한다.

~~~powershell
# 커밋 후 작업 상태를 확인한다.
git status
~~~

---

## 11. Push 규칙

작업 브랜치를 원격 저장소에 올린다.

~~~powershell
# 현재 브랜치를 원격 저장소에 push한다.
git push -u origin docs/team-development-guide
~~~

이미 upstream이 연결된 브랜치라면 다음 명령어만 사용해도 된다.

~~~powershell
# 현재 브랜치의 변경 사항을 원격 저장소에 push한다.
git push
~~~

---

## 12. Pull Request 작성 규칙

작업 브랜치를 원격 저장소에 push한 후 GitHub에서 Pull Request를 생성한다.

Pull Request는 작업 브랜치에서 `dev` 브랜치로 보낸다.

~~~text
base: dev
compare: docs/team-development-guide
~~~

Pull Request 제목은 커밋 메시지와 비슷하게 작성한다.

~~~text
docs: 팀 개발 가이드 문서 추가
~~~

---

## 13. Pull Request 내용 작성 기준

Pull Request 본문에는 다음 내용을 작성한다.

~~~md
## 작업 목적

- 팀 개발 규칙을 문서화하기 위해 `team_development_guide.md` 파일을 추가했다.

## 주요 변경 사항

- 브랜치 사용 규칙 정리
- 작업 시작 전 확인 명령어 정리
- 커밋 메시지 규칙 정리
- Pull Request 작성 규칙 정리
- 작업 완료 기준 정리

## 확인 사항

- 문서 파일 위치 확인 완료
- 마크다운 형식 확인 완료
- 불필요한 코드 파일 수정 없음
~~~

---

## 14. 코드 리뷰 규칙

Pull Request가 생성되면 다른 팀원이 변경 내용을 확인한다.

리뷰어는 다음 항목을 확인한다.

~~~text
- 작업 목적에 맞는 파일만 수정되었는지 확인
- 문서 내용이 이해하기 쉬운지 확인
- 코드 작업의 경우 실행 오류가 없는지 확인
- 기능 작업의 경우 테스트 결과가 있는지 확인
- 불필요한 파일이 포함되지 않았는지 확인
~~~

리뷰 후 문제가 없으면 `dev` 브랜치에 병합한다.

---

## 15. 병합 규칙

작업 브랜치는 바로 `main`에 병합하지 않는다.

기본 병합 흐름은 다음과 같다.

~~~text
작업 브랜치 → dev → stage → main
~~~

각 브랜치의 역할은 다음과 같다.

~~~text
작업 브랜치 → 개인 작업 공간
dev          → 개발 결과 통합 공간
stage        → 배포 전 검증 공간
main         → 최종 안정 버전 공간
~~~

---

## 16. 충돌 방지 규칙

여러 명이 동시에 작업할 경우 충돌을 줄이기 위해 다음 규칙을 따른다.

~~~text
- 작업 시작 전 항상 dev 브랜치를 최신 상태로 가져온다.
- 같은 파일을 여러 명이 동시에 수정하지 않도록 역할을 나눈다.
- 공통 파일을 수정할 때는 팀원에게 먼저 공유한다.
- 큰 기능은 작은 작업 단위로 나누어 커밋한다.
- 오래된 브랜치에서 계속 작업하지 않는다.
~~~

---

## 17. 기능 개발 작업 기준

기능 개발은 다음 순서로 진행한다.

~~~text
1. 담당 기능의 문서를 확인한다.
2. 입력 데이터와 출력 데이터를 확인한다.
3. 작성해야 할 파일 위치를 확인한다.
4. 함수 이름과 역할을 정한다.
5. 최소 동작 코드를 먼저 작성한다.
6. 실행 테스트를 한다.
7. 예외 처리를 추가한다.
8. 테스트 코드를 작성하거나 기본 테스트를 수행한다.
9. 커밋 후 Pull Request를 생성한다.
~~~

예를 들어 Nmap 스캔 기능을 맡은 경우 다음 파일을 중심으로 작업한다.

~~~text
sls_scanner/scanners/nmap_scanner.py
sls_scanner/normalizers/nmap_normalizer.py
tests/test_normalizer.py
~~~

---

## 18. 문서 작업 기준

문서 작업은 다음 순서로 진행한다.

~~~text
1. 문서 목적을 먼저 작성한다.
2. 문서 대상 파일 또는 기능을 명확히 한다.
3. 큰 항목부터 작성한다.
4. 세부 설명을 추가한다.
5. 예시 명령어 또는 예시 구조를 추가한다.
6. 오탈자와 마크다운 형식을 확인한다.
7. 커밋 후 Pull Request를 생성한다.
~~~

문서 작업 시 문장 끝은 가능한 한 보고서형 문체로 통일한다.

예시는 다음과 같다.

~~~text
좋은 예시:
- 이 파일은 전체 스캔 흐름을 관리하는 역할을 한다.
- 이 폴더는 스캐너 결과를 표준 형식으로 변환하는 코드를 관리한다.

피해야 할 예시:
- 여기서 대충 처리하면 된다.
- 나중에 알아서 수정한다.
~~~

---

## 19. 테스트 기준

기능을 수정하거나 추가한 경우 가능한 범위에서 테스트를 수행한다.

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

현재 테스트 코드가 충분하지 않은 경우에는 최소한 실행 명령어로 오류 여부를 확인한다.

~~~powershell
# 기본 스캔 명령어 실행 여부를 확인한다.
python main.py scan --target http://example.com
~~~

---

## 20. 작업 완료 기준

작업은 다음 조건을 만족했을 때 완료로 본다.

~~~text
- 맡은 파일 작성 또는 수정 완료
- git status로 변경 파일 확인 완료
- 불필요한 파일이 포함되지 않았는지 확인 완료
- 실행 테스트 또는 문서 형식 확인 완료
- 커밋 생성 완료
- 원격 저장소 push 완료
- Pull Request 생성 완료
~~~

---

## 21. 문서 작업 완료 후 예시 명령어

`team_development_guide.md` 문서 작성 후에는 다음 명령어를 실행한다.

~~~powershell
# 현재 변경 상태를 확인한다.
git status

# 작성한 문서를 스테이징한다.
git add docs/team_development_guide.md

# 문서 추가 커밋을 생성한다.
git commit -m "docs: 팀 개발 가이드 문서 추가"

# 현재 브랜치를 원격 저장소에 push한다.
git push -u origin docs/team-development-guide
~~~

---

