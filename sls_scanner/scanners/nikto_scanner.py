# sls_scanner/scanners/nikto_scanner.py
# Nikto 구버전(apt) 호환 — JSON 미지원, stdout 텍스트 직접 파싱

import subprocess, re


class NiktoScanner:
    def __init__(self, target: str, strength: str = "medium"):
        self.target   = target
        self.strength = strength
        self.name     = "Nikto"
        self._use_wsl = False

    def _check_installed(self) -> bool:
        for cmd in [["nikto", "-Version"], ["wsl", "nikto", "-Version"]]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                combined = (result.stdout + result.stderr).lower()
                if "nikto" in combined or result.returncode == 0:
                    self._use_wsl = (cmd[0] == "wsl")
                    return True
            except FileNotFoundError:
                continue
            except Exception:
                continue
        return False

    def run(self) -> list:
        if not self._check_installed():
            print("  [Nikto] ⚠️  설치되지 않음 — 건너뜀")
            print("  [Nikto]    또는 WSL:     wsl --install → apt install nikto")
            return []

        timeout_map = {"low": 120, "medium": 240, "high": 360}
        proc_timeout = timeout_map.get(self.strength, 240)

        # -Format json 미지원 구버전 대응 → stdout 텍스트 파싱
        nikto_cmd = [
            "nikto", "-h", self.target,
            "-nointeractive",
        ]
        if self.strength == "high":
            nikto_cmd += ["-Tuning", "123457890abc"]

        cmd = (["wsl"] + nikto_cmd) if self._use_wsl else nikto_cmd

        print(f"\n  [Nikto] 스캔 시작 (강도: {self.strength})...")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=proc_timeout
            )
            raw = self._parse_text(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            print("  [Nikto] 타임아웃 — 부분 결과 없음")
            raw = []
        except FileNotFoundError:
            print("  [Nikto] 실행 파일 없음")
            return []
        except Exception as e:
            print(f"  [Nikto] 실행 오류: {e}")
            return []

        print(f"  [Nikto] 탐지: {len(raw)}건")
        return raw

    def _parse_text(self, text: str) -> list:
        """
        Nikto 텍스트 출력 파싱.
        탐지 라인 패턴: "+ " 또는 "+ OSVDB-" 또는 "- OSVDB-" 로 시작
        헤더/날짜/구분선은 제외.
        """
        results = []
        skip_patterns = [
            "target ip:", "target hostname:", "target port:",
            "start time:", "end time:", "host summary:",
            "nikto v", "-----------", "+ no web server",
            "0 item(s) reported", "1 host(s) tested",
        ]

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # 탐지 항목은 '+ ' 로 시작
            if not line.startswith("+ "):
                continue

            # 스킵 패턴 필터
            ll = line.lower()
            if any(p in ll for p in skip_patterns):
                continue

            # ID 추출 (OSVDB-XXXX 또는 없음)
            vuln_id = ""
            id_match = re.search(r'(OSVDB-\d+|CVE-\d+-\d+)', line)
            if id_match:
                vuln_id = id_match.group(1)

            # URI 추출
            uri_match = re.search(r'(/[\w\-./~%?=&+]*)', line)
            uri = uri_match.group(1) if uri_match else self.target

            msg = line[2:].strip()  # '+ ' 제거

            if msg:
                results.append({
                    "id":         vuln_id,
                    "msg":        msg,
                    "uri":        uri,
                    "references": vuln_id,
                })

        return results