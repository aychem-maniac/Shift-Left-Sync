# sls_scanner/scanners/nuclei_scanner.py

import subprocess, json, os, tempfile


class NucleiScanner:
    TEMPLATE_TAGS = {
        "low":    ["cve", "info"],
        "medium": ["cve", "owasp", "misconfig", "exposure"],
        "high":   ["cve", "owasp", "misconfig", "exposure",
                   "sqli", "xss", "ssrf", "rce", "lfi"],
    }

    def __init__(self, target: str, strength: str = "medium"):
        self.target   = target
        self.strength = strength
        self.name     = "Nuclei"
        self.tags     = self.TEMPLATE_TAGS.get(strength, self.TEMPLATE_TAGS["medium"])

    def _check_installed(self) -> bool:
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def run(self) -> list:
        if not self._check_installed():
            print("  [Nuclei] ⚠️  설치되지 않음 — 건너뜀")
            print("  [Nuclei]    Windows 설치: https://github.com/projectdiscovery/nuclei/releases")
            return []

        tmp      = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w")
        out_path = tmp.name
        tmp.close()

        tags_str = ",".join(self.tags)

        # -jsonl : Nuclei v3+ 호환 (v2의 -json 대체)
        # -no-interactsh : 외부 OAST 서버 연결 없이 실행
        cmd = [
            "nuclei",
            "-u",    self.target,
            "-tags", tags_str,
            "-o",    out_path,
            "-jsonl",
            "-no-color",
            "-no-interactsh",
            "-timeout", "10",
        ]
        if self.strength == "high":
            cmd += ["-rate-limit", "150", "-bulk-size", "25"]
        else:
            cmd += ["-rate-limit", "50",  "-bulk-size", "10"]

        print(f"\n  [Nuclei] 스캔 시작 (태그: {tags_str})...")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=600
            )
            if result.returncode not in (0, 1):
                print(f"  [Nuclei] 실행 오류 (code={result.returncode}): {result.stderr[:150]}")
        except subprocess.TimeoutExpired:
            print("  [Nuclei] 타임아웃 — 부분 결과 사용")
        except FileNotFoundError:
            print("  [Nuclei] 실행 파일 없음")
            return []
        except Exception as e:
            print(f"  [Nuclei] 예외: {e}")
            return []

        raw = self._parse_output(out_path)
        try:
            os.unlink(out_path)
        except Exception:
            pass

        print(f"  [Nuclei] 탐지: {len(raw)}건")
        return raw

    def _parse_output(self, jsonl_path: str) -> list:
        results = []
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print("  [Nuclei] 출력 파일 없음 (탐지 0건)")
        return results