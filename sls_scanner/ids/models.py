"""
IDS/IPS data models

SLS 서비스 보호용 Web IDS/IPS에서 사용하는 탐지 결과 모델입니다.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass(frozen=True)
class IDSFinding:
    attack_type: str
    rule_name: str
    severity: str
    matched_field: str
    matched_value: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
