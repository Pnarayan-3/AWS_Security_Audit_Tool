from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str
    service: str
    resource_id: str = ""
    region: str = ""
    account_id: str = ""
    remediation: str = ""
    compliance: Optional[dict] = None