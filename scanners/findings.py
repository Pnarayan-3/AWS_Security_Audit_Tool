from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


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
    compliance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)