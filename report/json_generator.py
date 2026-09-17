import json
from pathlib import Path


def generate_json(findings, output_path="reports/findings.json"):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "summary": {
            "total_findings": len(findings),
            "critical": sum(f.severity == "CRITICAL" for f in findings),
            "high": sum(f.severity == "HIGH" for f in findings),
            "medium": sum(f.severity == "MEDIUM" for f in findings),
            "low": sum(f.severity == "LOW" for f in findings),
            "info": sum(f.severity == "INFO" for f in findings),
        },
        "findings": [f.to_dict() for f in findings],
    }

    path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8"
    )

    return path