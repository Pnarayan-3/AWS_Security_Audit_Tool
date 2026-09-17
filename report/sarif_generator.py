import json
from pathlib import Path


LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def generate_sarif(
    findings,
    output_path="reports/security-results.sarif"
):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rules = {}
    results = []

    for f in findings:

        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,

                "name": f.title,

                "shortDescription": {
                    "text": f.title
                },

                "fullDescription": {
                    "text": f.description
                },

                "help": {
                    "text": (
                        f.remediation
                        or
                        "Review the finding and apply "
                        "the recommended remediation."
                    )
                },
            }
        )

        results.append(
            {
                "ruleId": f.rule_id,

                "level": LEVEL_MAP.get(
                    f.severity.upper(),
                    "warning"
                ),

                "message": {
                    "text": f.description
                },

                "properties": {
                    "severity": f.severity,
                    "service": f.service,
                    "resource": f.resource_id,
                    "region": f.region,
                    "account_id": f.account_id,
                },
            }
        )

    payload = {
        "$schema":
            "https://json.schemastore.org/sarif-2.1.0.json",

        "version": "2.1.0",

        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AWS Security Audit Tool",

                        "version": "1.0.0",

                        "informationUri":
                            "https://github.com/",

                        "rules": list(
                            rules.values()
                        ),
                    }
                },

                "results": results,
            }
        ],
    }

    path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8"
    )

    return path