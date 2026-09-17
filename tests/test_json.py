import json

from scanners.findings import Finding
from report.json_generator import generate_json


def test_generate_json(tmp_path):

    findings = [
        Finding(
            rule_id="S3-001",
            title="Public bucket",
            description="Bucket is public",
            severity="HIGH",
            service="S3",
            resource_id="test-bucket"
        )
    ]

    output = tmp_path / "findings.json"

    result = generate_json(
        findings,
        output
    )

    assert result.exists()

    data = json.loads(
        output.read_text()
    )

    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["high"] == 1
    assert data["findings"][0]["rule_id"] == "S3-001"