import json

from scanners.findings import Finding
from report.sarif_generator import generate_sarif


def test_generate_sarif(tmp_path):

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

    output = tmp_path / "security-results.sarif"

    result = generate_sarif(
        findings,
        output
    )

    assert result.exists()

    data = json.loads(
        output.read_text()
    )

    assert data["version"] == "2.1.0"

    results = data["runs"][0]["results"]

    assert len(results) == 1
    assert results[0]["ruleId"] == "S3-001"
    assert results[0]["level"] == "error"