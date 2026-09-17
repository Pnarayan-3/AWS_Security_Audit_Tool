from scanners.findings import Finding
from report.html_generator import generate_html


def test_generate_html(tmp_path):

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

    output = tmp_path / "security-report.html"

    result = generate_html(
        findings,
        output
    )

    assert result.exists()

    html = output.read_text()

    assert "AWS Security Audit Report" in html
    assert "S3-001" in html
    assert "Public bucket" in html
    assert "test-bucket" in html