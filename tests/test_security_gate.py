from scanners.findings import Finding
from scanners.security_gate import security_gate


def test_security_gate_passes_without_high_findings():

    findings = [
        Finding(
            rule_id="IAM-001",
            title="No MFA",
            description="User has no MFA",
            severity="MEDIUM",
            service="IAM"
        )
    ]

    assert security_gate(
        findings,
        "HIGH"
    ) is True


def test_security_gate_fails_with_high_finding():

    findings = [
        Finding(
            rule_id="S3-001",
            title="Public bucket",
            description="Bucket is public",
            severity="HIGH",
            service="S3"
        )
    ]

    assert security_gate(
        findings,
        "HIGH"
    ) is False


def test_security_gate_fails_with_critical_finding():

    findings = [
        Finding(
            rule_id="ROOT-001",
            title="Root access key",
            description="Root has access key",
            severity="CRITICAL",
            service="IAM"
        )
    ]

    assert security_gate(
        findings,
        "HIGH"
    ) is False