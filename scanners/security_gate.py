from scanners.findings import Finding, SEVERITY_ORDER


def security_gate(
    findings: list[Finding],
    minimum_severity: str = "HIGH"
) -> bool:

    threshold = SEVERITY_ORDER[
        minimum_severity.upper()
    ]

    return not any(
        SEVERITY_ORDER.get(
            finding.severity.upper(),
            0
        ) >= threshold
        for finding in findings
    )