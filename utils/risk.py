RISK_SCORES = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def get_risk_score(severity):
    """
    Convert severity into a numeric risk score.
    """

    return RISK_SCORES.get(
        severity.upper(),
        0
    )


def is_high_risk(severity):
    """
    Return True when severity is HIGH or CRITICAL.
    """

    return get_risk_score(severity) >= RISK_SCORES["HIGH"]


def get_highest_risk(findings):
    """
    Return the highest severity among findings.
    """

    if not findings:
        return "INFO"

    highest = max(
        findings,
        key=lambda finding: get_risk_score(
            finding.severity
        )
    )

    return highest.severity