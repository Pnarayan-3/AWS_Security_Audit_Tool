from scanners.findings import Finding


def check_root_account(
    iam_client,
    account_id="",
    region=""
) -> list[Finding]:

    findings = []

    try:
        response = iam_client.get_account_summary()
        summary = response.get("SummaryMap", {})

    except Exception as exc:
        return [
            Finding(
                rule_id="ROOT-ERROR",
                title="Unable to inspect root account",
                description=f"Root-account scan failed: {exc}",
                severity="INFO",
                service="IAM",
                account_id=account_id,
                region=region,
                remediation=(
                    "Check that the scanner has permission "
                    "to call iam:GetAccountSummary."
                ),
            )
        ]

    # Check whether the root account has active access keys
    if summary.get("AccountAccessKeysPresent", 0) > 0:

        findings.append(
            Finding(
                rule_id="ROOT-001",
                title="Root account has an active access key",
                description=(
                    "The AWS account summary indicates that "
                    "the root account has an access key."
                ),
                severity="CRITICAL",
                service="IAM",
                resource_id="root",
                region=region,
                account_id=account_id,
                remediation=(
                    "Remove root account access keys and use "
                    "IAM roles or federated credentials instead."
                ),
            )
        )

    # Check whether the root account has a console password
    if summary.get("AccountPasswordPresent", 0) > 0:

        findings.append(
            Finding(
                rule_id="ROOT-002",
                title="Root account has a console password",
                description=(
                    "The AWS account summary indicates that "
                    "the root account has a console password."
                ),
                severity="CRITICAL",
                service="IAM",
                resource_id="root",
                region=region,
                account_id=account_id,
                remediation=(
                    "Avoid routine root-account use. "
                    "Secure the root account and use "
                    "IAM roles or federation for administration."
                ),
            )
        )

    return findings