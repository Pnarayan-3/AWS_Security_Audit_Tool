import csv
import io

from scanners.findings import Finding


def scan_iam_mfa(
    iam_client,
    account_id="",
    region=""
) -> list[Finding]:

    findings = []

    try:
        users = iam_client.list_users().get(
            "Users",
            []
        )

    except Exception as exc:
        return [
            Finding(
                rule_id="IAM-ERROR",
                title="Unable to inspect IAM users",
                description=f"IAM scan failed: {exc}",
                severity="INFO",
                service="IAM",
                account_id=account_id,
                region=region,
                remediation=(
                    "Check that the scanner role "
                    "has the required IAM permissions."
                ),
            )
        ]

    for user in users:

        username = user["UserName"]

        try:
            devices = iam_client.list_mfa_devices(
                UserName=username
            ).get(
                "MFADevices",
                []
            )

        except Exception:
            devices = []

        if not devices:

            findings.append(
                Finding(
                    rule_id="IAM-001",
                    title="IAM user does not have MFA enabled",
                    description=(
                        f"IAM user '{username}' "
                        "has no registered MFA device."
                    ),
                    severity="MEDIUM",
                    service="IAM",
                    resource_id=username,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Enable MFA for the IAM user, "
                        "or preferably use federated/"
                        "temporary credentials."
                    ),
                    compliance={
                        "controls": [
                            "CIS AWS Foundations - MFA"
                        ]
                    },
                )
            )

    return findings


def scan_root_account(
    iam_client,
    account_id="",
    region=""
) -> list[Finding]:

    findings = []

    try:

        response = iam_client.get_credential_report()

        report = response["Content"]

        if isinstance(report, bytes):
            report = report.decode("utf-8")

        rows = list(
            csv.DictReader(
                io.StringIO(report)
            )
        )

    except Exception as exc:

        return [
            Finding(
                rule_id="ROOT-ERROR",
                title=(
                    "Unable to inspect root account "
                    "credential report"
                ),
                description=(
                    f"Root-account scan failed: {exc}"
                ),
                severity="INFO",
                service="IAM",
                account_id=account_id,
                region=region,
                remediation=(
                    "Ensure iam:GetCredentialReport "
                    "is allowed."
                ),
            )
        ]

    for row in rows:

        if row.get("user") != "<root_account>":
            continue

        if row.get("password_enabled") == "true":

            findings.append(
                Finding(
                    rule_id="ROOT-001",
                    title=(
                        "Root account has a console "
                        "password enabled"
                    ),
                    description=(
                        "The IAM credential report shows "
                        "that the root account has a "
                        "console password."
                    ),
                    severity="CRITICAL",
                    service="IAM",
                    resource_id="root",
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Avoid routine root-account use. "
                        "Secure the root account and use "
                        "IAM roles/federation for daily "
                        "administration."
                    ),
                )
            )

        for key_number in ("1", "2"):

            if row.get(
                f"access_key_{key_number}_active"
            ) == "true":

                findings.append(
                    Finding(
                        rule_id="ROOT-002",
                        title=(
                            "Root account has an "
                            "active access key"
                        ),
                        description=(
                            f"The root account has active "
                            f"access key {key_number}."
                        ),
                        severity="CRITICAL",
                        service="IAM",
                        resource_id="root",
                        region=region,
                        account_id=account_id,
                        remediation=(
                            "Remove root access keys and "
                            "use IAM roles or federated "
                            "credentials."
                        ),
                    )
                )

    return findings