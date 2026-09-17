import csv
import io
from datetime import datetime, timezone

from scanners.findings import Finding


def scan_old_access_keys(
    iam_client,
    account_id="",
    region="",
    max_age_days=90
) -> list[Finding]:

    findings = []

    try:

        report = iam_client.get_credential_report()[
            "Content"
        ]

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
                rule_id="KEY-ERROR",
                title="Unable to inspect access keys",
                description=(
                    f"Access-key scan failed: {exc}"
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

    now = datetime.now(timezone.utc)

    for row in rows:

        username = row.get(
            "user",
            ""
        )

        if username == "<root_account>":
            continue

        for key_number in ("1", "2"):

            active = row.get(
                f"access_key_{key_number}_active"
            )

            created = row.get(
                f"access_key_{key_number}_last_rotated"
            )

            if (
                active != "true"
                or not created
                or created == "N/A"
            ):
                continue

            try:

                created_at = datetime.fromisoformat(
                    created.replace(
                        "Z",
                        "+00:00"
                    )
                )

            except ValueError:
                continue

            age_days = (
                now - created_at
            ).days

            if age_days > max_age_days:

                findings.append(
                    Finding(
                        rule_id="KEY-001",
                        title=(
                            "IAM access key is older "
                            "than the configured age"
                        ),
                        description=(
                            f"User '{username}' has "
                            f"active access key "
                            f"{key_number} that is "
                            f"approximately "
                            f"{age_days} days old."
                        ),
                        severity="MEDIUM",
                        service="IAM",
                        resource_id=(
                            f"{username}/"
                            f"access-key-{key_number}"
                        ),
                        region=region,
                        account_id=account_id,
                        remediation=(
                            f"Rotate or remove active "
                            f"access keys older than "
                            f"{max_age_days} days."
                        ),
                    )
                )

    return findings