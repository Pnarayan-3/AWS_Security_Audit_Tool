import boto3

from scanners.findings import Finding

from scanners.rules.access_keys import (
    scan_old_access_keys
)

from scanners.rules.iam import (
    scan_iam_mfa,
    scan_root_account
)

from scanners.rules.s3 import (
    scan_s3
)

from scanners.rules.security_groups import (
    scan_security_groups
)


class SecurityScanner:

    def __init__(
        self,
        session=None,
        region=None
    ):

        self.session = (
            session
            or boto3.Session(
                region_name=region
            )
        )

        self.region = (
            region
            or self.session.region_name
            or "unknown"
        )

        sts = self.session.client("sts")

        self.account_id = (
            sts.get_caller_identity()["Account"]
        )


    def scan(self) -> list[Finding]:

        findings = []

        iam = self.session.client("iam")

        s3 = self.session.client("s3")

        ec2 = self.session.client(
            "ec2",
            region_name=self.region
        )

        findings.extend(
            scan_iam_mfa(
                iam,
                self.account_id,
                self.region
            )
        )

        findings.extend(
            scan_root_account(
                iam,
                self.account_id,
                self.region
            )
        )

        findings.extend(
            scan_old_access_keys(
                iam,
                self.account_id,
                self.region
            )
        )

        findings.extend(
            scan_s3(
                s3,
                self.account_id,
                self.region
            )
        )

        findings.extend(
            scan_security_groups(
                ec2,
                self.account_id,
                self.region
            )
        )

        return findings