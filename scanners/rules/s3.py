from scanners.findings import Finding


def _is_public_acl(acl_response):

    for grant in acl_response.get(
        "Grants",
        []
    ):

        grantee = grant.get(
            "Grantee",
            {}
        )

        if (
            grantee.get("Type") == "Group"
            and "AllUsers" in grantee.get(
                "URI",
                ""
            )
        ):

            permission = grant.get(
                "Permission",
                ""
            )

            if permission in {
                "READ",
                "READ_ACP",
                "WRITE",
                "WRITE_ACP",
                "FULL_CONTROL",
            }:

                return True

    return False


def scan_s3(
    s3_client,
    account_id="",
    region=""
) -> list[Finding]:

    findings = []

    try:

        buckets = s3_client.list_buckets().get(
            "Buckets",
            []
        )

    except Exception as exc:

        return [
            Finding(
                rule_id="S3-ERROR",
                title="Unable to inspect S3",
                description=f"S3 scan failed: {exc}",
                severity="INFO",
                service="S3",
                account_id=account_id,
                region=region,
                remediation=(
                    "Check that the scanner role "
                    "has the required S3 permissions."
                ),
            )
        ]

    for bucket in buckets:

        name = bucket["Name"]

        public = False

        try:

            response = s3_client.get_public_access_block(
                Bucket=name
            )

            settings = response[
                "PublicAccessBlockConfiguration"
            ]

            if not all([
                settings.get(
                    "BlockPublicAcls",
                    False
                ),
                settings.get(
                    "IgnorePublicAcls",
                    False
                ),
                settings.get(
                    "BlockPublicPolicy",
                    False
                ),
                settings.get(
                    "RestrictPublicBuckets",
                    False
                ),
            ]):

                public = True

        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:

            public = True

        except Exception:
            pass

        try:

            policy_status = (
                s3_client
                .get_bucket_policy_status(
                    Bucket=name
                )
            )

            if policy_status.get(
                "PolicyStatus",
                {}
            ).get(
                "IsPublic",
                False
            ):

                public = True

        except Exception:
            pass

        try:

            acl = s3_client.get_bucket_acl(
                Bucket=name
            )

            if _is_public_acl(acl):
                public = True

        except Exception:
            pass

        if public:

            findings.append(
                Finding(
                    rule_id="S3-001",
                    title=(
                        "S3 bucket may allow "
                        "public access"
                    ),
                    description=(
                        f"Bucket '{name}' does not have "
                        "effective public-access "
                        "protection."
                    ),
                    severity="HIGH",
                    service="S3",
                    resource_id=name,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Enable all S3 Block Public "
                        "Access settings and remove "
                        "public bucket policies/ACL grants."
                    ),
                    compliance={
                        "controls": [
                            "CIS AWS Foundations - "
                            "S3 public access"
                        ]
                    },
                )
            )

    return findings