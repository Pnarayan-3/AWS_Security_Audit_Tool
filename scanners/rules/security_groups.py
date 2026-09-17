from scanners.findings import Finding


def scan_security_groups(
    ec2_client,
    account_id="",
    region=""
) -> list[Finding]:

    findings = []

    try:

        response = (
            ec2_client
            .describe_security_groups()
        )

    except Exception as exc:

        return [
            Finding(
                rule_id="SG-ERROR",
                title=(
                    "Unable to inspect "
                    "security groups"
                ),
                description=(
                    f"Security-group scan failed: {exc}"
                ),
                severity="INFO",
                service="EC2",
                account_id=account_id,
                region=region,
                remediation=(
                    "Check that the scanner role has "
                    "ec2:DescribeSecurityGroups "
                    "permission."
                ),
            )
        ]

    for sg in response.get(
        "SecurityGroups",
        []
    ):

        for permission in sg.get(
            "IpPermissions",
            []
        ):

            for ip_range in permission.get(
                "IpRanges",
                []
            ):

                if ip_range.get(
                    "CidrIp"
                ) == "0.0.0.0/0":

                    from_port = permission.get(
                        "FromPort"
                    )

                    to_port = permission.get(
                        "ToPort"
                    )

                    protocol = permission.get(
                        "IpProtocol",
                        ""
                    )

                    if protocol == "-1":
                        port_text = "all ports"
                    else:
                        port_text = (
                            f"{from_port}-{to_port}"
                        )

                    findings.append(
                        Finding(
                            rule_id="SG-001",
                            title=(
                                "Security group allows "
                                "IPv4 traffic from "
                                "the internet"
                            ),
                            description=(
                                f"Security group "
                                f"'{sg.get('GroupId')}' "
                                f"allows {protocol} "
                                f"traffic on "
                                f"{port_text} from "
                                f"0.0.0.0/0."
                            ),
                            severity="HIGH",
                            service="EC2",
                            resource_id=sg.get(
                                "GroupId",
                                ""
                            ),
                            region=region,
                            account_id=account_id,
                            remediation=(
                                "Restrict inbound rules "
                                "to trusted CIDR ranges "
                                "or security groups."
                            ),
                            compliance={
                                "controls": [
                                    "CIS AWS Foundations - "
                                    "unrestricted ingress"
                                ]
                            },
                        )
                    )

    return findings