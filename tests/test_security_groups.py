from scanners.rules.security_groups import scan_security_groups


class FakeEC2Client:

    def describe_security_groups(self):

        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123456",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ],
                        }
                    ],
                }
            ]
        }


def test_open_security_group():

    findings = scan_security_groups(
        FakeEC2Client(),
        account_id="123456789012",
        region="eu-north-1"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SG-001"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource_id == "sg-123456"