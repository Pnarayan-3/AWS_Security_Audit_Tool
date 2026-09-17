from scanners.rules.iam import scan_iam_mfa


class FakeIAMClient:

    def list_users(self):
        return {
            "Users": [
                {"UserName": "alice"},
                {"UserName": "bob"},
            ]
        }

    def list_mfa_devices(self, UserName):
        if UserName == "alice":
            return {
                "MFADevices": []
            }

        return {
            "MFADevices": [
                {"SerialNumber": "mfa-device"}
            ]
        }


def test_iam_user_without_mfa():

    findings = scan_iam_mfa(
        FakeIAMClient(),
        account_id="123456789012",
        region="eu-north-1"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-001"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].resource_id == "alice"