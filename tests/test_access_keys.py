from datetime import datetime, timedelta, timezone

from scanners.rules.access_keys import scan_old_access_keys


class FakeIAMClient:

    def get_credential_report(self):

        old_date = (
            datetime.now(timezone.utc)
            - timedelta(days=120)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")

        report = (
            "user,access_key_1_active,"
            "access_key_1_last_rotated\n"
            f"alice,true,{old_date}\n"
        )

        return {
            "Content": report
        }


def test_old_access_key():

    findings = scan_old_access_keys(
        FakeIAMClient(),
        account_id="123456789012",
        region="eu-north-1",
        max_age_days=90
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "KEY-001"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].resource_id.startswith(
        "alice/access-key-1"
    )