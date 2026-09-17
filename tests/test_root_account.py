from scanners.rules.root_account import check_root_account


class FakeIAMClient:

    def get_account_summary(self):

        return {
            "SummaryMap": {
                "AccountAccessKeysPresent": 1,
                "AccountPasswordPresent": 1,
            }
        }


def test_root_account_security_issues():

    findings = check_root_account(
        FakeIAMClient(),
        account_id="123456789012",
        region="eu-north-1"
    )

    assert len(findings) == 2

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert "ROOT-001" in rule_ids
    assert "ROOT-002" in rule_ids

    for finding in findings:
        assert finding.severity == "CRITICAL"