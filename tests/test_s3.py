from scanners.rules.s3 import scan_s3


class FakeExceptions:

    class NoSuchPublicAccessBlockConfiguration(Exception):
        pass


class FakeS3Client:

    exceptions = FakeExceptions

    def list_buckets(self):
        return {
            "Buckets": [
                {"Name": "public-test-bucket"}
            ]
        }

    def get_public_access_block(self, Bucket):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }

    def get_bucket_policy_status(self, Bucket):
        return {
            "PolicyStatus": {
                "IsPublic": True
            }
        }

    def get_bucket_acl(self, Bucket):
        return {
            "Grants": []
        }


def test_public_s3_bucket():

    findings = scan_s3(
        FakeS3Client(),
        account_id="123456789012",
        region="eu-north-1"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "S3-001"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource_id == "public-test-bucket"