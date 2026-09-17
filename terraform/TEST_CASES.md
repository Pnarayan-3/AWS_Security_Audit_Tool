# Terraform Security Test Cases

This Terraform configuration creates intentionally insecure AWS resources
for testing the AWS Security Audit Tool.

## Test Cases

### 1. Public S3 Bucket

Resource:

- `aws_s3_bucket.public_test`

Expected scanner finding:

- Rule: `S3-001`
- Severity: `HIGH`

The bucket has public access settings disabled and a public-read bucket policy.

---

### 2. IAM User Without MFA

Resource:

- `aws_iam_user.no_mfa_test`

Expected scanner finding:

- Rule: `IAM-001`
- Severity: `MEDIUM`

The IAM user is created without an MFA device.

---

### 3. Open Security Group

Resource:

- `aws_security_group.open_test`

Expected scanner finding:

- Rule: `SG-001`
- Severity: `HIGH`

The security group allows SSH traffic from `0.0.0.0/0`.

---

## Resources Not Created

This lab does not create:

- EC2 instances
- IAM access keys
- Root-account credentials

Therefore, the access-key and root-account rules must be tested separately.

---

## Test Commands

Initialize Terraform:

```bash
terraform init