output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "test_bucket_name" {
  value = aws_s3_bucket.public_test.bucket
}

output "test_iam_user" {
  value = aws_iam_user.no_mfa_test.name
}

output "test_security_group_id" {
  value = aws_security_group.open_test.id
}