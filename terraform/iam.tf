resource "aws_iam_user" "no_mfa_test" {
  name = "${var.lab_name}-no-mfa"
}

resource "aws_iam_user_policy" "no_mfa_test" {
  user = aws_iam_user.no_mfa_test.name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:GetCallerIdentity"]
      Resource = "*"
    }]
  })
}