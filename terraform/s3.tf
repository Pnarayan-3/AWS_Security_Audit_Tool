resource "aws_s3_bucket" "public_test" {
  bucket_prefix = "${var.lab_name}-public-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public_test" {
  bucket = aws_s3_bucket.public_test.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_test" {
  bucket = aws_s3_bucket.public_test.id

  depends_on = [
    aws_s3_bucket_public_access_block.public_test
  ]

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Sid       = "PublicReadForAuditLab"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"

      Resource = "${aws_s3_bucket.public_test.arn}/*"
    }]
  })
}