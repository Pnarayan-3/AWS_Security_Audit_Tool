variable "aws_region" {
  description = "AWS region for the security lab"
  type        = string
  default     = "eu-north-1"
}

variable "lab_name" {
  description = "Name prefix for lab resources"
  type        = string
  default     = "aws-security-audit-lab"
}