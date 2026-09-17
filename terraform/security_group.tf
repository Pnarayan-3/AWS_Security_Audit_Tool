resource "aws_security_group" "open_test" {
  name        = "${var.lab_name}-open"
  description = "Intentional insecure security group for scanner testing"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Intentional test rule"

    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_vpc" "default" {
  default = true
}