terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "fake-access-key"
  secret_key                  = "fake-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_bucket" "demo" {
  bucket = "aryan-policy-gate-demo-bucket"
}

# Insecure on purpose: SSH (port 22) open to the whole internet, written three different ways.

# Way 1: the rule is written inline, inside the security group.
resource "aws_security_group" "ssh_inline" {
  name        = "demo-ssh-inline"
  description = "Insecure demo: SSH open to the world (inline rule)"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Way 2: the modern standalone rule.
resource "aws_security_group" "ssh_modern" {
  name        = "demo-ssh-modern"
  description = "Insecure demo: SSH open to the world (modern rule)"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_modern" {
  security_group_id = aws_security_group.ssh_modern.id
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# Way 3: the old standalone rule.
resource "aws_security_group" "ssh_old" {
  name        = "demo-ssh-old"
  description = "Insecure demo: SSH open to the world (old rule)"
}

resource "aws_security_group_rule" "ssh_old" {
  type              = "ingress"
  security_group_id = aws_security_group.ssh_old.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

# Insecure on purpose: RDP (port 3389, Windows remote desktop) open to the whole internet.
resource "aws_security_group" "rdp_inline" {
  name        = "demo-rdp-inline"
  description = "Insecure demo: RDP open to the world"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
