terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Fake keys on purpose: they let 'terraform plan' run without an AWS account.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "fake-access-key"
  secret_key                  = "fake-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_bucket" "demo" {
  bucket = "aryan-policy-gate-secure-bucket"
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket                  = aws_s3_bucket.demo.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "demo" {
  bucket = aws_s3_bucket.demo.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# A second bucket that receives the access logs (the "diary" bucket).
resource "aws_s3_bucket" "logs" {
  bucket = "aryan-policy-gate-secure-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# The main bucket writes its access log into the log bucket.
resource "aws_s3_bucket_logging" "demo" {
  bucket        = aws_s3_bucket.demo.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "demo-bucket-logs/"
}

# Secure: websites (HTTPS) are open to everyone, but SSH only from the private network.
resource "aws_security_group" "web" {
  name        = "demo-web"
  description = "Secure demo: HTTPS from anywhere, SSH only from the private network"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# A network whose rejected and accepted traffic is recorded (flow log, traffic type ALL).
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn
}

# A KMS key that rotates itself every year.
resource "aws_kms_key" "trail" {
  description             = "Secure demo: key for CloudTrail logs"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# A trail that covers every region, validates its log files and encrypts them with the key above.
# It writes into the log bucket. (A real trail also needs a bucket policy and a key policy.
# We only ever plan, never apply, so the demo leaves them out.)
resource "aws_cloudtrail" "main" {
  name                       = "demo-secure-trail"
  s3_bucket_name             = aws_s3_bucket.logs.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.trail.arn
}

# A narrow policy: read objects from one bucket only. The ARN is built from the bucket NAME,
# which is known at plan time. (The bucket's .arn attribute is unknown until apply, which would
# make the whole policy text unreadable at plan time, and IAM-06 would flag it.)
resource "aws_iam_policy" "read_logs" {
  name = "demo-read-logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::${aws_s3_bucket.logs.bucket}/*"]
    }]
  })
}
