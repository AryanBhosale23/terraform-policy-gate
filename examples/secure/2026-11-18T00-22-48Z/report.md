# Terraform policy gate report

- Plan: `plan.json` (sha256 `fd4cc016f98f`)
- Terraform version in the plan: 1.17.1
- Run at: 2026-11-18T00:22:48Z
- Result: **PASS** (0 failing resources)

| Rule | Verdict | Pass | Fail | Not applicable | Title |
|------|---------|------|------|----------------|-------|
| S3-07 | PASS | 2 | 0 | 0 | Every S3 bucket has a public access block with all four settings on |
| S3-08 | PASS | 2 | 0 | 0 | Every S3 bucket has default encryption (AES256 or aws:kms) |
| S3-09 | PASS | 2 | 0 | 0 | Every S3 bucket has versioning enabled |
| S3-10 | PASS | 1 | 0 | 1 | Every S3 bucket writes server access logs to a log bucket |
| VPC-15 | PASS | 1 | 0 | 0 | Every VPC has a flow log that records rejected traffic |
| VPC-17 | PASS | 1 | 0 | 0 | No security group allows SSH (port 22) from the whole internet |
| VPC-18 | PASS | 1 | 0 | 0 | No security group allows RDP (port 3389) from the whole internet |
| CT-11 | PASS | 1 | 0 | 0 | Every CloudTrail trail is multi-region, logging, and records all management events |
| CT-12 | PASS | 1 | 0 | 0 | Every CloudTrail trail has log file validation enabled |
| CT-13 | PASS | 1 | 0 | 0 | Every CloudTrail trail encrypts its logs with a KMS key |
| KMS-19 | PASS | 1 | 0 | 0 | Automatic rotation is enabled on customer-managed KMS keys |
| IAM-06 | PASS | 1 | 0 | 0 | No IAM policy grants full administrator access |

## Where Checkov and the OPA rules disagree

- **S3-08** `aws_s3_bucket.demo`: OPA says PASS, Checkov says CKV_AWS_145 FAILED. Checkov requires a KMS key. This gate accepts AES256 as well, to match the scanner in Project 1.
- **S3-08** `aws_s3_bucket.logs`: OPA says PASS, Checkov says CKV_AWS_145 FAILED. Checkov requires a KMS key. This gate accepts AES256 as well, to match the scanner in Project 1.
