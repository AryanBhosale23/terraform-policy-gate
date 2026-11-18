# Terraform policy gate report

- Plan: `plan.json` (sha256 `b33b2f515ea6`)
- Terraform version in the plan: 1.17.1
- Run at: 2026-11-18T00:24:29Z
- Result: **FAIL** (14 failing resources)

| Rule | Verdict | Pass | Fail | Not applicable | Title |
|------|---------|------|------|----------------|-------|
| S3-07 | FAIL | 0 | 1 | 0 | Every S3 bucket has a public access block with all four settings on |
| S3-08 | FAIL | 0 | 1 | 0 | Every S3 bucket has default encryption (AES256 or aws:kms) |
| S3-09 | FAIL | 0 | 1 | 0 | Every S3 bucket has versioning enabled |
| S3-10 | FAIL | 0 | 1 | 0 | Every S3 bucket writes server access logs to a log bucket |
| VPC-15 | FAIL | 0 | 1 | 0 | Every VPC has a flow log that records rejected traffic |
| VPC-17 | FAIL | 3 | 3 | 0 | No security group allows SSH (port 22) from the whole internet |
| VPC-18 | FAIL | 5 | 1 | 0 | No security group allows RDP (port 3389) from the whole internet |
| CT-11 | FAIL | 0 | 1 | 0 | Every CloudTrail trail is multi-region, logging, and records all management events |
| CT-12 | FAIL | 0 | 1 | 0 | Every CloudTrail trail has log file validation enabled |
| CT-13 | FAIL | 0 | 1 | 0 | Every CloudTrail trail encrypts its logs with a KMS key |
| KMS-19 | FAIL | 0 | 1 | 0 | Automatic rotation is enabled on customer-managed KMS keys |
| IAM-06 | FAIL | 0 | 1 | 0 | No IAM policy grants full administrator access |

## Findings

- **S3-07** `aws_s3_bucket.demo`: needs a public access block with all four settings on. Fix: Add an aws_s3_bucket_public_access_block for the bucket with all four settings set to true.
- **S3-08** `aws_s3_bucket.demo`: needs default encryption (AES256 or aws:kms). Fix: Add an aws_s3_bucket_server_side_encryption_configuration for the bucket (AES256 at minimum, aws:kms if required).
- **S3-09** `aws_s3_bucket.demo`: needs a versioning resource with status Enabled. Fix: Add an aws_s3_bucket_versioning for the bucket with status = "Enabled".
- **S3-10** `aws_s3_bucket.demo`: needs access logging to a log bucket. Fix: Add an aws_s3_bucket_logging for the bucket with a target_bucket. A bucket that only receives logs is exempt.
- **VPC-15** `aws_vpc.main`: needs a flow log with traffic type REJECT or ALL. Fix: Add an aws_flow_log for the VPC with traffic_type = "REJECT" or "ALL".
- **VPC-17** `aws_security_group.ssh_inline`: allows SSH (port 22) from the whole internet. Fix: Replace the 0.0.0.0/0 (or ::/0) source with a trusted range, or delete the rule.
- **VPC-17** `aws_security_group_rule.ssh_old`: allows SSH (port 22) from the whole internet. Fix: Replace the 0.0.0.0/0 (or ::/0) source with a trusted range, or delete the rule.
- **VPC-17** `aws_vpc_security_group_ingress_rule.ssh_modern`: allows SSH (port 22) from the whole internet. Fix: Replace the 0.0.0.0/0 (or ::/0) source with a trusted range, or delete the rule.
- **VPC-18** `aws_security_group.rdp_inline`: allows RDP (port 3389) from the whole internet. Fix: Replace the 0.0.0.0/0 (or ::/0) source with a trusted range, or delete the rule.
- **CT-11** `aws_cloudtrail.weak`: must be multi-region, logging, and record all management events. Fix: Set is_multi_region_trail = true, keep enable_logging = true and record all management events (reads and writes).
- **CT-12** `aws_cloudtrail.weak`: needs enable_log_file_validation = true. Fix: Set enable_log_file_validation = true on the trail.
- **CT-13** `aws_cloudtrail.weak`: needs kms_key_id so its logs are encrypted with KMS. Fix: Set kms_key_id on the trail to a KMS key.
- **KMS-19** `aws_kms_key.no_rotation`: needs enable_key_rotation = true. Fix: Set enable_key_rotation = true on the key.
- **IAM-06** `aws_iam_policy.admin`: grants full administrator access (Allow * on *). Fix: Replace the wildcard action and resource with the specific actions and resources needed, and never attach AdministratorAccess.

## Where Checkov and the OPA rules disagree

- **VPC-17** `aws_security_group_rule.ssh_old`: OPA says FAIL, Checkov says CKV_AWS_24 PASSED. Agreed in every case tried: IPv6, port ranges, all-protocol rules and the three rule forms.
