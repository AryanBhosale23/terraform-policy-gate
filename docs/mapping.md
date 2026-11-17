# Control mapping sources and decisions

Pinned benchmark: **CIS Amazon Web Services Foundations Benchmark v7.1.0** (the same version as
[aws-cis-scanner](https://github.com/AryanBhosale23/aws-cis-scanner), so the 12 rule IDs mean the same thing in both projects).
Other sources: NIST SP 800-53 Rev 5 catalog; ISO/IEC 27001:2022 Annex A; AICPA SOC 2 Trust Services Criteria.
CIS recommendation numbers change between benchmark versions, so every CIS number below is for v7.1.0 only.
Cite recommendations by number. Do not copy benchmark text into this repo (see CIS terms of use).

The NIST, ISO and SOC 2 columns are a judgment, not an official crosswalk. Each row says why the mapping holds,
and where the gate covers less (or more) than the CIS recommendation, the notes say so.

## Scope notes that apply to every rule

- **A plan, not an account.** The gate judges what a Terraform plan will create or change. It cannot see
  settings made by hand, drift, or resources created outside Terraform. It cannot judge account-level
  settings either. The scanner in Project 1 covers those.
- **No data must not pass.** A missing value, an unreadable policy, or a value Terraform cannot know until
  apply (for example an attribute computed from another resource) is a FAIL, never a PASS. A rule that cannot
  run is an ERROR.
- **One record per resource**, so each resource is its own evidence. A resource a rule deliberately skips is a
  NOT_APPLICABLE record with the reason.
- **Resources being deleted are ignored.**
- **Root module only.** The links between a resource and its companion (for example a bucket and its
  versioning resource) are read from the root module of the plan. Resources inside child modules, and
  resources made with `count` or `for_each`, are judged but their links are not followed, so the rules that
  need a link fail them. The error is always in the cautious direction.

## Which engine decides

OPA/Rego decides every rule. Checkov runs on the same plan with the one check that matches each rule, as an
independent second opinion. The report lists every disagreement. I compared them on the example folders and
on small test cases (Checkov 3.4.5, November 2026). "Same" means they agreed on everything I tried.

## The mapping

| Rule | CIS v7.1.0 | CIS status | NIST 800-53 r5 | ISO 27001:2022 | SOC 2 | Why this mapping, and what the gate judges |
|------|-----------|------------|----------------|----------------|-------|--------------------------------------------|
| S3-07 public access block | 3.1.4 | Automated | AC-3 | A.8.3 | CC6.1 | The four Block Public Access settings are a guard that keeps buckets from being opened to the internet by mistake. Every bucket in the plan needs its own `aws_s3_bucket_public_access_block` with all four settings `true`. A setting that is missing or `false` fails. The account-level resource (`aws_s3_account_public_access_block`) is not judged, so a bucket with no block of its own fails even if the account level protects it (strict, as in Project 1). |
| S3-08 default encryption | 3.1.5 | Manual | SC-28 | A.8.24 | CC6.1 | Default encryption means objects are stored encrypted without relying on each uploader to ask for it. Every bucket needs an `aws_s3_bucket_server_side_encryption_configuration` whose algorithm is `AES256` or `aws:kms`. CIS lists this as Manual; the gate automates the "is encryption on" part only and does not judge the key management. |
| S3-09 versioning | none | n/a | CP-9 | A.8.13 | A1.2 | Versioning keeps earlier copies of objects, so an accidental delete or overwrite can be undone. Not its own CIS recommendation in v7.1.0 (versioning appears only inside 3.1.2, MFA Delete). Every bucket needs an `aws_s3_bucket_versioning` with `status = "Enabled"`. `Suspended`, a missing status and no resource at all all fail. |
| S3-10 server access logging | 4.4 (partial) | Manual | AU-12 | A.8.15 | CC7.2 | Server access logs give an audit trail of who requested which objects. CIS 4.4 covers the CloudTrail S3 bucket only; this rule covers every bucket, which is broader. Every bucket needs an `aws_s3_bucket_logging` that names a `target_bucket`. **Differs from Project 1:** a bucket that is the target of another bucket's logging is exempt (NOT_APPLICABLE), because a plan cannot express "logs somewhere else" without an endless chain of log buckets. Project 1 fails a bucket that only receives logs. |
| VPC-15 flow logs | 4.7 | Automated | SI-4 | A.8.16 | CC7.2 | Flow logs record which network connections reached a VPC and which were refused, which supports spotting unusual traffic. Every `aws_vpc` needs an `aws_flow_log` whose `vpc_id` points at it and whose `traffic_type` is `REJECT` or `ALL`, because the CIS description recommends recording rejected packets. Project 1 also requires the flow log to be ACTIVE; a flow log in a plan has no status yet, so that part cannot be judged here. A flow log on a subnet or network interface does not count. |
| VPC-17 SSH open to the internet | 6.3 | Automated | SC-7 | A.8.20 | CC6.6 | Opening the SSH port to the whole internet invites password guessing against servers, so limiting sources is boundary protection. Judged in all three ways Terraform writes a rule: inline `ingress` in `aws_security_group`, `aws_vpc_security_group_ingress_rule`, and the older `aws_security_group_rule` (ingress only). Sources `0.0.0.0/0` and `::/0` both count. A port range that includes 22 and protocol `-1` (all traffic) fail too; TCP may be written `tcp`, `TCP` or `6`. **Differs from Project 1:** IPv6 (`::/0`, CIS 6.4) is covered here and not there. A rule with the ports missing counts as open. |
| VPC-18 RDP open to the internet | 6.3 | Automated | SC-7 | A.8.20 | CC6.6 | Same reasoning and same logic as VPC-17 for port 3389, through one shared helper (`policies/open_ports.rego`). |
| CT-11 multi-region trail logging | 4.1 | Manual | AU-12 | A.8.15 | CC7.2 | A trail that records management events in every region is the account's activity history. Each `aws_cloudtrail` must have `is_multi_region_trail = true`, `enable_logging = true`, and record all management events (reads and writes); with no event selector at all, AWS records all management events by default, so that passes. **Differs from Project 1:** each trail is judged on its own (Project 1 passes if any one trail is good), and a plan with no trail has nothing to judge (Project 1 fails an account with no trail). |
| CT-12 log file validation | 4.2 | Automated | AU-9 | A.8.15 | CC7.2 | Log file validation signs a fingerprint of each log file, so tampering or deletion can be detected. This protects the integrity of the audit record. Each trail needs `enable_log_file_validation = true`. |
| CT-13 trail logs encrypted with KMS | 4.5 | Automated | SC-28 | A.8.24 | CC6.1 | Encrypting trail logs with a KMS key means reading them also needs permission on the key, not only on the bucket. Each trail needs a `kms_key_id`, either written out or pointing at a key in the same code. A variable that turns out empty fails. |
| KMS-19 key rotation | 4.6 | Automated | SC-12 | A.8.24 | CC6.1 | Rotating a key limits how much data a leaked key can unlock. Judged on `aws_kms_key` resources that can rotate: symmetric, enabled, and with key material created by AWS. Asymmetric, disabled and imported-material keys are NOT_APPLICABLE. A missing `enable_key_rotation` fails. |
| IAM-06 no full-admin wildcard policy | 2.14 | Automated | AC-6 | A.8.2 | CC6.3 | A policy that allows every action on every resource ignores least privilege. Judges the policy text of `aws_iam_policy` and of the inline policies of roles, users and groups: an `Allow` statement with `*` as an action and `*` as a resource fails; a `Deny` statement is not admin. It also fails any attachment of the AWS managed `AdministratorAccess` policy written out in full. **Differs from Project 1:** Project 1 judges attached managed policies only; here every policy in the code is judged, attached or not, plus inline policies. A policy whose text cannot be read at plan time fails. |

## How Checkov compares (checked on the example folders and small test cases)

| Rule | Checkov check | Relation | What I observed |
|------|---------------|----------|-----------------|
| S3-07 | CKV2_AWS_6 | weaker | Only checks that a public access block is attached. It passed a block with `restrict_public_buckets = false`. |
| S3-08 | CKV_AWS_145 | stricter | Requires a KMS key. It failed the secure example, which uses `AES256`. |
| S3-09 | CKV_AWS_21 | same | Agreed on both example folders. |
| S3-10 | CKV_AWS_18 | same | Agreed on both example folders, including the log bucket. |
| VPC-15 | CKV2_AWS_11 | weaker | Passed a flow log that records only `ACCEPT` traffic. |
| VPC-17 | CKV_AWS_24 | same | Agreed on IPv6, port ranges, all-protocol rules and all three rule forms. |
| VPC-18 | CKV_AWS_25 | same | Agreed on inline rules, port ranges and all-protocol rules. IPv6 and the standalone rule forms were only tried for SSH. |
| CT-11 | CKV_AWS_67 | weaker | Only checks the trail is multi-region. It passed a trail with logging off and a trail with read-only events. |
| CT-12 | CKV_AWS_36 | same | Agreed on both example folders. |
| CT-13 | CKV_AWS_35 | same | Agreed on both example folders. |
| KMS-19 | CKV_AWS_7 | same | Agreed on both example folders; it also skips asymmetric keys. |
| IAM-06 | CKV_AWS_62 | partial | Judges policy text (it flagged a list-style `*` policy). It does not judge attachments of `AdministratorAccess`. |
