package s3_10_test

import rego.v1

import data.s3_10

# The bucket we are checking, as it appears in "resource_changes".
bucket_b := {
	"address": "aws_s3_bucket.b",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}},
}

# A second bucket that receives the logs (the "diary" bucket).
bucket_logs := {
	"address": "aws_s3_bucket.logs",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}},
}

# The logging resource itself, as it appears in "resource_changes".
logging_resource := {
	"address": "aws_s3_bucket_logging.b",
	"type": "aws_s3_bucket_logging",
	"change": {"actions": ["create"], "after": {"target_prefix": "log/"}},
}

# The links, as they appear in "configuration": watches bucket b, writes to bucket logs.
config_with_target := {"root_module": {"resources": [{
	"address": "aws_s3_bucket_logging.b",
	"type": "aws_s3_bucket_logging",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]},
		"target_bucket": {"references": ["aws_s3_bucket.logs.id", "aws_s3_bucket.logs"]},
	},
}]}}

# Same, but the logging resource has no target_bucket at all.
config_without_target := {"root_module": {"resources": [{
	"address": "aws_s3_bucket_logging.b",
	"type": "aws_s3_bucket_logging",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
}]}}

config_without_logging := {"root_module": {"resources": []}}

# One bucket and no logging at all must be denied.
test_bucket_without_logging_is_denied if {
	plan := {"resource_changes": [bucket_b], "configuration": config_without_logging}
	count(s3_10.deny) == 1 with input as plan
}

# Bucket b logs into bucket logs. Bucket b is fine, and the log bucket is exempt.
test_bucket_with_logging_and_log_bucket_is_allowed if {
	plan := {"resource_changes": [bucket_b, bucket_logs, logging_resource], "configuration": config_with_target}
	count(s3_10.deny) == 0 with input as plan
}

# A logging resource with no target_bucket: no data must not pass.
test_logging_without_target_is_denied if {
	plan := {"resource_changes": [bucket_b, logging_resource], "configuration": config_without_target}
	count(s3_10.deny) == 1 with input as plan
}

# Two buckets and no logging: nobody is a log destination, so nobody is exempt.
test_two_buckets_without_logging_are_both_denied if {
	plan := {"resource_changes": [bucket_b, bucket_logs], "configuration": config_without_logging}
	count(s3_10.deny) == 2 with input as plan
}
