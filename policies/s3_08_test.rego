package s3_08_test

import rego.v1

import data.s3_08

# A bucket, as it appears in the "resource_changes" part of a plan.
bucket := {
	"address": "aws_s3_bucket.b",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}},
}

# An encryption resource that uses the given algorithm, for example "AES256".
encryption(algorithm) := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.b",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {
		"actions": ["create"],
		"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": algorithm}]}]},
	},
}

# An encryption resource that has no rule at all.
encryption_without_rule := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.b",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"actions": ["create"], "after": {"rule": []}},
}

# The link from the encryption resource to its bucket, as in the "configuration" part.
config_with_link := {"root_module": {"resources": [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.b",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
}]}}

config_without_link := {"root_module": {"resources": []}}

# A bucket with no encryption resource at all must be denied.
test_bucket_without_encryption_is_denied if {
	plan := {"resource_changes": [bucket], "configuration": config_without_link}
	count(s3_08.deny) == 1 with input as plan
}

# A bucket encrypted with AES256 is fine.
test_bucket_with_aes256_is_allowed if {
	plan := {"resource_changes": [bucket, encryption("AES256")], "configuration": config_with_link}
	count(s3_08.deny) == 0 with input as plan
}

# A bucket encrypted with a KMS key is fine too.
test_bucket_with_kms_is_allowed if {
	plan := {"resource_changes": [bucket, encryption("aws:kms")], "configuration": config_with_link}
	count(s3_08.deny) == 0 with input as plan
}

# An encryption resource with no rule: no data must not pass.
test_encryption_without_rule_is_denied if {
	plan := {"resource_changes": [bucket, encryption_without_rule], "configuration": config_with_link}
	count(s3_08.deny) == 1 with input as plan
}
