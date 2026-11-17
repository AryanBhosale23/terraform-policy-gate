package s3_07_test

import rego.v1

import data.s3_07

# A bucket, as it appears in the "resource_changes" part of a plan.
bucket := {
	"address": "aws_s3_bucket.b",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}},
}

# A public access block with the four switches. restrict_on is the fourth switch.
block(restrict_on) := {
	"address": "aws_s3_public_access_block.b",
	"type": "aws_s3_bucket_public_access_block",
	"change": {
		"actions": ["create"],
		"after": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": restrict_on,
		},
	},
}

# The link from the block to its bucket, as it appears in the "configuration" part.
config_with_link := {"root_module": {"resources": [{
	"address": "aws_s3_public_access_block.b",
	"type": "aws_s3_bucket_public_access_block",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
}]}}

config_without_link := {"root_module": {"resources": []}}

# A bucket with no public access block at all must be denied.
test_bucket_without_block_is_denied if {
	plan := {"resource_changes": [bucket], "configuration": config_without_link}
	count(s3_07.deny) == 1 with input as plan
}

# A bucket with a block that has all four switches on is fine.
test_bucket_with_all_four_on_is_allowed if {
	plan := {"resource_changes": [bucket, block(true)], "configuration": config_with_link}
	count(s3_07.deny) == 0 with input as plan
}

# A bucket whose block has one switch off must be denied.
test_bucket_with_one_switch_off_is_denied if {
	plan := {"resource_changes": [bucket, block(false)], "configuration": config_with_link}
	count(s3_07.deny) == 1 with input as plan
}
