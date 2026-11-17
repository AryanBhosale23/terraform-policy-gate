package s3_09_test

import rego.v1

import data.s3_09

# A bucket, as it appears in the "resource_changes" part of a plan.
bucket := {
	"address": "aws_s3_bucket.b",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}},
}

# A versioning resource with a given status, for example "Enabled".
versioning(status) := {
	"address": "aws_s3_bucket_versioning.b",
	"type": "aws_s3_bucket_versioning",
	"change": {
		"actions": ["create"],
		"after": {"versioning_configuration": [{"status": status}]},
	},
}

# A versioning resource that has no versioning_configuration at all.
versioning_without_status := {
	"address": "aws_s3_bucket_versioning.b",
	"type": "aws_s3_bucket_versioning",
	"change": {"actions": ["create"], "after": {"versioning_configuration": []}},
}

# The link from the versioning resource to its bucket, as in the "configuration" part.
config_with_link := {"root_module": {"resources": [{
	"address": "aws_s3_bucket_versioning.b",
	"type": "aws_s3_bucket_versioning",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
}]}}

config_without_link := {"root_module": {"resources": []}}

# A bucket with no versioning resource at all must be denied.
test_bucket_without_versioning_is_denied if {
	plan := {"resource_changes": [bucket], "configuration": config_without_link}
	count(s3_09.deny) == 1 with input as plan
}

# A bucket with versioning Enabled is fine.
test_bucket_with_versioning_enabled_is_allowed if {
	plan := {"resource_changes": [bucket, versioning("Enabled")], "configuration": config_with_link}
	count(s3_09.deny) == 0 with input as plan
}

# A bucket whose versioning is Suspended must be denied.
test_bucket_with_versioning_suspended_is_denied if {
	plan := {"resource_changes": [bucket, versioning("Suspended")], "configuration": config_with_link}
	count(s3_09.deny) == 1 with input as plan
}

# A versioning resource with no status: no data must not pass.
test_versioning_without_status_is_denied if {
	plan := {"resource_changes": [bucket, versioning_without_status], "configuration": config_with_link}
	count(s3_09.deny) == 1 with input as plan
}
