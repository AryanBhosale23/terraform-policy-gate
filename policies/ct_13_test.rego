package ct_13_test

import rego.v1

import data.ct_13

trail(after, after_unknown) := {
	"address": "aws_cloudtrail.main",
	"type": "aws_cloudtrail",
	"change": {"actions": ["create"], "after": after, "after_unknown": after_unknown},
}

# The "configuration" part of the plan for the trail, with the given kms_key_id expression.
config_with(expression) := {"root_module": {"resources": [{
	"address": "aws_cloudtrail.main",
	"type": "aws_cloudtrail",
	"expressions": {"kms_key_id": expression},
}]}}

config_without_kms := {"root_module": {"resources": [{
	"address": "aws_cloudtrail.main",
	"type": "aws_cloudtrail",
	"expressions": {},
}]}}

test_literal_kms_key_is_allowed if {
	plan := {"resource_changes": [trail({"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc"}, {})], "configuration": config_without_kms}
	count(ct_13.deny) == 0 with input as plan
}

# The key is another resource in the same plan, so its value is unknown until apply.
test_key_from_another_resource_is_allowed if {
	plan := {
		"resource_changes": [trail({}, {"kms_key_id": true})],
		"configuration": config_with({"references": ["aws_kms_key.trail.arn", "aws_kms_key.trail"]}),
	}
	count(ct_13.deny) == 0 with input as plan
}

test_no_kms_key_is_denied if {
	plan := {"resource_changes": [trail({"kms_key_id": null}, {})], "configuration": config_without_kms}
	count(ct_13.deny) == 1 with input as plan
}

test_empty_kms_key_is_denied if {
	plan := {"resource_changes": [trail({"kms_key_id": ""}, {})], "configuration": config_without_kms}
	count(ct_13.deny) == 1 with input as plan
}

# Unknown value and nothing in the code points at a key: no data must not pass.
test_unknown_key_without_reference_is_denied if {
	plan := {"resource_changes": [trail({}, {"kms_key_id": true})], "configuration": config_without_kms}
	count(ct_13.deny) == 1 with input as plan
}

# The code points at a variable, but the variable's value is known and empty.
test_variable_that_is_empty_is_denied if {
	plan := {
		"resource_changes": [trail({"kms_key_id": ""}, {"kms_key_id": false})],
		"configuration": config_with({"references": ["var.kms_key"]}),
	}
	count(ct_13.deny) == 1 with input as plan
}
