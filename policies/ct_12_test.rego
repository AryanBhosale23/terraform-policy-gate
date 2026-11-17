package ct_12_test

import rego.v1

import data.ct_12

trail(after) := {
	"address": "aws_cloudtrail.main",
	"type": "aws_cloudtrail",
	"change": {"actions": ["create"], "after": after},
}

test_validation_on_is_allowed if {
	plan := {"resource_changes": [trail({"enable_log_file_validation": true})]}
	count(ct_12.deny) == 0 with input as plan
}

test_validation_off_is_denied if {
	plan := {"resource_changes": [trail({"enable_log_file_validation": false})]}
	count(ct_12.deny) == 1 with input as plan
}

# No value at all: no data must not pass.
test_validation_missing_is_denied if {
	plan := {"resource_changes": [trail({})]}
	count(ct_12.deny) == 1 with input as plan
}

# A trail that is being deleted is not judged.
test_deleted_trail_is_ignored if {
	deleted := {
		"address": "aws_cloudtrail.old",
		"type": "aws_cloudtrail",
		"change": {"actions": ["delete"], "after": null},
	}
	plan := {"resource_changes": [deleted]}
	count(ct_12.deny) == 0 with input as plan
}
