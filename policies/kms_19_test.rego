package kms_19_test

import rego.v1

import data.kms_19

key(after) := {
	"address": "aws_kms_key.k",
	"type": "aws_kms_key",
	"change": {"actions": ["create"], "after": after},
}

test_key_with_rotation_is_allowed if {
	plan := {"resource_changes": [key({"enable_key_rotation": true, "customer_master_key_spec": "SYMMETRIC_DEFAULT"})]}
	count(kms_19.deny) == 0 with input as plan
}

test_key_without_rotation_is_denied if {
	plan := {"resource_changes": [key({"enable_key_rotation": false, "customer_master_key_spec": "SYMMETRIC_DEFAULT"})]}
	count(kms_19.deny) == 1 with input as plan
}

# The rotation value is missing: no data must not pass.
test_key_with_missing_rotation_value_is_denied if {
	plan := {"resource_changes": [key({})]}
	count(kms_19.deny) == 1 with input as plan
}

# Asymmetric keys cannot rotate automatically, so they are not judged.
test_asymmetric_key_is_not_judged if {
	plan := {"resource_changes": [key({"enable_key_rotation": false, "customer_master_key_spec": "RSA_2048"})]}
	count(kms_19.deny) == 0 with input as plan
}

# A disabled key is not judged (same as the scanner in Project 1).
test_disabled_key_is_not_judged if {
	plan := {"resource_changes": [key({"enable_key_rotation": false, "is_enabled": false})]}
	count(kms_19.deny) == 0 with input as plan
}

# Imported key material cannot rotate automatically, so it is not judged.
test_external_key_material_is_not_judged if {
	plan := {"resource_changes": [key({"enable_key_rotation": false, "origin": "EXTERNAL"})]}
	count(kms_19.deny) == 0 with input as plan
}
