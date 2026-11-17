package iam_06_test

import rego.v1

import data.iam_06

# Build the policy text from a list of statements.
doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

policy(type, text) := {
	"address": sprintf("%s.p", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": {"policy": text}},
}

attachment(arn) := {
	"address": "aws_iam_role_policy_attachment.a",
	"type": "aws_iam_role_policy_attachment",
	"change": {"actions": ["create"], "after": {"policy_arn": arn}},
}

admin_statement := {"Effect": "Allow", "Action": "*", "Resource": "*"}

test_managed_policy_with_allow_everything_is_denied if {
	plan := {"resource_changes": [policy("aws_iam_policy", doc([admin_statement]))]}
	count(iam_06.deny) == 1 with input as plan
}

# Action and Resource as lists.
test_admin_written_as_lists_is_denied if {
	statement := {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
	plan := {"resource_changes": [policy("aws_iam_policy", doc([statement]))]}
	count(iam_06.deny) == 1 with input as plan
}

# Statement written as one object instead of a list.
test_admin_with_single_statement_object_is_denied if {
	plan := {"resource_changes": [policy("aws_iam_policy", doc(admin_statement))]}
	count(iam_06.deny) == 1 with input as plan
}

test_narrow_policy_is_allowed if {
	statement := {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*"]}
	plan := {"resource_changes": [policy("aws_iam_policy", doc([statement]))]}
	count(iam_06.deny) == 0 with input as plan
}

# All actions but on one resource is not full admin.
test_all_actions_on_one_resource_is_allowed if {
	statement := {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}
	plan := {"resource_changes": [policy("aws_iam_policy", doc([statement]))]}
	count(iam_06.deny) == 0 with input as plan
}

# A Deny statement is not admin.
test_deny_everything_is_allowed if {
	statement := {"Effect": "Deny", "Action": "*", "Resource": "*"}
	plan := {"resource_changes": [policy("aws_iam_policy", doc([statement]))]}
	count(iam_06.deny) == 0 with input as plan
}

test_inline_role_policy_with_admin_is_denied if {
	plan := {"resource_changes": [policy("aws_iam_role_policy", doc([admin_statement]))]}
	count(iam_06.deny) == 1 with input as plan
}

test_attaching_administrator_access_is_denied if {
	plan := {"resource_changes": [attachment("arn:aws:iam::aws:policy/AdministratorAccess")]}
	count(iam_06.deny) == 1 with input as plan
}

test_attaching_read_only_access_is_allowed if {
	plan := {"resource_changes": [attachment("arn:aws:iam::aws:policy/ReadOnlyAccess")]}
	count(iam_06.deny) == 0 with input as plan
}

# The policy text is not known at plan time: no data must not pass.
test_unreadable_policy_is_denied if {
	unknown := {
		"address": "aws_iam_policy.p",
		"type": "aws_iam_policy",
		"change": {"actions": ["create"], "after": {}},
	}
	plan := {"resource_changes": [unknown]}
	count(iam_06.deny) == 1 with input as plan
}

test_invalid_json_policy_is_denied if {
	plan := {"resource_changes": [policy("aws_iam_policy", "{not json")]}
	count(iam_06.deny) == 1 with input as plan
}
