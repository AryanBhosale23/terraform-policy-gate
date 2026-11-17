package ct_13

import rego.v1

# CT-13: every CloudTrail trail must encrypt its logs with a KMS key.

trails contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	resource.change.actions != ["delete"]
}

# Case 1: the key is written directly in the code as a non-empty text.
kms_set(trail) if {
	is_string(trail.change.after.kms_key_id)
	trail.change.after.kms_key_id != ""
}

# Case 2: the key is another resource (for example aws_kms_key.trail.arn), so its value
# is unknown until apply. Then we look at the code: the trail must point at something.
kms_set(trail) if {
	trail.change.after_unknown.kms_key_id == true
	some resource in input.configuration.root_module.resources
	resource.address == trail.address
	count(resource.expressions.kms_key_id.references) > 0
}

scope contains trail.address if {
	some trail in trails
}

deny contains msg if {
	some trail in trails
	not kms_set(trail)
	msg := sprintf("CT-13: %s needs kms_key_id so its logs are encrypted with KMS", [trail.address])
}
