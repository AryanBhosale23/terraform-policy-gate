package kms_19

import rego.v1

# KMS-19: customer-managed KMS keys must have automatic rotation turned on.
# Only keys that can rotate are judged: enabled, symmetric keys that AWS creates the key material for.
# Anything the plan does not clearly rule out is judged (missing data must not pass).

not_symmetric(after) if {
	is_string(after.customer_master_key_spec)
	after.customer_master_key_spec != "SYMMETRIC_DEFAULT"
}

disabled(after) if {
	after.is_enabled == false
}

external_material(after) if {
	is_string(after.origin)
	after.origin != "AWS_KMS"
}

keys contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_kms_key"
	resource.change.actions != ["delete"]
	not not_symmetric(resource.change.after)
	not disabled(resource.change.after)
	not external_material(resource.change.after)
}

# If the value is missing, this is undefined (counts as "no").
rotation_on(key) if {
	key.change.after.enable_key_rotation == true
}

scope contains key.address if {
	some key in keys
}

deny contains msg if {
	some key in keys
	not rotation_on(key)
	msg := sprintf("KMS-19: %s needs enable_key_rotation = true", [key.address])
}
