package ct_12

import rego.v1

# CT-12: every CloudTrail trail must have log file validation turned on.
# Validation signs each log file, so tampering or deletion can be detected.

trails contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	resource.change.actions != ["delete"]
}

# If the value is missing, this is undefined (counts as "no").
validation_on(trail) if {
	trail.change.after.enable_log_file_validation == true
}

scope contains trail.address if {
	some trail in trails
}

deny contains msg if {
	some trail in trails
	not validation_on(trail)
	msg := sprintf("CT-12: %s needs enable_log_file_validation = true", [trail.address])
}
