package s3_09

import rego.v1

# S3-09: every S3 bucket must have versioning turned on.
# Versioning keeps old copies of a file when it is overwritten or deleted.

# Step 1: collect every bucket that the plan will create or change.
# (A bucket that is being deleted does not need versioning.)
buckets contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	resource.change.actions != ["delete"]
}

# Step 2: find the versioning resources that point at this bucket.
# The link is only visible in the "configuration" part of the plan.
versioning_for(bucket_address) := {v.address |
	some v in input.configuration.root_module.resources
	v.type == "aws_s3_bucket_versioning"
	bucket_address in v.expressions.bucket.references
}

# Step 3: is this versioning resource really switched on?
# It must have a versioning_configuration with status "Enabled".
# If the status is missing or anything else, this is undefined (counts as "no").
is_enabled(versioning_address) if {
	some resource in input.resource_changes
	resource.address == versioning_address
	some cfg in resource.change.after.versioning_configuration
	cfg.status == "Enabled"
}

# Step 4: a bucket is protected if at least one linked versioning resource is enabled.
protected(bucket_address) if {
	some versioning_address in versioning_for(bucket_address)
	is_enabled(versioning_address)
}

# Step 5: complain about every bucket that is not protected.
deny contains msg if {
	some bucket in buckets
	not protected(bucket.address)
	msg := sprintf("S3-09: %s needs a versioning resource with status Enabled", [bucket.address])
}

# The resources this rule judged (used for the evidence records).
scope contains bucket.address if {
	some bucket in buckets
}
