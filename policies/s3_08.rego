package s3_08

import rego.v1

# S3-08: every S3 bucket must have default encryption declared.
# We accept S3-managed keys (AES256) or a KMS key (aws:kms).

# The algorithms we accept.
allowed_algorithms := {"AES256", "aws:kms"}

# Step 1: collect every bucket that the plan will create or change.
buckets contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	resource.change.actions != ["delete"]
}

# Step 2: find the encryption resources that point at this bucket.
# The link is only visible in the "configuration" part of the plan.
encryption_for(bucket_address) := {e.address |
	some e in input.configuration.root_module.resources
	e.type == "aws_s3_bucket_server_side_encryption_configuration"
	bucket_address in e.expressions.bucket.references
}

# Step 3: does this encryption resource really name an accepted algorithm?
# If the rule or the algorithm is missing, this is undefined (counts as "no").
is_encrypted(encryption_address) if {
	some resource in input.resource_changes
	resource.address == encryption_address
	some enc_rule in resource.change.after.rule
	some setting in enc_rule.apply_server_side_encryption_by_default
	setting.sse_algorithm in allowed_algorithms
}

# Step 4: a bucket is protected if at least one linked encryption resource is valid.
protected(bucket_address) if {
	some encryption_address in encryption_for(bucket_address)
	is_encrypted(encryption_address)
}

# Step 5: complain about every bucket that is not protected.
deny contains msg if {
	some bucket in buckets
	not protected(bucket.address)
	msg := sprintf("S3-08: %s needs default encryption (AES256 or aws:kms)", [bucket.address])
}
