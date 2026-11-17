package s3_07

import rego.v1

# S3-07: every S3 bucket must have a public access block with all four switches on.

# Every bucket the plan will create or change. Buckets being deleted are ignored.
buckets contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	resource.change.actions != ["delete"]
}

# The addresses of the public access blocks that are linked to one bucket.
blocks_for(bucket_address) := {block.address |
	some block in input.configuration.root_module.resources
	block.type == "aws_s3_bucket_public_access_block"
	bucket_address in block.expressions.bucket.references
}

# True when the block at this address has all four switches on.
all_four_on(block_address) if {
	some resource in input.resource_changes
	resource.address == block_address
	resource.change.after.block_public_acls == true
	resource.change.after.block_public_policy == true
	resource.change.after.ignore_public_acls == true
	resource.change.after.restrict_public_buckets == true
}

# True when at least one block linked to the bucket has all four switches on.
protected(bucket_address) if {
	some block_address in blocks_for(bucket_address)
	all_four_on(block_address)
}

# One complaint for every bucket that is not protected.
deny contains msg if {
	some bucket in buckets
	not protected(bucket.address)
	msg := sprintf("S3-07: %s needs a public access block with all four settings on", [bucket.address])
}

# The resources this rule judged (used for the evidence records).
scope contains bucket.address if {
	some bucket in buckets
}
