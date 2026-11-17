package s3_10

import rego.v1

# S3-10: every S3 bucket must write an access log (a "diary") into a log bucket.
# Exception: a bucket that IS someone's log destination does not need its own logging,
# otherwise we would demand a diary for the diary, forever.

# Step 1: collect every bucket that the plan will create or change.
buckets contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	resource.change.actions != ["delete"]
}

# Step 2: collect every logging resource written in the code.
logging_resources contains l if {
	some l in input.configuration.root_module.resources
	l.type == "aws_s3_bucket_logging"
}

# Step 3: collect the names of buckets that receive logs (the "diary" buckets).
log_destinations contains name if {
	some l in logging_resources
	some name in l.expressions.target_bucket.references
}

# Step 4: find the logging resources that watch this bucket AND say where to write.
# If target_bucket is missing, the resource is skipped (counts as "no").
logging_for(bucket_address) := {l.address |
	some l in logging_resources
	bucket_address in l.expressions.bucket.references
	l.expressions.target_bucket
}

# Step 5: is the logging resource really part of the plan (not being deleted)?
is_logging(logging_address) if {
	some resource in input.resource_changes
	resource.address == logging_address
	resource.change.actions != ["delete"]
}

logged(bucket_address) if {
	some logging_address in logging_for(bucket_address)
	is_logging(logging_address)
}

# Step 6: complain about every bucket that is neither exempt nor logged.
deny contains msg if {
	some bucket in buckets
	not bucket.address in log_destinations
	not logged(bucket.address)
	msg := sprintf("S3-10: %s needs access logging to a log bucket", [bucket.address])
}

# The resources this rule judged (used for the evidence records).
# A bucket that receives logs is exempt, so it is not in scope.
scope contains bucket.address if {
	some bucket in buckets
	not bucket.address in log_destinations
}
