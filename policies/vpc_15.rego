package vpc_15

import rego.v1

# VPC-15: every VPC must have a flow log that records rejected traffic.
# A flow log is a diary of network connections. We accept traffic type REJECT or ALL.

allowed_traffic_types := {"REJECT", "ALL"}

# Step 1: collect every VPC that the plan will create or change.
vpcs contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_vpc"
	resource.change.actions != ["delete"]
}

# Step 2: find the flow logs that point at this VPC (the link is in "configuration").
flow_logs_for(vpc_address) := {l.address |
	some l in input.configuration.root_module.resources
	l.type == "aws_flow_log"
	vpc_address in l.expressions.vpc_id.references
}

# Step 3: is this flow log part of the plan and does it record an accepted traffic type?
# If traffic_type is missing, this is undefined (counts as "no").
is_good(flow_log_address) if {
	some resource in input.resource_changes
	resource.address == flow_log_address
	resource.change.actions != ["delete"]
	resource.change.after.traffic_type in allowed_traffic_types
}

protected(vpc_address) if {
	some flow_log_address in flow_logs_for(vpc_address)
	is_good(flow_log_address)
}

# The resources this rule judged (used for the evidence records).
scope contains vpc.address if {
	some vpc in vpcs
}

deny contains msg if {
	some vpc in vpcs
	not protected(vpc.address)
	msg := sprintf("VPC-15: %s needs a flow log with traffic type REJECT or ALL", [vpc.address])
}
