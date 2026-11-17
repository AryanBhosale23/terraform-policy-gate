package vpc_15_test

import rego.v1

import data.vpc_15

vpc(name) := {
	"address": sprintf("aws_vpc.%s", [name]),
	"type": "aws_vpc",
	"change": {"actions": ["create"], "after": {}},
}

# A flow log resource with the given traffic type (null means the value is missing).
flow_log(traffic_type) := {
	"address": "aws_flow_log.f",
	"type": "aws_flow_log",
	"change": {"actions": ["create"], "after": {"traffic_type": traffic_type}},
}

# The link from the flow log to a VPC, as in the "configuration" part of the plan.
config_linked_to(name) := {"root_module": {"resources": [{
	"address": "aws_flow_log.f",
	"type": "aws_flow_log",
	"expressions": {"vpc_id": {"references": [
		sprintf("aws_vpc.%s.id", [name]),
		sprintf("aws_vpc.%s", [name]),
	]}},
}]}}

config_without_flow_log := {"root_module": {"resources": []}}

test_vpc_without_flow_log_is_denied if {
	plan := {"resource_changes": [vpc("main")], "configuration": config_without_flow_log}
	count(vpc_15.deny) == 1 with input as plan
}

test_vpc_with_all_traffic_flow_log_is_allowed if {
	plan := {"resource_changes": [vpc("main"), flow_log("ALL")], "configuration": config_linked_to("main")}
	count(vpc_15.deny) == 0 with input as plan
}

test_vpc_with_reject_traffic_flow_log_is_allowed if {
	plan := {"resource_changes": [vpc("main"), flow_log("REJECT")], "configuration": config_linked_to("main")}
	count(vpc_15.deny) == 0 with input as plan
}

# ACCEPT-only logs miss the rejected connections, which are the interesting ones.
test_vpc_with_accept_only_flow_log_is_denied if {
	plan := {"resource_changes": [vpc("main"), flow_log("ACCEPT")], "configuration": config_linked_to("main")}
	count(vpc_15.deny) == 1 with input as plan
}

# Flow log with no traffic type: no data must not pass.
test_flow_log_without_traffic_type_is_denied if {
	plan := {"resource_changes": [vpc("main"), flow_log(null)], "configuration": config_linked_to("main")}
	count(vpc_15.deny) == 1 with input as plan
}

# A flow log for VPC "a" does not protect VPC "b".
test_flow_log_for_another_vpc_does_not_protect if {
	plan := {"resource_changes": [vpc("a"), vpc("b"), flow_log("ALL")], "configuration": config_linked_to("a")}
	count(vpc_15.deny) == 1 with input as plan
}
