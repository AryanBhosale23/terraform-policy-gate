package vpc_18_test

import rego.v1

import data.vpc_18

# ---------- fake pieces of a plan ----------

ingress(from, to, protocol, cidrs) := {
	"from_port": from,
	"to_port": to,
	"protocol": protocol,
	"cidr_blocks": cidrs,
	"ipv6_cidr_blocks": [],
}

sg(rules) := {
	"address": "aws_security_group.windows",
	"type": "aws_security_group",
	"change": {"actions": ["create"], "after": {"ingress": rules}},
}

modern_rule(from, to, protocol, cidr) := {
	"address": "aws_vpc_security_group_ingress_rule.rdp",
	"type": "aws_vpc_security_group_ingress_rule",
	"change": {"actions": ["create"], "after": {
		"from_port": from,
		"to_port": to,
		"ip_protocol": protocol,
		"cidr_ipv4": cidr,
		"cidr_ipv6": null,
	}},
}

world := ["0.0.0.0/0"]

# ---------- tests ----------

# RDP (3389) open to the whole internet must be denied.
test_rdp_open_to_world_is_denied if {
	plan := {"resource_changes": [sg([ingress(3389, 3389, "tcp", world)])]}
	count(vpc_18.deny) == 1 with input as plan
}

# RDP only from the private network is fine.
test_rdp_from_private_range_is_allowed if {
	plan := {"resource_changes": [sg([ingress(3389, 3389, "tcp", ["10.0.0.0/8"])])]}
	count(vpc_18.deny) == 0 with input as plan
}

# SSH (22) open to the world is VPC-17's business, not this rule's.
test_ssh_open_to_world_is_not_this_rules_business if {
	plan := {"resource_changes": [sg([ingress(22, 22, "tcp", world)])]}
	count(vpc_18.deny) == 0 with input as plan
}

# Ports 3000 to 4000 include 3389.
test_range_covering_rdp_is_denied if {
	plan := {"resource_changes": [sg([ingress(3000, 4000, "tcp", world)])]}
	count(vpc_18.deny) == 1 with input as plan
}

# The modern standalone rule form is caught too.
test_modern_rule_rdp_open_to_world_is_denied if {
	plan := {"resource_changes": [modern_rule(3389, 3389, "tcp", "0.0.0.0/0")]}
	count(vpc_18.deny) == 1 with input as plan
}
