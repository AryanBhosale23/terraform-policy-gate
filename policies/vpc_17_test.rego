package vpc_17_test

import rego.v1

import data.vpc_17

# ---------- fake pieces of a plan ----------

# One inline ingress rule, as found inside an aws_security_group.
ingress(from, to, protocol, cidrs) := {
	"from_port": from,
	"to_port": to,
	"protocol": protocol,
	"cidr_blocks": cidrs,
	"ipv6_cidr_blocks": [],
}

# The same, but the address list is IPv6.
ingress_v6(from, to, protocol, cidrs) := {
	"from_port": from,
	"to_port": to,
	"protocol": protocol,
	"cidr_blocks": [],
	"ipv6_cidr_blocks": cidrs,
}

# A security group holding a list of inline ingress rules.
sg(rules) := {
	"address": "aws_security_group.web",
	"type": "aws_security_group",
	"change": {"actions": ["create"], "after": {"ingress": rules}},
}

# A standalone rule, modern style (aws_vpc_security_group_ingress_rule).
modern_rule(from, to, protocol, cidr) := {
	"address": "aws_vpc_security_group_ingress_rule.r",
	"type": "aws_vpc_security_group_ingress_rule",
	"change": {"actions": ["create"], "after": {
		"from_port": from,
		"to_port": to,
		"ip_protocol": protocol,
		"cidr_ipv4": cidr,
		"cidr_ipv6": null,
	}},
}

# A standalone rule, old style (aws_security_group_rule). Its "kind" is ingress or egress.
old_rule(kind, from, to, protocol, cidrs) := {
	"address": "aws_security_group_rule.r",
	"type": "aws_security_group_rule",
	"change": {"actions": ["create"], "after": {
		"type": kind,
		"from_port": from,
		"to_port": to,
		"protocol": protocol,
		"cidr_blocks": cidrs,
		"ipv6_cidr_blocks": null,
	}},
}

world := ["0.0.0.0/0"]

# ---------- inline rules ----------

test_inline_ssh_open_to_world_is_denied if {
	plan := {"resource_changes": [sg([ingress(22, 22, "tcp", world)])]}
	count(vpc_17.deny) == 1 with input as plan
}

test_inline_ssh_from_private_range_is_allowed if {
	plan := {"resource_changes": [sg([ingress(22, 22, "tcp", ["10.0.0.0/8"])])]}
	count(vpc_17.deny) == 0 with input as plan
}

# Web traffic (443) open to the world is normal and is NOT this rule's business.
test_inline_https_open_to_world_is_allowed if {
	plan := {"resource_changes": [sg([ingress(443, 443, "tcp", world)])]}
	count(vpc_17.deny) == 0 with input as plan
}

# Ports 0 to 65535 include port 22.
test_inline_full_port_range_open_to_world_is_denied if {
	plan := {"resource_changes": [sg([ingress(0, 65535, "tcp", world)])]}
	count(vpc_17.deny) == 1 with input as plan
}

# Protocol "-1" means every protocol and every port.
test_inline_all_protocols_open_to_world_is_denied if {
	plan := {"resource_changes": [sg([ingress(0, 0, "-1", world)])]}
	count(vpc_17.deny) == 1 with input as plan
}

test_inline_ssh_open_to_ipv6_world_is_denied if {
	plan := {"resource_changes": [sg([ingress_v6(22, 22, "tcp", ["::/0"])])]}
	count(vpc_17.deny) == 1 with input as plan
}

# Open to the world but the ports are missing: no data must not pass.
test_inline_world_without_ports_is_denied if {
	plan := {"resource_changes": [sg([ingress(null, null, "tcp", world)])]}
	count(vpc_17.deny) == 1 with input as plan
}

# ---------- standalone rules ----------

test_modern_rule_ssh_open_to_world_is_denied if {
	plan := {"resource_changes": [modern_rule(22, 22, "tcp", "0.0.0.0/0")]}
	count(vpc_17.deny) == 1 with input as plan
}

test_old_rule_ssh_open_to_world_is_denied if {
	plan := {"resource_changes": [old_rule("ingress", 22, 22, "tcp", world)]}
	count(vpc_17.deny) == 1 with input as plan
}

# An egress rule is about traffic going OUT, so it is not this rule's business.
test_old_rule_egress_is_allowed if {
	plan := {"resource_changes": [old_rule("egress", 22, 22, "tcp", world)]}
	count(vpc_17.deny) == 0 with input as plan
}
