package open_ports

import rego.v1

# Shared helper for the rules that say "port N must not be open to the whole internet".
# VPC-17 uses it for port 22 (SSH), VPC-18 for port 3389 (RDP).
# The main entry point is violating(port): the addresses of every resource that opens that port.

# The addresses that mean "the whole internet".
world_cidrs := {"0.0.0.0/0", "::/0"}

# Look only at resources that are not being deleted.
live contains r if {
	some r in input.resource_changes
	r.change.actions != ["delete"]
}

# Does an address list contain a "whole internet" address?
# If the list is missing or empty, this is undefined (counts as "no").
is_world(cidrs) if {
	some cidr in cidrs
	cidr in world_cidrs
}

# Does the range from..to include the port?
# If either end is missing, we cannot tell, so we say "yes" (no data must not pass).
covers(from, _, _) if {
	not is_number(from)
}

covers(_, to, _) if {
	not is_number(to)
}

covers(from, to, port) if {
	from <= port
	port <= to
}

# Does a rule with this protocol and port range expose the port?
# "-1" means every protocol and every port. TCP (written "tcp", "TCP" or "6") needs the range to include the port.
exposes(protocol, _, _, _) if {
	protocol == "-1"
}

exposes(protocol, from, to, port) if {
	is_string(protocol)
	lower(protocol) in {"tcp", "6"}
	covers(from, to, port)
}

# Inline rules inside aws_security_group, IPv4 addresses.
inline_v4(port) := {r.address |
	some r in live
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	is_world(object.get(rule, "cidr_blocks", []))
	exposes(object.get(rule, "protocol", null), object.get(rule, "from_port", null), object.get(rule, "to_port", null), port)
}

# Inline rules inside aws_security_group, IPv6 addresses.
inline_v6(port) := {r.address |
	some r in live
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	is_world(object.get(rule, "ipv6_cidr_blocks", []))
	exposes(object.get(rule, "protocol", null), object.get(rule, "from_port", null), object.get(rule, "to_port", null), port)
}

# Modern standalone rule, IPv4 or IPv6 address.
modern(port) := {r.address |
	some r in live
	r.type == "aws_vpc_security_group_ingress_rule"
	after := r.change.after
	some cidr in {object.get(after, "cidr_ipv4", null), object.get(after, "cidr_ipv6", null)}
	cidr in world_cidrs
	exposes(object.get(after, "ip_protocol", null), object.get(after, "from_port", null), object.get(after, "to_port", null), port)
}

# Old standalone rule. Only "ingress" rules count; "egress" goes the other way.
old(port) := {r.address |
	some r in live
	r.type == "aws_security_group_rule"
	after := r.change.after
	after.type == "ingress"
	some cidrs in {object.get(after, "cidr_blocks", null), object.get(after, "ipv6_cidr_blocks", null)}
	is_world(cidrs)
	exposes(object.get(after, "protocol", null), object.get(after, "from_port", null), object.get(after, "to_port", null), port)
}

# Every resource that opens the port to the whole internet, in any of the four forms.
violating(port) := ((inline_v4(port) | inline_v6(port)) | modern(port)) | old(port)

# The resources this helper judges (used for the evidence records):
# security groups with inline rules, modern standalone rules, and old standalone "ingress" rules.
scope contains r.address if {
	some r in live
	r.type in {"aws_security_group", "aws_vpc_security_group_ingress_rule"}
}

scope contains r.address if {
	some r in live
	r.type == "aws_security_group_rule"
	r.change.after.type == "ingress"
}
