package vpc_17

import rego.v1

# VPC-17: no security group may allow SSH (port 22) from the whole internet.

# The port we protect, and the addresses that mean "the whole internet".
ssh_port := 22

world_cidrs := {"0.0.0.0/0", "::/0"}

# Step 1: look only at resources that are not being deleted.
live contains r if {
	some r in input.resource_changes
	r.change.actions != ["delete"]
}

# Step 2: does an address list contain a "whole internet" address?
# If the list is missing or empty, this is undefined (counts as "no").
is_world(cidrs) if {
	some cidr in cidrs
	cidr in world_cidrs
}

# Step 3: does the range from..to include the port?
# If either end is missing, we cannot tell, so we say "yes" (no data must not pass).
covers(from, to, port) if {
	not is_number(from)
}

covers(from, to, port) if {
	not is_number(to)
}

covers(from, to, port) if {
	from <= port
	port <= to
}

# Step 4: does a rule with this protocol and port range expose the port?
# "-1" means every protocol and every port. "tcp" needs the range to include the port.
exposes(protocol, from, to, port) if {
	protocol == "-1"
}

exposes(protocol, from, to, port) if {
	protocol == "tcp"
	covers(from, to, port)
}

# Step 5: collect every resource that opens the port to the world.

# 5a: inline rules inside aws_security_group, IPv4 addresses.
violating contains r.address if {
	some r in live
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	is_world(object.get(rule, "cidr_blocks", []))
	exposes(object.get(rule, "protocol", null), object.get(rule, "from_port", null), object.get(rule, "to_port", null), ssh_port)
}

# 5b: inline rules inside aws_security_group, IPv6 addresses.
violating contains r.address if {
	some r in live
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	is_world(object.get(rule, "ipv6_cidr_blocks", []))
	exposes(object.get(rule, "protocol", null), object.get(rule, "from_port", null), object.get(rule, "to_port", null), ssh_port)
}

# 5c: modern standalone rule, IPv4 or IPv6 address.
violating contains r.address if {
	some r in live
	r.type == "aws_vpc_security_group_ingress_rule"
	after := r.change.after
	some cidr in {object.get(after, "cidr_ipv4", null), object.get(after, "cidr_ipv6", null)}
	cidr in world_cidrs
	exposes(object.get(after, "ip_protocol", null), object.get(after, "from_port", null), object.get(after, "to_port", null), ssh_port)
}

# 5d: old standalone rule. Only "ingress" rules count; "egress" goes the other way.
violating contains r.address if {
	some r in live
	r.type == "aws_security_group_rule"
	after := r.change.after
	after.type == "ingress"
	some cidrs in {object.get(after, "cidr_blocks", null), object.get(after, "ipv6_cidr_blocks", null)}
	is_world(cidrs)
	exposes(object.get(after, "protocol", null), object.get(after, "from_port", null), object.get(after, "to_port", null), ssh_port)
}

# Step 6: one complaint per offending resource.
deny contains msg if {
	some address in violating
	msg := sprintf("VPC-17: %s allows SSH (port 22) from the whole internet", [address])
}
