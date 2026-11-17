package vpc_18

import rego.v1

import data.open_ports

# VPC-18: no security group may allow RDP (port 3389) from the whole internet.
# The real work is done by the shared helper in open_ports.rego.

rdp_port := 3389

deny contains msg if {
	some address in open_ports.violating(rdp_port)
	msg := sprintf("VPC-18: %s allows RDP (port 3389) from the whole internet", [address])
}
