package vpc_17

import rego.v1

import data.open_ports

# VPC-17: no security group may allow SSH (port 22) from the whole internet.
# The real work is done by the shared helper in open_ports.rego.

ssh_port := 22

deny contains msg if {
	some address in open_ports.violating(ssh_port)
	msg := sprintf("VPC-17: %s allows SSH (port 22) from the whole internet", [address])
}
