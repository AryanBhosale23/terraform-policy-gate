package iam_06

import rego.v1

# IAM-06: no IAM policy may grant full administrator access (Allow every action on every resource).
# We judge: customer-managed policies, inline policies, and attachments of AWS's AdministratorAccess.

admin_arn := "arn:aws:iam::aws:policy/AdministratorAccess"

policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

attachment_types := {
	"aws_iam_role_policy_attachment",
	"aws_iam_user_policy_attachment",
	"aws_iam_group_policy_attachment",
	"aws_iam_policy_attachment",
}

# Look only at resources that are not being deleted.
live contains r if {
	some r in input.resource_changes
	r.change.actions != ["delete"]
}

documents contains r if {
	some r in live
	r.type in policy_types
}

attachments contains r if {
	some r in live
	r.type in attachment_types
}

# IAM lets a value be a single item or a list of items. Turn both into a list.
as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

# Can we read the policy text? It must be a string that is valid JSON.
readable(r) if {
	is_string(r.change.after.policy)
	json.is_valid(r.change.after.policy)
}

# Full admin: an Allow statement with "*" as an action and "*" as a resource.
is_admin(document) if {
	some statement in as_list(document.Statement)
	statement.Effect == "Allow"
	"*" in as_list(statement.Action)
	"*" in as_list(statement.Resource)
}

# The resources this rule judged (used for the evidence records).
scope contains r.address if {
	some r in (documents | attachments)
}

deny contains msg if {
	some r in documents
	not readable(r)
	msg := sprintf("IAM-06: %s has a policy that cannot be read at plan time", [r.address])
}

deny contains msg if {
	some r in documents
	readable(r)
	is_admin(json.unmarshal(r.change.after.policy))
	msg := sprintf("IAM-06: %s grants full administrator access (Allow * on *)", [r.address])
}

deny contains msg if {
	some r in attachments
	r.change.after.policy_arn == admin_arn
	msg := sprintf("IAM-06: %s attaches the AdministratorAccess policy", [r.address])
}
