package ct_11

import rego.v1

# CT-11: every CloudTrail trail must be multi-region, switched on, and record all management events.
# (Management events are actions on the account itself: creating users, changing settings, and so on.)

# Step 1: collect every trail that the plan will create or change.
trails contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	resource.change.actions != ["delete"]
}

# Step 2: does the trail say anything about which events to record?
has_selectors(after) if {
	count(after.event_selector) > 0
}

has_selectors(after) if {
	count(after.advanced_event_selector) > 0
}

# Step 3: does the trail record ALL management events (both reads and writes)?
# With no selector at all, AWS records all management events by default.
all_management_events(after) if {
	not has_selectors(after)
}

all_management_events(after) if {
	some selector in after.event_selector
	selector.include_management_events == true
	selector.read_write_type == "All"
}

# The newer "advanced" form: an eventCategory of Management and no readOnly filter.
all_management_events(after) if {
	some selector in after.advanced_event_selector
	some field in selector.field_selector
	field.field == "eventCategory"
	"Management" in field.equals
	not has_read_only_filter(selector)
}

has_read_only_filter(selector) if {
	some field in selector.field_selector
	field.field == "readOnly"
}

# Step 4: a trail is good only if every part is exactly right. Missing values count as "no".
good(after) if {
	after.is_multi_region_trail == true
	after.enable_logging == true
	all_management_events(after)
}

# The resources this rule judged (used for the evidence records).
scope contains trail.address if {
	some trail in trails
}

deny contains msg if {
	some trail in trails
	not good(trail.change.after)
	msg := sprintf("CT-11: %s must be multi-region, logging, and record all management events", [trail.address])
}
