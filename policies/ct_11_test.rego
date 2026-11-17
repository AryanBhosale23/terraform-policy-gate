package ct_11_test

import rego.v1

import data.ct_11

# A trail with the given settings. "extra" holds the optional selector fields.
trail(multi_region, logging, extra) := {
	"address": "aws_cloudtrail.main",
	"type": "aws_cloudtrail",
	"change": {
		"actions": ["create"],
		"after": object.union({"is_multi_region_trail": multi_region, "enable_logging": logging}, extra),
	},
}

all_events_selector := {"event_selector": [{"include_management_events": true, "read_write_type": "All"}]}

test_good_trail_with_default_events_is_allowed if {
	plan := {"resource_changes": [trail(true, true, {})]}
	count(ct_11.deny) == 0 with input as plan
}

test_good_trail_with_explicit_selector_is_allowed if {
	plan := {"resource_changes": [trail(true, true, all_events_selector)]}
	count(ct_11.deny) == 0 with input as plan
}

test_good_trail_with_advanced_selector_is_allowed if {
	selector := {"advanced_event_selector": [{"field_selector": [{"field": "eventCategory", "equals": ["Management"]}]}]}
	plan := {"resource_changes": [trail(true, true, selector)]}
	count(ct_11.deny) == 0 with input as plan
}

test_single_region_trail_is_denied if {
	plan := {"resource_changes": [trail(false, true, {})]}
	count(ct_11.deny) == 1 with input as plan
}

test_trail_with_logging_off_is_denied if {
	plan := {"resource_changes": [trail(true, false, {})]}
	count(ct_11.deny) == 1 with input as plan
}

# Reads are missing, so not ALL management events.
test_read_only_selector_is_denied if {
	selector := {"event_selector": [{"include_management_events": true, "read_write_type": "ReadOnly"}]}
	plan := {"resource_changes": [trail(true, true, selector)]}
	count(ct_11.deny) == 1 with input as plan
}

# A selector that records only data events, not management events.
test_selector_without_management_events_is_denied if {
	selector := {"event_selector": [{"include_management_events": false, "read_write_type": "All"}]}
	plan := {"resource_changes": [trail(true, true, selector)]}
	count(ct_11.deny) == 1 with input as plan
}

# Advanced selector with a readOnly filter only records part of the management events.
test_advanced_selector_with_read_only_filter_is_denied if {
	selector := {"advanced_event_selector": [{"field_selector": [
		{"field": "eventCategory", "equals": ["Management"]},
		{"field": "readOnly", "equals": ["false"]},
	]}]}
	plan := {"resource_changes": [trail(true, true, selector)]}
	count(ct_11.deny) == 1 with input as plan
}

# Multi-region value missing: no data must not pass.
test_missing_multi_region_value_is_denied if {
	missing := {
		"address": "aws_cloudtrail.main",
		"type": "aws_cloudtrail",
		"change": {"actions": ["create"], "after": {"enable_logging": true}},
	}
	plan := {"resource_changes": [missing]}
	count(ct_11.deny) == 1 with input as plan
}
