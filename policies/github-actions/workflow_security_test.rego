package ingot.github_actions.security_test

import rego.v1

import data.ingot.github_actions.security

test_deny_unpinned_action_tag if {
	mock_workflow := {
		"permissions": {"contents": "read"},
		"jobs": {"build": {"steps": [{"uses": "actions/checkout@v4"}]}},
	}

	violations := security.deny with input as mock_workflow
	count(violations) == 1
}

test_deny_missing_permissions if {
	mock_workflow := {"jobs": {"build": {"steps": [{"uses": "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"}]}}}

	violations := security.deny with input as mock_workflow
	count(violations) == 1
}

test_allow_sha_pinned_action_with_permissions if {
	mock_workflow := {
		"permissions": {"contents": "read"},
		"jobs": {"build": {"steps": [{"uses": "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"}]}},
	}

	violations := security.deny with input as mock_workflow
	count(violations) == 0
}
