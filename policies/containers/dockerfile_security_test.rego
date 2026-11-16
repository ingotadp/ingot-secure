package ingot.containers.security_test

import rego.v1

import data.ingot.containers.security

test_deny_latest_image_tag if {
	mock_dockerfile := [
		{"Cmd": "from", "Value": ["alpine:latest"]},
		{"Cmd": "user", "Value": ["10001:10001"]},
	]

	violations := security.deny with input as mock_dockerfile
	count(violations) == 1
}

test_deny_missing_or_root_user if {
	mock_dockerfile := [
		{"Cmd": "from", "Value": ["cgr.dev/chainguard/static:latest@sha256:abcdef123456"]},
		{"Cmd": "user", "Value": ["root"]},
	]

	violations := security.deny with input as mock_dockerfile
	count(violations) == 1
}

test_allow_pinned_non_root_container if {
	mock_dockerfile := [
		{"Cmd": "from", "Value": ["cgr.dev/chainguard/static@sha256:abcdef123456"]},
		{"Cmd": "user", "Value": ["65532:65532"]},
	]

	violations := security.deny with input as mock_dockerfile
	count(violations) == 0
}
