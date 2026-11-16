package ingot.containers.security

import rego.v1

# Deny base images using mutable ':latest' tags
deny contains msg if {
	some cmd in input
	lower(cmd.Cmd) == "from"
	image := cmd.Value[0]
	not contains(image, "@sha256:")
	endswith(image, ":latest")

	msg := sprintf("Container immutability violation: base image '%s' must not use ':latest'.", [image])
}

# Require a non-root USER instruction in the final stage
deny contains msg if {
	user_cmds := [cmd | some cmd in input; lower(cmd.Cmd) == "user"]
	count(user_cmds) == 0
	msg := "Container privilege violation: Dockerfile must specify a non-root USER instruction."
}

deny contains msg if {
	user_cmds := [cmd | some cmd in input; lower(cmd.Cmd) == "user"]
	count(user_cmds) > 0
	last_user := user_cmds[count(user_cmds) - 1].Value[0]
	last_user in {"root", "0", "0:0", "root:root"}

	msg := sprintf("Container privilege violation: final USER '%s' must not run as root.", [last_user])
}
