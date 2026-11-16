package ingot.github_actions.security

import rego.v1

# Require explicit top-level permissions block to prevent overly broad GITHUB_TOKEN defaults
deny contains msg if {
	not input.permissions
	msg := "Workflow security violation: top-level 'permissions' block must be explicitly declared."
}

# Require external third-party actions to be pinned to a full 40-character commit SHA
deny contains msg if {
	some job_name, job in input.jobs
	some step in job.steps
	step.uses
	not startswith(step.uses, "./")
	not startswith(step.uses, "docker://")
	not regex.match(`^[^@]+@[0-9a-f]{40}$`, step.uses)

	msg := sprintf(
		"Supply-chain risk in job '%s': action '%s' must be pinned to a 40-character commit SHA.",
		[job_name, step.uses],
	)
}
