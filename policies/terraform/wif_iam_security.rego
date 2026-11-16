package ingot.terraform.security

import rego.v1

# Deny Workload Identity bindings scoped broadly to an entire GitHub organisation
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_service_account_iam_member"
	rc.change.actions[_] in {"create", "update"}
	rc.change.after.role == "roles/iam.workloadIdentityUser"
	contains(rc.change.after.member, "/attribute.repository_owner/")

	msg := sprintf(
		"WIF privilege escalation risk in '%s': member '%s' must be scoped to 'attribute.repository/<org>/<repo>', not 'attribute.repository_owner'.",
		[rc.address, rc.change.after.member],
	)
}

# Deny primitive IAM roles (Owner/Editor) on GCP projects
deny contains msg if {
	some rc in input.resource_changes
	rc.type in {"google_project_iam_member", "google_project_iam_binding"}
	rc.change.actions[_] in {"create", "update"}
	rc.change.after.role in {"roles/owner", "roles/editor"}

	msg := sprintf(
		"Least-privilege violation in '%s': primitive role '%s' is prohibited.",
		[rc.address, rc.change.after.role],
	)
}
