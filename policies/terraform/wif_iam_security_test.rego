package ingot.terraform.security_test

import rego.v1

import data.ingot.terraform.security

test_deny_org_wide_wif_binding if {
	mock_plan := {"resource_changes": [{
		"address": "module.wif.google_service_account_iam_member.runner",
		"type": "google_service_account_iam_member",
		"change": {
			"actions": ["create"],
			"after": {
				"role": "roles/iam.workloadIdentityUser",
				"member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attribute.repository_owner/ingotadp",
			},
		},
	}]}

	violations := security.deny with input as mock_plan
	count(violations) == 1
}

test_allow_repo_scoped_wif_binding if {
	mock_plan := {"resource_changes": [{
		"address": "module.wif.google_service_account_iam_member.runner",
		"type": "google_service_account_iam_member",
		"change": {
			"actions": ["create"],
			"after": {
				"role": "roles/iam.workloadIdentityUser",
				"member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attribute.repository/ingotadp/ingot-core",
			},
		},
	}]}

	violations := security.deny with input as mock_plan
	count(violations) == 0
}

test_deny_primitive_project_role if {
	mock_plan := {"resource_changes": [{
		"address": "google_project_iam_member.bad_binding",
		"type": "google_project_iam_member",
		"change": {
			"actions": ["create"],
			"after": {
				"role": "roles/editor",
				"member": "serviceAccount:runner@ingotadp-core.iam.gserviceaccount.com",
			},
		},
	}]}

	violations := security.deny with input as mock_plan
	count(violations) == 1
}
