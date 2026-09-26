# Google Workspace and GCP IAM connectors

The Google connectors are read-only and use the same collector → immutable ZIP
artifact → importer flow as the directory connectors. Install the optional
runtime dependencies with `pip install '.[app,google]'`.

Workspace configuration references a service-account file through an
environment variable and uses domain-wide delegation for the configured
delegated administrator. GCP prefers Application Default Credentials and
supports a service-account file reference for local deployments. Credential
contents are never accepted in YAML or written to artifacts.

V1 coverage is deliberately explicit:

- Workspace: users, groups, direct membership roles (Member, Manager, Owner),
  nested groups, admin roles and direct role assignments.
- GCP: project-scoped IAM Allow bindings, IAM conditions and service accounts.

V1 does not collect IAM Deny, Principal Access Boundaries, GKE RBAC, object
ACLs, Gmail delegation, Drive ACLs, Calendar ACLs or OAuth grants. Incomplete
collections are marked `scoped`; they never authorize deletion of previously
observed objects.

Cloud Asset Inventory's `searchAllIamPolicies` requires the OAuth scope
`https://www.googleapis.com/auth/cloud-platform`; this scope alone does not
grant write access. The service account must still be restricted to the
read-only IAM permissions required by the connector. Configure a reverse proxy
and TLS outside EARE for production use; do not expose credential files to the
WebUI. Optional live tests must be explicitly configured and are skipped when
Google credentials are absent.
