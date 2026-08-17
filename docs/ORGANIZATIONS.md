<!-- SPDX-License-Identifier: MPL-2.0 -->

# Organizations and scoped access

One `auth.User` may belong to many organizations without creating another
credential or browser session. Organizations own projects; projects own
environments; environments own application services. Teams are optional groups
of active organization members.

`organizations.Service` creates those resources and issues digest-backed,
expiring, single-use invitations. Acceptance verifies that the authenticated
user's normalized email matches the invitation before activating membership.
Applications own invitation pages, email or out-of-band delivery, organization
deletion policy, and account recovery.

`access.Service` evaluates a permission against a complete resource scope:

```go
decision, err := accessService.Authorize(ctx, principal.User.ID, access.Scope{
	OrganizationID: organizationID,
	ProjectID:      projectID,
	EnvironmentID:  environmentID,
	ServiceID:      serviceID,
}, "telemetry.read")
```

A binding at organization scope covers its descendants. A narrower binding
covers only its matching branch. The repository resolves team membership; a
handler must never accept caller-supplied team identifiers as authority.

Platform roles in `auth.Principal` remain useful for installation health,
account administration, and other explicitly global operations. They do not
grant organization-data access. If an operator must inspect tenant data during
an incident, use a reasoned break-glass grant. It expires within one hour and
creates an append-only audit event in the same transaction.

The SQLite adapter namespaces all tables, enforces organization membership and
resource ancestry before accepting a binding, and keeps invitations and
sessions as digests. Applications remain responsible for database backup,
filesystem ownership, retention, and presenting audit history to organization
owners.
