<!-- SPDX-License-Identifier: MPL-2.0 -->

# Organizations and scoped access

One `auth.User` may belong to many organizations without creating another
credential or browser session. Organizations own projects; projects own
environments; environments own application services. Teams are optional groups
of active organization members.

`organizations.Service` creates those resources and issues digest-backed,
expiring, single-use invitations. An invitation may carry one direct role and
up to sixteen reviewed team memberships. Acceptance verifies that the
authenticated user's normalized email matches and applies the membership,
role, teams, consumption marker, and audit event in one transaction.
Applications own invitation pages, email or out-of-band delivery, active-source
checks before archival, and account recovery.

Organizations and teams use optimistic revisions and reversible
`active`/`archived` states. Archived objects keep their history but contribute
no effective authority. Memberships may be suspended, reactivated, or removed;
team membership can be removed independently. Configure `OwnerRole` when
constructing the service before exposing membership-removal operations. The
SQLite adapter then refuses to suspend or remove the final active direct owner.

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

The SQLite adapter namespaces all tables, enforces active organization and team
membership plus resource ancestry before accepting or evaluating a binding,
and keeps invitations and sessions as digests. Applications remain responsible
for database backup, filesystem ownership, retention, and presenting audit
history to organization owners.
