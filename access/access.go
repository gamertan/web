// SPDX-License-Identifier: MPL-2.0

// Package access defines organization-scoped role bindings and audited,
// short-lived break-glass authorization.
package access

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,127}$`)
)

type SubjectKind string

const (
	User SubjectKind = "user"
	Team SubjectKind = "team"
)

type Scope struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

func (scope Scope) Validate() error {
	if !idPattern.MatchString(scope.OrganizationID) || scope.ProjectID != "" && !idPattern.MatchString(scope.ProjectID) || scope.EnvironmentID != "" && !idPattern.MatchString(scope.EnvironmentID) || scope.ServiceID != "" && !idPattern.MatchString(scope.ServiceID) {
		return errors.New("access: invalid scope")
	}
	if scope.EnvironmentID != "" && scope.ProjectID == "" || scope.ServiceID != "" && scope.EnvironmentID == "" {
		return errors.New("access: incomplete scope hierarchy")
	}
	return nil
}

func (scope Scope) contains(requested Scope) bool {
	if scope.OrganizationID != requested.OrganizationID {
		return false
	}
	for _, pair := range [][2]string{{scope.ProjectID, requested.ProjectID}, {scope.EnvironmentID, requested.EnvironmentID}, {scope.ServiceID, requested.ServiceID}} {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	return true
}

type Binding struct {
	ID          string
	SubjectKind SubjectKind
	SubjectID   string
	Role        string
	Scope       Scope
	GrantedBy   string
	GrantedAt   time.Time
}

type Policy struct {
	Roles       map[string]string
	Permissions map[string]string
	Grants      map[string][]string
}

func (policy Policy) Validate() error {
	if len(policy.Roles) == 0 || len(policy.Roles) > 1000 || len(policy.Permissions) == 0 || len(policy.Permissions) > 10000 || len(policy.Grants) > 1000 {
		return errors.New("access: invalid policy size")
	}
	for name, description := range policy.Roles {
		if !namePattern.MatchString(name) || !text(description, 512, true) {
			return errors.New("access: invalid role")
		}
	}
	for name, description := range policy.Permissions {
		if !namePattern.MatchString(name) || !text(description, 512, true) {
			return errors.New("access: invalid permission")
		}
	}
	for role, permissions := range policy.Grants {
		if _, ok := policy.Roles[role]; !ok || len(permissions) > 10000 {
			return errors.New("access: invalid role grant")
		}
		for _, permission := range permissions {
			if _, ok := policy.Permissions[permission]; !ok {
				return errors.New("access: role references unknown permission")
			}
		}
	}
	return nil
}

type BreakGlass struct {
	ID, OrganizationID, UserID, Permission, Reason string
	CreatedAt, ExpiresAt                           time.Time
}

type AuditEvent struct {
	ID, OrganizationID, ActorUserID, Action, ResourceType, ResourceID, RequestID, Summary string
	CreatedAt                                                                             time.Time
}

type Repository interface {
	SeedAccessPolicy(context.Context, Policy) error
	Grant(context.Context, Binding) error
	Revoke(context.Context, string, string, time.Time) error
	EffectiveBindings(context.Context, string, string) ([]Binding, error)
	CreateBreakGlass(context.Context, BreakGlass, AuditEvent) error
	ActiveBreakGlass(context.Context, string, string, time.Time) ([]BreakGlass, error)
	AppendAccessAudit(context.Context, AuditEvent) error
	AccessAudit(context.Context, string, int) ([]AuditEvent, error)
}

type Options struct {
	Random io.Reader
	Now    func() time.Time
}

type Service struct {
	repository Repository
	policy     Policy
	random     io.Reader
	now        func() time.Time
}

func New(repository Repository, policy Policy, options Options) (*Service, error) {
	if repository == nil {
		return nil, errors.New("access: repository is required")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{repository: repository, policy: policy, random: options.Random, now: options.Now}, nil
}

func (service *Service) Seed(ctx context.Context) error {
	return service.repository.SeedAccessPolicy(ctx, service.policy)
}

type Grant struct {
	SubjectKind SubjectKind
	SubjectID   string
	Role        string
	Scope       Scope
	GrantedBy   string
}

func (service *Service) Grant(ctx context.Context, input Grant) (Binding, error) {
	if (input.SubjectKind != User && input.SubjectKind != Team) || !idPattern.MatchString(input.SubjectID) || !idPattern.MatchString(input.GrantedBy) {
		return Binding{}, errors.New("access: invalid binding subject")
	}
	if _, ok := service.policy.Roles[input.Role]; !ok {
		return Binding{}, errors.New("access: unknown role")
	}
	if err := input.Scope.Validate(); err != nil {
		return Binding{}, err
	}
	id, err := randomID(service.random)
	if err != nil {
		return Binding{}, err
	}
	binding := Binding{ID: id, SubjectKind: input.SubjectKind, SubjectID: input.SubjectID, Role: input.Role, Scope: input.Scope, GrantedBy: input.GrantedBy, GrantedAt: service.now().UTC()}
	if err = service.repository.Grant(ctx, binding); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

type Decision struct {
	Allowed bool
	Source  string
	Role    string
}

func (service *Service) Authorize(ctx context.Context, userID string, scope Scope, permission string) (Decision, error) {
	if !idPattern.MatchString(userID) || !namePattern.MatchString(permission) {
		return Decision{}, errors.New("access: invalid authorization request")
	}
	if err := scope.Validate(); err != nil {
		return Decision{}, err
	}
	if _, ok := service.policy.Permissions[permission]; !ok {
		return Decision{}, errors.New("access: unknown permission")
	}
	bindings, err := service.repository.EffectiveBindings(ctx, scope.OrganizationID, userID)
	if err != nil {
		return Decision{}, err
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ID < bindings[j].ID })
	for _, binding := range bindings {
		if !binding.Scope.contains(scope) {
			continue
		}
		for _, granted := range service.policy.Grants[binding.Role] {
			if granted == permission {
				return Decision{Allowed: true, Source: "role", Role: binding.Role}, nil
			}
		}
	}
	breakGlass, err := service.repository.ActiveBreakGlass(ctx, scope.OrganizationID, userID, service.now().UTC())
	if err != nil {
		return Decision{}, err
	}
	for _, grant := range breakGlass {
		if grant.Permission == permission {
			return Decision{Allowed: true, Source: "break_glass"}, nil
		}
	}
	return Decision{}, nil
}

func (service *Service) ActivateBreakGlass(ctx context.Context, organizationID, userID, permission, reason, requestID string, lifetime time.Duration) (BreakGlass, error) {
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(userID) || !namePattern.MatchString(permission) || !text(strings.TrimSpace(reason), 1024, false) || !text(requestID, 128, true) || lifetime < time.Minute || lifetime > time.Hour {
		return BreakGlass{}, errors.New("access: invalid break-glass request")
	}
	if _, ok := service.policy.Permissions[permission]; !ok {
		return BreakGlass{}, errors.New("access: unknown permission")
	}
	id, err := randomID(service.random)
	if err != nil {
		return BreakGlass{}, err
	}
	auditID, err := randomID(service.random)
	if err != nil {
		return BreakGlass{}, err
	}
	now := service.now().UTC()
	grant := BreakGlass{ID: id, OrganizationID: organizationID, UserID: userID, Permission: permission, Reason: strings.TrimSpace(reason), CreatedAt: now, ExpiresAt: now.Add(lifetime)}
	audit := AuditEvent{ID: auditID, OrganizationID: organizationID, ActorUserID: userID, Action: "break_glass.activate", ResourceType: "organization", ResourceID: organizationID, RequestID: requestID, Summary: "Temporary emergency access activated", CreatedAt: now}
	if err = service.repository.CreateBreakGlass(ctx, grant, audit); err != nil {
		return BreakGlass{}, err
	}
	return grant, nil
}

func (service *Service) Audit(ctx context.Context, organizationID string, limit int) ([]AuditEvent, error) {
	if !idPattern.MatchString(organizationID) || limit < 1 || limit > 1000 {
		return nil, errors.New("access: invalid audit query")
	}
	return service.repository.AccessAudit(ctx, organizationID, limit)
}

func randomID(random io.Reader) (string, error) {
	value := make([]byte, 18)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("access: secure randomness unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func text(value string, limit int, emptyOK bool) bool {
	return (emptyOK || value != "") && len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}
