// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingRepository struct {
	setup Setup
	err   error
}

func (repository *recordingRepository) CreateInitialOwner(_ context.Context, setup Setup) error {
	repository.setup = setup
	return repository.err
}

func TestStartBuildsAtomicInitialOwnerSetup(t *testing.T) {
	repository := new(recordingRepository)
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	service, err := New(repository, Options{OwnerRole: "home.owner", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Start(t.Context(), Input{Username: "cole.owner", Email: "COLE@EXAMPLE.TEST", DisplayName: "Cole Speelman", OrganizationSlug: "Gamertan", OrganizationName: "Gamertan"})
	if err != nil {
		t.Fatal(err)
	}
	setup := repository.setup
	if result.EnrollmentToken == "" || setup.Enrollment.Digest == [32]byte{} || result.User.Email != "cole@example.test" || result.Organization.Personal || result.Organization.Status != "active" {
		t.Fatalf("result=%+v setup=%+v", result, setup)
	}
	if setup.Membership.UserID != result.User.ID || setup.Membership.OrganizationID != result.Organization.ID || setup.OwnerBinding.Role != "home.owner" || setup.OwnerBinding.GrantedBy != result.User.ID {
		t.Fatalf("membership=%+v binding=%+v", setup.Membership, setup.OwnerBinding)
	}
	if setup.AuthAudit.ID == setup.OrganizationAudit.ID || setup.OrganizationAudit.ID == setup.AccessAudit.ID || setup.AuthAudit.Summary == "" || setup.AccessAudit.ResourceID != setup.OwnerBinding.ID {
		t.Fatalf("audits=%+v %+v %+v", setup.AuthAudit, setup.OrganizationAudit, setup.AccessAudit)
	}
	if !result.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expires=%v", result.ExpiresAt)
	}
}

func TestStartRejectsUnsafeInputAndDoesNotCommit(t *testing.T) {
	repository := new(recordingRepository)
	service, err := New(repository, Options{OwnerRole: "home.owner"})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []Input{
		{Username: "x", Email: "owner@example.test", DisplayName: "Owner", OrganizationSlug: "gamertan", OrganizationName: "Gamertan"},
		{Username: "owner.user", Email: "Owner <owner@example.test>", DisplayName: "Owner", OrganizationSlug: "gamertan", OrganizationName: "Gamertan"},
		{Username: "owner.user", Email: "owner@example.test", DisplayName: "Owner", OrganizationSlug: "bad/slug", OrganizationName: "Gamertan"},
	} {
		if _, startErr := service.Start(t.Context(), input); startErr == nil {
			t.Fatalf("unsafe input accepted: %+v", input)
		}
	}
	if repository.setup.User.ID != "" {
		t.Fatal("repository was called for rejected input")
	}
}

func TestStartDoesNotReturnSecretAfterRepositoryFailure(t *testing.T) {
	repository := &recordingRepository{err: errors.New("commit failed")}
	service, err := New(repository, Options{OwnerRole: "home.owner"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Start(t.Context(), Input{Username: "owner.user", Email: "owner@example.test", DisplayName: "Owner", OrganizationSlug: "gamertan", OrganizationName: "Gamertan"})
	if err == nil || result.EnrollmentToken != "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
