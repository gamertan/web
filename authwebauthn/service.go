// SPDX-License-Identifier: MPL-2.0

package authwebauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gamertan.com/web/internal/webauthnvendored/protocol"
	"gamertan.com/web/internal/webauthnvendored/protocol/webauthncose"
	wa "gamertan.com/web/internal/webauthnvendored/webauthn"

	"gamertan.com/web/auth"
)

const (
	defaultEnrollmentLifetime = 15 * time.Minute
	defaultRegistrationTTL    = 5 * time.Minute
	defaultLoginTTL           = 2 * time.Minute
	defaultApprovalTTL        = 90 * time.Second
	maxCredentialLabelBytes   = 80
	maxResponseBytes          = 128 << 10
)

var accountNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)

type Config struct {
	RPID                    string
	RPDisplayName           string
	Origin                  string
	EnrollmentLifetime      time.Duration
	RegistrationTTL         time.Duration
	LoginTTL                time.Duration
	ApprovalTTL             time.Duration
	SessionLifetime         time.Duration
	RequiredCredentialCount int
	Random                  io.Reader
	Now                     func() time.Time
}

type Service struct {
	repository Repository
	auth       *auth.Service
	webAuthn   *wa.WebAuthn
	random     io.Reader
	now        func() time.Time
	config     Config
}

type BootstrapInput struct {
	Username, Email, DisplayName string
}

func New(repository Repository, authService *auth.Service, config Config) (*Service, error) {
	if repository == nil || authService == nil {
		return nil, errors.New("authwebauthn: repository and auth service are required")
	}
	if err := validateOrigin(config.RPID, config.Origin); err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.RPDisplayName) == "" || len(config.RPDisplayName) > 80 {
		return nil, errors.New("authwebauthn: relying-party display name is invalid")
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.EnrollmentLifetime == 0 {
		config.EnrollmentLifetime = defaultEnrollmentLifetime
	}
	if config.RegistrationTTL == 0 {
		config.RegistrationTTL = defaultRegistrationTTL
	}
	if config.LoginTTL == 0 {
		config.LoginTTL = defaultLoginTTL
	}
	if config.ApprovalTTL == 0 {
		config.ApprovalTTL = defaultApprovalTTL
	}
	if config.SessionLifetime == 0 {
		config.SessionLifetime = 12 * time.Hour
	}
	if config.RequiredCredentialCount == 0 {
		config.RequiredCredentialCount = 2
	}
	if config.EnrollmentLifetime < time.Minute || config.EnrollmentLifetime > time.Hour ||
		config.RegistrationTTL < time.Minute || config.RegistrationTTL > 10*time.Minute ||
		config.LoginTTL < time.Minute || config.LoginTTL > 5*time.Minute ||
		config.ApprovalTTL < 30*time.Second || config.ApprovalTTL > 2*time.Minute ||
		config.SessionLifetime < 5*time.Minute || config.SessionLifetime > 30*24*time.Hour ||
		config.RequiredCredentialCount < 1 || config.RequiredCredentialCount > 8 {
		return nil, errors.New("authwebauthn: lifetime or credential-count policy is invalid")
	}
	webAuthn, err := wa.New(&wa.Config{
		RPID:                  config.RPID,
		RPDisplayName:         config.RPDisplayName,
		RPOrigins:             []string{config.Origin},
		RPAllowCrossOrigin:    false,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: wa.TimeoutsConfig{
			Login:        wa.TimeoutConfig{Timeout: config.LoginTTL, TimeoutUVD: config.LoginTTL},
			Registration: wa.TimeoutConfig{Timeout: config.RegistrationTTL, TimeoutUVD: config.RegistrationTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("authwebauthn: configure verifier: %w", err)
	}
	return &Service{repository: repository, auth: authService, webAuthn: webAuthn, random: config.Random, now: config.Now, config: config}, nil
}

func (service *Service) Bootstrap(ctx context.Context, input BootstrapInput) (auth.User, string, error) {
	username := strings.TrimSpace(input.Username)
	email := strings.TrimSpace(input.Email)
	displayName := strings.TrimSpace(input.DisplayName)
	if !accountNamePattern.MatchString(username) || email == "" || len(email) > 320 || !strings.Contains(email, "@") || displayName == "" || len(displayName) > 128 {
		return auth.User{}, "", errors.New("authwebauthn: invalid user")
	}
	userID, err := service.randomToken(18)
	if err != nil {
		return auth.User{}, "", err
	}
	token, enrollment, err := service.newEnrollment(userID)
	if err != nil {
		return auth.User{}, "", err
	}
	now := service.now().UTC()
	user := auth.User{ID: userID, Username: username, Email: email, DisplayName: displayName, Status: "active", CreatedAt: now, UpdatedAt: now}
	audit, err := service.audit("", "auth.passkey.bootstrap", "user", userID, "A local administrator created a passkey-only account and one-time enrollment token.")
	if err != nil {
		return auth.User{}, "", err
	}
	if err = service.repository.CreatePasskeyUser(ctx, user, enrollment, audit); err != nil {
		return auth.User{}, "", err
	}
	return user, token, nil
}

func (service *Service) Recover(ctx context.Context, identifier, reason string) (auth.User, string, error) {
	identifier = strings.TrimSpace(identifier)
	reason = strings.TrimSpace(reason)
	if identifier == "" || len(identifier) > 320 || reason == "" || len(reason) > 240 || strings.ContainsAny(reason, "\x00\r\n") {
		return auth.User{}, "", errors.New("authwebauthn: recovery identifier and bounded reason are required")
	}
	user, err := service.repository.UserByIdentifier(ctx, identifier)
	if err != nil {
		return auth.User{}, "", err
	}
	if user.Status != "active" {
		return auth.User{}, "", auth.ErrInactiveUser
	}
	token, enrollment, err := service.newEnrollment(user.ID)
	if err != nil {
		return auth.User{}, "", err
	}
	audit, err := service.audit("", "auth.passkey.recovery", "user", user.ID, "A local administrator revoked sessions and issued a one-time passkey enrollment token. Reason: "+reason)
	if err != nil {
		return auth.User{}, "", err
	}
	user, err = service.repository.RecoverUser(ctx, identifier, enrollment, audit)
	if err != nil {
		return auth.User{}, "", err
	}
	return user, token, nil
}

func (service *Service) BeginEnrollment(ctx context.Context, enrollmentToken, label string) (BeginResult, error) {
	digest, err := tokenDigest(enrollmentToken)
	if err != nil {
		return BeginResult{}, ErrEnrollmentNotFound
	}
	user, err := service.repository.ConsumeEnrollmentToken(ctx, digest, service.now().UTC())
	if err != nil {
		return BeginResult{}, err
	}
	return service.beginRegistration(ctx, user, label, CeremonyRegistration, [32]byte{})
}

func (service *Service) BeginRegistration(ctx context.Context, userID, label string) (BeginResult, error) {
	user, err := service.repository.UserByID(ctx, strings.TrimSpace(userID))
	if err != nil {
		return BeginResult{}, err
	}
	return service.beginRegistration(ctx, user, label, CeremonyRegistration, [32]byte{})
}

// BeginPasswordMigration starts registration for an already authenticated
// password-backed user. Completion atomically retires the password and revokes
// all sessions, including the session that authorized this ceremony.
func (service *Service) BeginPasswordMigration(ctx context.Context, userID, label string) (BeginResult, error) {
	user, err := service.repository.UserByID(ctx, strings.TrimSpace(userID))
	if err != nil {
		return BeginResult{}, err
	}
	exists, err := service.repository.PasswordCredentialExists(ctx, user.ID)
	if err != nil {
		return BeginResult{}, err
	}
	if !exists {
		return BeginResult{}, ErrPasswordNotAvailable
	}
	return service.beginRegistration(ctx, user, label, CeremonyRegistration, passwordMigrationBinding(user.ID))
}

func (service *Service) beginRegistration(ctx context.Context, user auth.User, label, kind string, binding [32]byte) (BeginResult, error) {
	label, err := credentialLabel(label)
	if err != nil {
		return BeginResult{}, err
	}
	adapter, err := service.user(ctx, user)
	if err != nil {
		return BeginResult{}, err
	}
	challenge, err := service.randomBytes(32)
	if err != nil {
		return BeginResult{}, err
	}
	creation, session, err := service.webAuthn.BeginRegistration(adapter,
		func(options *protocol.PublicKeyCredentialCreationOptions) { options.Challenge = challenge },
		wa.WithCredentialParameters([]protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}),
		wa.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		wa.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return BeginResult{}, fmt.Errorf("authwebauthn: begin registration: %w", err)
	}
	return service.storeCeremony(ctx, kind, user.ID, label, session, binding, creation.Response, service.config.RegistrationTTL)
}

func (service *Service) FinishRegistration(ctx context.Context, ceremonyToken string, response []byte) (Credential, error) {
	return service.finishRegistration(ctx, ceremonyToken, CeremonyRegistration, [32]byte{}, response, false)
}

// FinishPasswordMigration verifies the new passkey and persists it together
// with password retirement and session revocation in one storage transaction.
func (service *Service) FinishPasswordMigration(ctx context.Context, ceremonyToken string, response []byte) (Credential, error) {
	ceremony, err := service.takeCeremony(ctx, ceremonyToken, CeremonyRegistration)
	if err != nil {
		return Credential{}, err
	}
	return service.finishRegistrationCeremony(ctx, ceremony, passwordMigrationBinding(ceremony.UserID), response, true)
}

func (service *Service) finishRegistration(ctx context.Context, ceremonyToken, kind string, expectedBinding [32]byte, response []byte, retirePassword bool) (Credential, error) {
	ceremony, err := service.takeCeremony(ctx, ceremonyToken, kind)
	if err != nil {
		return Credential{}, err
	}
	return service.finishRegistrationCeremony(ctx, ceremony, expectedBinding, response, retirePassword)
}

func (service *Service) finishRegistrationCeremony(ctx context.Context, ceremony Ceremony, expectedBinding [32]byte, response []byte, retirePassword bool) (Credential, error) {
	if ceremony.BindingDigest != expectedBinding {
		return Credential{}, ErrOperationBinding
	}
	if len(response) == 0 || len(response) > maxResponseBytes {
		return Credential{}, errors.New("authwebauthn: registration response is invalid")
	}
	user, err := service.repository.UserByID(ctx, ceremony.UserID)
	if err != nil {
		return Credential{}, err
	}
	adapter, err := service.user(ctx, user)
	if err != nil {
		return Credential{}, err
	}
	session, err := decodeSession(ceremony.SessionData)
	if err != nil {
		return Credential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Credential{}, errors.New("authwebauthn: registration response is invalid")
	}
	verified, err := service.webAuthn.CreateCredential(adapter, session, parsed)
	if err != nil {
		return Credential{}, fmt.Errorf("authwebauthn: verify registration: %w", err)
	}
	if verified.Attestation.PublicKeyAlgorithm != int64(webauthncose.AlgES256) {
		return Credential{}, ErrUnsupportedCredential
	}
	encoded, err := json.Marshal(verified)
	if err != nil {
		return Credential{}, err
	}
	now := service.now().UTC()
	record := Credential{ID: append([]byte(nil), verified.ID...), UserID: user.ID, Label: ceremony.Label, Data: encoded, CreatedAt: now}
	action, summary := "auth.passkey.add", "A passkey was enrolled."
	if retirePassword {
		action, summary = "auth.passkey.migrate", "A passkey was enrolled and the legacy password credential was retired."
	}
	audit, err := service.audit(user.ID, action, "passkey", base64.RawURLEncoding.EncodeToString(verified.ID), summary)
	if err != nil {
		return Credential{}, err
	}
	if retirePassword {
		err = service.repository.SaveCredentialAndRetirePassword(ctx, record, audit)
	} else {
		err = service.repository.SaveCredential(ctx, record, audit)
	}
	if err != nil {
		return Credential{}, err
	}
	return record, nil
}

func (service *Service) BeginLogin(ctx context.Context) (BeginResult, error) {
	challenge, err := service.randomBytes(32)
	if err != nil {
		return BeginResult{}, err
	}
	assertion, session, err := service.webAuthn.BeginDiscoverableLogin(
		wa.WithChallenge(challenge),
		wa.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return BeginResult{}, fmt.Errorf("authwebauthn: begin login: %w", err)
	}
	return service.storeCeremony(ctx, CeremonyLogin, "", "", session, [32]byte{}, assertion.Response, service.config.LoginTTL)
}

func (service *Service) FinishLogin(ctx context.Context, ceremonyToken string, response []byte) (Authentication, error) {
	ceremony, err := service.takeCeremony(ctx, ceremonyToken, CeremonyLogin)
	if err != nil {
		return Authentication{}, err
	}
	if len(response) == 0 || len(response) > maxResponseBytes {
		return Authentication{}, errors.New("authwebauthn: login response is invalid")
	}
	session, err := decodeSession(ceremony.SessionData)
	if err != nil {
		return Authentication{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Authentication{}, errors.New("authwebauthn: login response is invalid")
	}
	var loaded *passkeyUser
	user, verified, err := service.webAuthn.ValidatePasskeyLogin(func(rawID, userHandle []byte) (wa.User, error) {
		account, lookupErr := service.repository.UserByCredentialID(ctx, rawID)
		if lookupErr != nil || account.ID != string(userHandle) {
			return nil, ErrCredentialNotFound
		}
		loaded, lookupErr = service.user(ctx, account)
		return loaded, lookupErr
	}, session, parsed)
	if err != nil || loaded == nil || user == nil {
		return Authentication{}, errors.New("authwebauthn: authentication failed")
	}
	if err = service.persistUsedCredential(ctx, loaded.account.ID, verified); err != nil {
		return Authentication{}, err
	}
	token, principal, err := service.auth.IssueSession(ctx, loaded.account.ID, service.config.SessionLifetime)
	if err != nil {
		return Authentication{}, err
	}
	return Authentication{SessionToken: token, Principal: principal, CredentialID: append([]byte(nil), verified.ID...), CloneWarning: verified.Authenticator.CloneWarning}, nil
}

func (service *Service) BeginApproval(ctx context.Context, userID string, binding []byte) (BeginResult, error) {
	if len(binding) < 32 || len(binding) > 32<<10 {
		return BeginResult{}, errors.New("authwebauthn: operation binding is invalid")
	}
	if err := service.RequireReady(ctx, userID); err != nil {
		return BeginResult{}, err
	}
	account, err := service.repository.UserByID(ctx, userID)
	if err != nil {
		return BeginResult{}, err
	}
	adapter, err := service.user(ctx, account)
	if err != nil {
		return BeginResult{}, err
	}
	challenge, err := service.randomBytes(32)
	if err != nil {
		return BeginResult{}, err
	}
	assertion, session, err := service.webAuthn.BeginLogin(adapter, wa.WithChallenge(challenge), wa.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return BeginResult{}, fmt.Errorf("authwebauthn: begin approval: %w", err)
	}
	return service.storeCeremony(ctx, CeremonyApproval, account.ID, "", session, BindingDigest(binding), assertion.Response, service.config.ApprovalTTL)
}

func (service *Service) FinishApproval(ctx context.Context, ceremonyToken string, binding, response []byte) (Approval, error) {
	ceremony, err := service.takeCeremony(ctx, ceremonyToken, CeremonyApproval)
	if err != nil {
		return Approval{}, err
	}
	if BindingDigest(binding) != ceremony.BindingDigest {
		return Approval{}, ErrOperationBinding
	}
	if len(response) == 0 || len(response) > maxResponseBytes {
		return Approval{}, errors.New("authwebauthn: approval response is invalid")
	}
	account, err := service.repository.UserByID(ctx, ceremony.UserID)
	if err != nil {
		return Approval{}, err
	}
	adapter, err := service.user(ctx, account)
	if err != nil {
		return Approval{}, err
	}
	session, err := decodeSession(ceremony.SessionData)
	if err != nil {
		return Approval{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Approval{}, errors.New("authwebauthn: approval response is invalid")
	}
	verified, err := service.webAuthn.ValidateLogin(adapter, session, parsed)
	if err != nil {
		return Approval{}, errors.New("authwebauthn: approval failed")
	}
	if err = service.persistUsedCredential(ctx, account.ID, verified); err != nil {
		return Approval{}, err
	}
	return Approval{User: account, CredentialID: append([]byte(nil), verified.ID...), BindingDigest: ceremony.BindingDigest, CloneWarning: verified.Authenticator.CloneWarning, ApprovedAt: service.now().UTC()}, nil
}

func (service *Service) RequireReady(ctx context.Context, userID string) error {
	count, err := service.repository.CredentialCount(ctx, userID)
	if err != nil {
		return err
	}
	if count < service.config.RequiredCredentialCount {
		return ErrPasskeyReadiness
	}
	return nil
}

// RequiredCredentialCount reports the configured operational credential
// floor. Applications can use it to explain rotation policy without
// duplicating security configuration.
func (service *Service) RequiredCredentialCount() int {
	return service.config.RequiredCredentialCount
}

// CredentialSummaries returns bounded account-owner metadata without exposing
// stored credential documents.
func (service *Service) CredentialSummaries(ctx context.Context, userID string) ([]CredentialSummary, error) {
	records, err := service.repository.CredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	summaries := make([]CredentialSummary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, CredentialSummary{
			ID:         append([]byte(nil), record.ID...),
			Label:      record.Label,
			CreatedAt:  record.CreatedAt,
			LastUsedAt: record.LastUsedAt,
		})
	}
	return summaries, nil
}

func (service *Service) BeginCredentialRemoval(ctx context.Context, userID string, credentialID []byte) (BeginResult, error) {
	if len(credentialID) < 16 || len(credentialID) > 1024 {
		return BeginResult{}, ErrCredentialNotFound
	}
	records, err := service.repository.CredentialsByUserID(ctx, userID)
	if err != nil {
		return BeginResult{}, err
	}
	found := false
	for _, record := range records {
		if bytes.Equal(record.ID, credentialID) {
			found = true
			break
		}
	}
	if !found {
		return BeginResult{}, ErrCredentialNotFound
	}
	if len(records) <= service.config.RequiredCredentialCount {
		return BeginResult{}, ErrCredentialFloor
	}
	return service.BeginApproval(ctx, userID, credentialRemovalBinding(userID, credentialID))
}

func (service *Service) FinishCredentialRemoval(ctx context.Context, ceremonyToken, userID string, credentialID, response []byte) error {
	binding := credentialRemovalBinding(userID, credentialID)
	approval, err := service.FinishApproval(ctx, ceremonyToken, binding, response)
	if err != nil {
		return err
	}
	if approval.User.ID != userID || approval.BindingDigest != BindingDigest(binding) {
		return ErrOperationBinding
	}
	audit, err := service.audit(userID, "auth.passkey.remove", "passkey", base64.RawURLEncoding.EncodeToString(credentialID), "A passkey was removed after fresh authentication.")
	if err != nil {
		return err
	}
	return service.repository.DeleteCredential(ctx, userID, credentialID, service.config.RequiredCredentialCount, audit)
}

func (service *Service) storeCeremony(ctx context.Context, kind, userID, label string, session *wa.SessionData, binding [32]byte, publicKey any, ttl time.Duration) (BeginResult, error) {
	token, err := service.randomToken(32)
	if err != nil {
		return BeginResult{}, err
	}
	digest := sha256.Sum256([]byte(token))
	now := service.now().UTC()
	session.Expires = now.Add(ttl)
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return BeginResult{}, err
	}
	publicJSON, err := json.Marshal(publicKey)
	if err != nil {
		return BeginResult{}, err
	}
	ceremony := Ceremony{Digest: digest, Kind: kind, UserID: userID, Label: label, SessionData: sessionJSON, BindingDigest: binding, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err = service.repository.CreateCeremony(ctx, ceremony); err != nil {
		return BeginResult{}, err
	}
	return BeginResult{CeremonyToken: token, PublicKey: publicJSON, ExpiresAt: ceremony.ExpiresAt}, nil
}

func (service *Service) takeCeremony(ctx context.Context, token, kind string) (Ceremony, error) {
	digest, err := tokenDigest(token)
	if err != nil {
		return Ceremony{}, ErrCeremonyNotFound
	}
	ceremony, err := service.repository.TakeCeremony(ctx, digest, service.now().UTC())
	if err != nil {
		return Ceremony{}, err
	}
	if ceremony.Kind != kind {
		return Ceremony{}, ErrCeremonyNotFound
	}
	return ceremony, nil
}

func (service *Service) user(ctx context.Context, account auth.User) (*passkeyUser, error) {
	if account.Status != "active" {
		return nil, auth.ErrInactiveUser
	}
	records, err := service.repository.CredentialsByUserID(ctx, account.ID)
	if err != nil {
		return nil, err
	}
	credentials := make([]wa.Credential, 0, len(records))
	for _, record := range records {
		var credential wa.Credential
		if err = json.Unmarshal(record.Data, &credential); err != nil || len(credential.ID) == 0 {
			return nil, errors.New("authwebauthn: stored credential is invalid")
		}
		credentials = append(credentials, credential)
	}
	return &passkeyUser{account: account, credentials: credentials}, nil
}

func (service *Service) persistUsedCredential(ctx context.Context, userID string, credential *wa.Credential) error {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return service.repository.UpdateCredential(ctx, Credential{ID: append([]byte(nil), credential.ID...), UserID: userID, Data: encoded, LastUsedAt: service.now().UTC()})
}

func (service *Service) newEnrollment(userID string) (string, EnrollmentToken, error) {
	token, err := service.randomToken(32)
	if err != nil {
		return "", EnrollmentToken{}, err
	}
	now := service.now().UTC()
	return token, EnrollmentToken{Digest: sha256.Sum256([]byte(token)), UserID: userID, CreatedAt: now, ExpiresAt: now.Add(service.config.EnrollmentLifetime)}, nil
}

func (service *Service) audit(actor, action, resourceType, resourceID, summary string) (auth.AuditEvent, error) {
	id, err := service.randomToken(18)
	if err != nil {
		return auth.AuditEvent{}, err
	}
	return auth.AuditEvent{ID: id, ActorUserID: actor, Action: action, ResourceType: resourceType, ResourceID: resourceID, Summary: summary, CreatedAt: service.now().UTC()}, nil
}

func (service *Service) randomToken(size int) (string, error) {
	value, err := service.randomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (service *Service) randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(service.random, value); err != nil {
		return nil, fmt.Errorf("authwebauthn: secure randomness unavailable: %w", err)
	}
	return value, nil
}

func tokenDigest(token string) ([32]byte, error) {
	if len(token) < 32 || len(token) > 128 {
		return [32]byte{}, errors.New("invalid token")
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return [32]byte{}, errors.New("invalid token")
	}
	return sha256.Sum256([]byte(token)), nil
}

func decodeSession(value []byte) (wa.SessionData, error) {
	var session wa.SessionData
	if len(value) == 0 || len(value) > 64<<10 || json.Unmarshal(value, &session) != nil {
		return wa.SessionData{}, errors.New("authwebauthn: stored ceremony is invalid")
	}
	return session, nil
}

func credentialLabel(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCredentialLabelBytes || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("authwebauthn: credential label is invalid")
	}
	return value, nil
}

func credentialRemovalBinding(userID string, credentialID []byte) []byte {
	return []byte("gamertan-web/passkey-remove/v1\x00" + userID + "\x00" + base64.RawURLEncoding.EncodeToString(credentialID))
}

func passwordMigrationBinding(userID string) [32]byte {
	return BindingDigest([]byte("gamertan-web/password-to-passkey/v1\x00" + userID))
}

func validateOrigin(rpID, rawOrigin string) error {
	if strings.TrimSpace(rpID) == "" || strings.TrimSpace(rawOrigin) == "" {
		return errors.New("authwebauthn: relying-party ID and origin are required")
	}
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() != rpID || origin.Port() != "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("authwebauthn: origin must be the exact HTTPS relying-party origin")
	}
	return nil
}

type passkeyUser struct {
	account     auth.User
	credentials []wa.Credential
}

func (user *passkeyUser) WebAuthnID() []byte                   { return []byte(user.account.ID) }
func (user *passkeyUser) WebAuthnName() string                 { return user.account.Username }
func (user *passkeyUser) WebAuthnDisplayName() string          { return user.account.DisplayName }
func (user *passkeyUser) WebAuthnCredentials() []wa.Credential { return user.credentials }
