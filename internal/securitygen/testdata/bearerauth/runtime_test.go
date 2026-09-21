package security

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"example.test/generated/api"
)

type verifierFunc func(context.Context, string, string) (BearerTokenRecord, error)

func (f verifierFunc) VerifyBearerToken(ctx context.Context, scheme, token string) (BearerTokenRecord, error) {
	return f(ctx, scheme, token)
}

func TestBearerAuth(t *testing.T) {
	verifyError := errors.New("token verifier unavailable")
	for _, tc := range []struct {
		name                              string
		required                          []string
		emptyToken, nilVerifier, inactive bool
		zeroRecord                        bool
		notBefore, expires                time.Time
		verifyErr, wantErr                error
		cancelAt                          string
	}{
		{name: "valid with required roles", required: []string{"read", "admin"}},
		{name: "valid without required roles"},
		{name: "valid with duplicate requirements", required: []string{"admin", "admin"}},
		{name: "valid within time window", notBefore: time.Now().Add(-time.Hour), expires: time.Now().Add(time.Hour)},
		{name: "empty token", emptyToken: true, wantErr: ErrInvalidBearerToken},
		{name: "nil verifier", nilVerifier: true, wantErr: ErrBearerTokenVerifierNotConfigured},
		{name: "invalid token despite returned record", verifyErr: ErrInvalidBearerToken, wantErr: ErrInvalidBearerToken},
		{name: "wrapped invalid token", verifyErr: fmt.Errorf("bad signature: %w", ErrInvalidBearerToken), wantErr: ErrInvalidBearerToken},
		{name: "verifier failure despite returned record", verifyErr: verifyError, wantErr: verifyError},
		{name: "inactive or revoked", inactive: true, wantErr: ErrInvalidBearerToken},
		{name: "zero record is not authenticated", zeroRecord: true, wantErr: ErrInvalidBearerToken},
		{name: "not yet valid", notBefore: time.Now().Add(time.Hour), wantErr: ErrInvalidBearerToken},
		{name: "expired", expires: time.Now().Add(-time.Hour), wantErr: ErrInvalidBearerToken},
		{name: "missing role", required: []string{"write"}, wantErr: ErrBearerAuthForbidden},
		{name: "missing second role", required: []string{"read", "write"}, wantErr: ErrBearerAuthForbidden},
		{name: "canceled before verification", cancelAt: "before", wantErr: context.Canceled},
		{name: "canceled during verification", cancelAt: "verify", wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type marker struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), marker{}, "preserved"))
			defer cancel()
			if tc.cancelAt == "before" {
				cancel()
			}
			record := BearerTokenRecord{
				Active: !tc.inactive, Subject: "user-42", Roles: []string{"read", "admin"},
				NotBefore: tc.notBefore, ExpiresAt: tc.expires,
			}
			if tc.zeroRecord {
				record = BearerTokenRecord{}
			}
			credentials := api.CredentialXYZ{Token: "secret-opaque-token", Roles: tc.required}
			if tc.emptyToken {
				credentials.Token = ""
			}
			calls := 0
			var verifier BearerTokenVerifier = verifierFunc(func(got context.Context, scheme, token string) (BearerTokenRecord, error) {
				calls++
				if got != ctx || scheme != "CredentialXYZ" || token != credentials.Token {
					t.Fatal("incorrect token verification arguments")
				}
				if tc.cancelAt == "verify" {
					cancel()
				}
				return record, tc.verifyErr
			})
			if tc.nilVerifier {
				verifier = nil
			}
			required, granted := slices.Clone(tc.required), slices.Clone(record.Roles)
			result, err := NewHandler(verifier).HandleToken(ctx, "operation", credentials)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "secret-opaque-token") {
				t.Fatal("error leaks the token")
			}
			wantCalls := 1
			if tc.emptyToken || tc.nilVerifier || tc.cancelAt == "before" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("verification calls = %d, want %d", calls, wantCalls)
			}
			if !slices.Equal(tc.required, required) || !slices.Equal(record.Roles, granted) {
				t.Fatal("authorization mutated role slices")
			}
			if result == nil || result.Value(marker{}) != "preserved" {
				t.Fatal("original context was lost")
			}
			identity, ok := BearerAuthIdentityFromContext(result, "CredentialXYZ")
			if tc.wantErr != nil {
				if ok || result != ctx {
					t.Fatal("failed authorization changed the context")
				}
				return
			}
			if !ok || identity.Subject != record.Subject || !slices.Equal(identity.Roles, record.Roles) {
				t.Fatalf("unexpected identity: %+v, found %v", identity, ok)
			}
			record.Roles[0] = "changed by verifier"
			identity.Roles[1] = "changed by caller"
			again, _ := BearerAuthIdentityFromContext(result, "CredentialXYZ")
			if !slices.Equal(again.Roles, []string{"read", "admin"}) {
				t.Fatal("identity roles are not isolated")
			}
		})
	}
}

func TestBearerSchemesAndCredentialShapes(t *testing.T) {
	var schemes []string
	h := NewHandler(verifierFunc(func(_ context.Context, scheme, token string) (BearerTokenRecord, error) {
		schemes = append(schemes, scheme)
		if token != "opaque-token" {
			return BearerTokenRecord{}, ErrInvalidBearerToken
		}
		return BearerTokenRecord{Active: true, Subject: scheme, Roles: []string{"read"}}, nil
	}))
	ctx := context.Background()
	ctx, err := h.HandleToken(ctx, "operation-1", api.CredentialXYZ{Token: "opaque-token", Roles: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = h.HandleReferenced(ctx, "operation-2", api.ReferencedToken{Token: "opaque-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandleLegacy(ctx, "operation-3", api.LegacyToken{Token: "opaque-token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation-4", &api.PointerToken{Token: "opaque-token", Roles: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation-4", nil); !errors.Is(err, ErrInvalidBearerToken) {
		t.Fatalf("nil credentials: %v", err)
	}
	if !slices.Equal(schemes, []string{"CredentialXYZ", "ReferencedToken", "LegacyToken", "PointerToken"}) {
		t.Fatalf("wrong scheme namespaces: %v", schemes)
	}
	for _, scheme := range []string{"CredentialXYZ", "ReferencedToken"} {
		identity, ok := BearerAuthIdentityFromContext(ctx, scheme)
		if !ok || identity.Subject != scheme {
			t.Fatalf("identity for %s was lost", scheme)
		}
	}
	if _, ok := BearerAuthIdentityFromContext(ctx, "missing"); ok {
		t.Fatal("unexpected identity for unknown scheme")
	}
	// An identity from an earlier success must not bypass verification or the
	// current operation's role requirements.
	if _, err := h.HandleToken(ctx, "different-operation", api.CredentialXYZ{Token: "bad-token"}); !errors.Is(err, ErrInvalidBearerToken) {
		t.Fatalf("cached identity bypassed token verification: %v", err)
	}
	if _, err := h.HandleToken(ctx, "admin-operation", api.CredentialXYZ{Token: "opaque-token", Roles: []string{"admin"}}); !errors.Is(err, ErrBearerAuthForbidden) {
		t.Fatalf("cached identity bypassed required roles: %v", err)
	}
}

func TestUnsupportedSchemeRemainsStub(t *testing.T) {
	defer func() {
		if got := recover(); got != "HandleUnsupported: not implemented" {
			t.Fatalf("unsupported scheme must remain a stub, got %v", got)
		}
	}()
	_, _ = NewHandler(nil).HandleUnsupported(context.Background(), "operation", api.CustomCredential{})
}
