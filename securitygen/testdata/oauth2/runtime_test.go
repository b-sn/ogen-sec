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

type verifierFunc func(context.Context, string, string) (OAuth2TokenRecord, error)

func (f verifierFunc) VerifyOAuth2Token(ctx context.Context, scheme, token string) (OAuth2TokenRecord, error) {
	return f(ctx, scheme, token)
}

func TestOAuth2(t *testing.T) {
	verifyError := errors.New("introspection unavailable")
	for _, tc := range []struct {
		name                              string
		required, granted                 []string
		emptyToken, nilVerifier, inactive bool
		zeroRecord, clientOnly, noScopes  bool
		notBefore, expires                time.Time
		verifyErr, wantErr                error
		cancelAt                          string
	}{
		{name: "all required scopes", required: []string{"read", "write"}},
		{name: "no required scopes"},
		{name: "no granted or required scopes", noScopes: true},
		{name: "empty scope requirements", required: []string{}},
		{name: "duplicate requirements", required: []string{"read", "read"}},
		{name: "client credentials", clientOnly: true, required: []string{"read"}},
		{name: "valid within time window", notBefore: time.Now().Add(-time.Hour), expires: time.Now().Add(time.Hour)},
		{name: "empty token even without scopes", emptyToken: true, wantErr: ErrInvalidOAuth2Token},
		{name: "nil verifier even without scopes", nilVerifier: true, wantErr: ErrOAuth2TokenVerifierNotConfigured},
		{name: "invalid token despite returned record", verifyErr: ErrInvalidOAuth2Token, wantErr: ErrInvalidOAuth2Token},
		{name: "wrapped invalid token", verifyErr: fmt.Errorf("invalid audience: %w", ErrInvalidOAuth2Token), wantErr: ErrInvalidOAuth2Token},
		{name: "verifier failure despite returned record", verifyErr: verifyError, wantErr: verifyError},
		{name: "inactive or revoked", inactive: true, wantErr: ErrInvalidOAuth2Token},
		{name: "zero record is not authenticated", zeroRecord: true, wantErr: ErrInvalidOAuth2Token},
		{name: "not yet valid", notBefore: time.Now().Add(time.Hour), wantErr: ErrInvalidOAuth2Token},
		{name: "expired", expires: time.Now().Add(-time.Hour), wantErr: ErrInvalidOAuth2Token},
		{name: "missing scope", required: []string{"admin"}, wantErr: ErrOAuth2Forbidden},
		{name: "missing second scope", required: []string{"read", "admin"}, wantErr: ErrOAuth2Forbidden},
		{name: "no granted scopes", noScopes: true, required: []string{"read"}, wantErr: ErrOAuth2Forbidden},
		{name: "case sensitive scopes", required: []string{"Read"}, wantErr: ErrOAuth2Forbidden},
		{name: "no substring matching", required: []string{"rea"}, wantErr: ErrOAuth2Forbidden},
		{name: "no wildcard expansion", granted: []string{"*"}, required: []string{"read"}, wantErr: ErrOAuth2Forbidden},
		{name: "space separated scopes must be decoded by verifier", granted: []string{"read write"}, required: []string{"read"}, wantErr: ErrOAuth2Forbidden},
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
			record := OAuth2TokenRecord{
				Active: !tc.inactive, Subject: "user-42", ClientID: "client-7", Scopes: []string{"read", "write"},
				NotBefore: tc.notBefore, ExpiresAt: tc.expires,
			}
			if tc.clientOnly {
				record.Subject = ""
			}
			if tc.granted != nil {
				record.Scopes = slices.Clone(tc.granted)
			}
			if tc.noScopes {
				record.Scopes = nil
			}
			if tc.zeroRecord {
				record = OAuth2TokenRecord{}
			}
			credentials := api.AccessCredential{Token: "secret-access-token", Scopes: tc.required}
			if tc.emptyToken {
				credentials.Token = ""
			}
			calls := 0
			var verifier OAuth2TokenVerifier = verifierFunc(func(got context.Context, scheme, token string) (OAuth2TokenRecord, error) {
				calls++
				if got != ctx || scheme != "AccessCredential" || token != credentials.Token {
					t.Fatal("incorrect access token verification arguments")
				}
				if tc.cancelAt == "verify" {
					cancel()
				}
				return record, tc.verifyErr
			})
			if tc.nilVerifier {
				verifier = nil
			}
			required, granted := slices.Clone(tc.required), slices.Clone(record.Scopes)
			result, err := NewHandler(verifier).HandleAccess(ctx, "operation", credentials)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "secret-access-token") {
				t.Fatal("error leaks the access token")
			}
			wantCalls := 1
			if tc.emptyToken || tc.nilVerifier || tc.cancelAt == "before" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("verification calls = %d, want %d", calls, wantCalls)
			}
			if !slices.Equal(tc.required, required) || !slices.Equal(record.Scopes, granted) {
				t.Fatal("authorization mutated scope slices")
			}
			if result == nil || result.Value(marker{}) != "preserved" {
				t.Fatal("original context was lost")
			}
			identity, ok := OAuth2IdentityFromContext(result, "AccessCredential")
			if tc.wantErr != nil {
				if ok || result != ctx {
					t.Fatal("failed authorization changed the context")
				}
				return
			}
			if !ok || identity.Subject != record.Subject || identity.ClientID != record.ClientID || !slices.Equal(identity.Scopes, record.Scopes) {
				t.Fatalf("unexpected identity: %+v, found %v", identity, ok)
			}
			if len(granted) != 0 {
				record.Scopes[0] = "changed by verifier"
				identity.Scopes[0] = "changed by caller"
			}
			again, _ := OAuth2IdentityFromContext(result, "AccessCredential")
			if !slices.Equal(again.Scopes, granted) {
				t.Fatal("identity scopes are not isolated")
			}
		})
	}
}

func TestOAuth2SchemesAndCredentialShapes(t *testing.T) {
	var schemes []string
	h := NewHandler(verifierFunc(func(_ context.Context, scheme, token string) (OAuth2TokenRecord, error) {
		schemes = append(schemes, scheme)
		if token != "access-token" {
			return OAuth2TokenRecord{}, ErrInvalidOAuth2Token
		}
		return OAuth2TokenRecord{Active: true, Subject: scheme, ClientID: "client-7", Scopes: []string{"read"}}, nil
	}))
	ctx := context.Background()
	ctx, err := h.HandleAccess(ctx, "operation-1", api.AccessCredential{Token: "access-token", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = h.HandleAlias(ctx, "operation-2", api.AliasCredential{Token: "access-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation-3", &api.PointerCredential{Token: "access-token", Scopes: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation-3", nil); !errors.Is(err, ErrInvalidOAuth2Token) {
		t.Fatalf("nil credentials: %v", err)
	}
	if !slices.Equal(schemes, []string{"AccessCredential", "AliasCredential", "PointerCredential"}) {
		t.Fatalf("wrong scheme namespaces: %v", schemes)
	}
	for _, scheme := range []string{"AccessCredential", "AliasCredential"} {
		identity, ok := OAuth2IdentityFromContext(ctx, scheme)
		if !ok || identity.Subject != scheme {
			t.Fatalf("identity for %s was lost", scheme)
		}
	}
	if _, ok := OAuth2IdentityFromContext(ctx, "missing"); ok {
		t.Fatal("unexpected identity for unknown scheme")
	}
	// Reusing a context never bypasses validation or the next operation's scopes.
	if _, err := h.HandleAccess(ctx, "operation-4", api.AccessCredential{Token: "invalid"}); !errors.Is(err, ErrInvalidOAuth2Token) {
		t.Fatalf("previous identity bypassed token verification: %v", err)
	}
	if _, err := h.HandleAccess(ctx, "operation-4", api.AccessCredential{Token: "access-token", Scopes: []string{"write"}}); !errors.Is(err, ErrOAuth2Forbidden) {
		t.Fatalf("previous identity bypassed required scopes: %v", err)
	}
}
