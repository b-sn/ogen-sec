package security

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"example.test/generated/api"
)

type basicStoreFunc func(context.Context, string, string) (BasicAuthRecord, error)

func (f basicStoreFunc) LookupBasicAuth(ctx context.Context, scheme, username string) (BasicAuthRecord, error) {
	return f(ctx, scheme, username)
}

type verifierFunc func(context.Context, string, string) (bool, error)

func (f verifierFunc) VerifyPassword(ctx context.Context, hash, password string) (bool, error) {
	return f(ctx, hash, password)
}

type keyStoreFunc func(context.Context, string, [sha256.Size]byte) (APIKeyRecord, error)

func (f keyStoreFunc) LookupAPIKey(ctx context.Context, scheme string, hash [sha256.Size]byte) (APIKeyRecord, error) {
	return f(ctx, scheme, hash)
}

type bearerVerifierFunc func(context.Context, string, string) (string, []string, error)

func (f bearerVerifierFunc) VerifyBearerToken(ctx context.Context, scheme, token string) (string, []string, error) {
	return f(ctx, scheme, token)
}

type oauth2VerifierFunc func(context.Context, string, string) (OAuth2TokenRecord, error)

func (f oauth2VerifierFunc) VerifyOAuth2Token(ctx context.Context, scheme, token string) (OAuth2TokenRecord, error) {
	return f(ctx, scheme, token)
}

func TestBasicAuth(t *testing.T) {
	storeError := errors.New("user store unavailable")
	verifyError := errors.New("password verification failed")
	for _, tc := range []struct {
		name                            string
		required                        []string
		emptyUsername, emptyPassword    bool
		wrongPassword, emptyHash        bool
		disabled, nilStore, nilVerifier bool
		expires                         time.Time
		storeErr, verifyErr, wantErr    error
		cancelAt                        string
	}{
		{name: "valid with required roles", required: []string{"read", "admin"}},
		{name: "valid without required roles"},
		{name: "valid with future expiration", expires: time.Now().Add(time.Hour)},
		{name: "valid with duplicate requirements", required: []string{"admin", "admin"}},
		{name: "empty username", emptyUsername: true, wantErr: ErrInvalidBasicAuth},
		{name: "empty password", emptyPassword: true, wantErr: ErrInvalidBasicAuth},
		{name: "wrong password", wrongPassword: true, wantErr: ErrInvalidBasicAuth},
		{name: "unknown user", storeErr: ErrInvalidBasicAuth, wantErr: ErrInvalidBasicAuth},
		{name: "wrapped unknown user", storeErr: fmt.Errorf("not found: %w", ErrInvalidBasicAuth), wantErr: ErrInvalidBasicAuth},
		{name: "empty stored hash", emptyHash: true, wantErr: ErrInvalidBasicAuth},
		{name: "disabled user", disabled: true, wantErr: ErrInvalidBasicAuth},
		{name: "expired user", expires: time.Now().Add(-time.Hour), wantErr: ErrInvalidBasicAuth},
		{name: "missing role", required: []string{"write"}, wantErr: ErrBasicAuthForbidden},
		{name: "missing second role", required: []string{"read", "write"}, wantErr: ErrBasicAuthForbidden},
		{name: "store failure", storeErr: storeError, wantErr: storeError},
		{name: "verifier failure", verifyErr: verifyError, wantErr: verifyError},
		{name: "missing store", nilStore: true, wantErr: ErrBasicAuthStoreNotConfigured},
		{name: "missing verifier", nilVerifier: true, wantErr: ErrPasswordVerifierNotConfigured},
		{name: "canceled before lookup", cancelAt: "before", wantErr: context.Canceled},
		{name: "canceled during lookup", cancelAt: "lookup", wantErr: context.Canceled},
		{name: "canceled during verification", cancelAt: "verify", wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type marker struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), marker{}, "preserved"))
			defer cancel()
			if tc.cancelAt == "before" {
				cancel()
			}
			record := BasicAuthRecord{
				PasswordHash: "encoded-password-hash", Subject: "user-42", Roles: []string{"read", "admin"},
				Disabled: tc.disabled, ExpiresAt: tc.expires,
			}
			if tc.emptyHash {
				record.PasswordHash = ""
			}
			credentials := api.LoginCredential{Username: "alice", Password: "supplied-password", Roles: tc.required}
			if tc.emptyUsername {
				credentials.Username = ""
			}
			if tc.emptyPassword {
				credentials.Password = ""
			}
			storeCalls, verifyCalls := 0, 0
			var store BasicAuthStore = basicStoreFunc(func(got context.Context, scheme, username string) (BasicAuthRecord, error) {
				storeCalls++
				if got != ctx || scheme != "LoginCredential" || username != credentials.Username {
					t.Fatal("incorrect user lookup arguments")
				}
				if tc.cancelAt == "lookup" {
					cancel()
					return record, got.Err()
				}
				return record, tc.storeErr
			})
			var verifier PasswordVerifier = verifierFunc(func(got context.Context, hash, password string) (bool, error) {
				verifyCalls++
				wantHash := record.PasswordHash
				if errors.Is(tc.storeErr, ErrInvalidBasicAuth) {
					wantHash = ""
				}
				if got != ctx || hash != wantHash || password != credentials.Password {
					t.Fatal("incorrect verification arguments or missing dummy verification")
				}
				if tc.cancelAt == "verify" {
					cancel()
					return false, got.Err()
				}
				// Even a verifier that incorrectly accepts an empty hash cannot
				// authorize an unknown user or an account with no stored hash.
				return !tc.wrongPassword, tc.verifyErr
			})
			if tc.nilStore {
				store = nil
			}
			if tc.nilVerifier {
				verifier = nil
			}
			required := slices.Clone(tc.required)
			result, err := NewHandler(nil, store, verifier, nil, nil).HandleLogin(ctx, "operation", credentials)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			wantStore, wantVerify := 1, 1
			if tc.cancelAt == "before" || tc.emptyUsername || tc.emptyPassword || tc.nilStore || tc.nilVerifier {
				wantStore, wantVerify = 0, 0
			} else if tc.cancelAt == "lookup" || tc.storeErr != nil && !errors.Is(tc.storeErr, ErrInvalidBasicAuth) {
				wantVerify = 0
			}
			if storeCalls != wantStore || verifyCalls != wantVerify {
				t.Fatalf("calls: store=%d verifier=%d, want %d/%d", storeCalls, verifyCalls, wantStore, wantVerify)
			}
			if !slices.Equal(tc.required, required) || !slices.Equal(record.Roles, []string{"read", "admin"}) {
				t.Fatal("authorization mutated role slices")
			}
			if result == nil || result.Value(marker{}) != "preserved" {
				t.Fatal("original context was lost")
			}
			identity, ok := BasicAuthIdentityFromContext(result, "LoginCredential")
			if tc.wantErr != nil {
				if ok || result != ctx {
					t.Fatal("failed authorization changed the context")
				}
				return
			}
			if !ok || identity.Subject != record.Subject || identity.Username != credentials.Username || !slices.Equal(identity.Roles, record.Roles) {
				t.Fatalf("unexpected identity: %+v, found %v", identity, ok)
			}
			record.Roles[0] = "changed by store"
			identity.Roles[1] = "changed by caller"
			again, _ := BasicAuthIdentityFromContext(result, "LoginCredential")
			if !slices.Equal(again.Roles, []string{"read", "admin"}) {
				t.Fatal("identity roles are not isolated")
			}
		})
	}
}

func TestCredentialShapesAndCombinedIdentities(t *testing.T) {
	var schemes []string
	store := basicStoreFunc(func(_ context.Context, scheme, _ string) (BasicAuthRecord, error) {
		schemes = append(schemes, scheme)
		return BasicAuthRecord{PasswordHash: "stored", Subject: scheme}, nil
	})
	verifier := verifierFunc(func(context.Context, string, string) (bool, error) { return true, nil })
	keys := keyStoreFunc(func(_ context.Context, _ string, hash [sha256.Size]byte) (APIKeyRecord, error) {
		return APIKeyRecord{Hash: hash, Subject: "api-key-owner"}, nil
	})
	bearer := bearerVerifierFunc(func(_ context.Context, scheme, token string) (string, []string, error) {
		if scheme != "BearerCredential" || token != "token" {
			t.Fatal("incorrect bearer verifier arguments")
		}
		return "token-owner", nil, nil
	})
	oauth2 := oauth2VerifierFunc(func(_ context.Context, scheme, token string) (OAuth2TokenRecord, error) {
		if scheme != "OAuthCredential" || token != "access-token" {
			t.Fatal("incorrect OAuth2 verifier arguments")
		}
		return OAuth2TokenRecord{Active: true, Subject: "oauth-owner", ClientID: "client-7", Scopes: []string{"read"}}, nil
	})
	h := NewHandler(keys, store, verifier, bearer, oauth2)
	ctx := context.Background()
	ctx, err := h.HandleKey(ctx, "operation", api.KeyCredential{APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = h.HandleLogin(ctx, "operation", api.LoginCredential{Username: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = h.HandleAlias(ctx, "operation", api.AliasCredential{Username: "bob", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = h.HandleBearer(ctx, "operation", api.BearerCredential{Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = h.HandleOAuth2(ctx, "operation", api.OAuthCredential{Token: "access-token", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandleLegacy(ctx, "operation", api.LegacyCredential{Username: "legacy", Password: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation", &api.PointerCredential{Username: "pointer", Password: "password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation", nil); !errors.Is(err, ErrInvalidBasicAuth) {
		t.Fatalf("nil credentials: %v", err)
	}
	if !slices.Equal(schemes, []string{"LoginCredential", "AliasCredential", "LegacyCredential", "PointerCredential"}) {
		t.Fatalf("wrong scheme namespaces: %v", schemes)
	}
	for _, scheme := range []string{"LoginCredential", "AliasCredential"} {
		identity, ok := BasicAuthIdentityFromContext(ctx, scheme)
		if !ok || identity.Subject != scheme {
			t.Fatalf("identity for %s was lost", scheme)
		}
	}
	keyIdentity, ok := APIKeyIdentityFromContext(ctx, "KeyCredential")
	if !ok || keyIdentity.Subject != "api-key-owner" {
		t.Fatal("API key identity was overwritten by another auth scheme")
	}
	bearerIdentity, ok := BearerAuthIdentityFromContext(ctx, "BearerCredential")
	if !ok || bearerIdentity.Subject != "token-owner" {
		t.Fatal("Bearer identity was lost")
	}
	oauthIdentity, ok := OAuth2IdentityFromContext(ctx, "OAuthCredential")
	if !ok || oauthIdentity.Subject != "oauth-owner" || oauthIdentity.ClientID != "client-7" || !slices.Equal(oauthIdentity.Scopes, []string{"read"}) {
		t.Fatal("OAuth2 identity was lost")
	}
	// A Bearer identity must not supply OAuth2 scopes or bypass a missing
	// OAuth2 verifier, even though both credentials carry a token.
	_, err = NewHandler(keys, store, verifier, bearer, nil).HandleOAuth2(ctx, "operation", api.OAuthCredential{Token: "access-token"})
	if !errors.Is(err, ErrOAuth2TokenVerifierNotConfigured) {
		t.Fatalf("other scheme bypassed OAuth2 verification: %v", err)
	}
	if _, ok := BasicAuthIdentityFromContext(ctx, "unknown"); ok {
		t.Fatal("unexpected identity for unknown scheme")
	}
}
