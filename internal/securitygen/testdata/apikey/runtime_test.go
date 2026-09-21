package security

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"example.test/generated/api"
)

type storeFunc func(context.Context, string, [sha256.Size]byte) (APIKeyRecord, error)

func (f storeFunc) LookupAPIKey(ctx context.Context, scheme string, hash [sha256.Size]byte) (APIKeyRecord, error) {
	return f(ctx, scheme, hash)
}

func TestAPIKeyMethods(t *testing.T) {
	backendError := errors.New("backend unavailable")
	for _, method := range []struct {
		scheme string
		call   func(*Handler, context.Context, string, []string) (context.Context, error)
	}{
		{"CookieCredential", func(h *Handler, ctx context.Context, key string, roles []string) (context.Context, error) {
			return h.HandleCookie(ctx, "operation", api.CookieCredential{APIKey: key, Roles: roles})
		}},
		{"HeaderCredential", func(h *Handler, ctx context.Context, key string, roles []string) (context.Context, error) {
			return h.HandleHeader(ctx, "operation", api.HeaderCredential{APIKey: key, Roles: roles})
		}},
		{"QueryCredential", func(h *Handler, ctx context.Context, key string, roles []string) (context.Context, error) {
			return h.HandleQuery(ctx, "operation", api.QueryCredential{APIKey: key, Roles: roles})
		}},
	} {
		t.Run(method.scheme, func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				key      string
				required []string
				expires  time.Time
				revoked  bool
				storeErr error
				nilStore bool
				cancel   bool
				wantErr  error
			}{
				{name: "valid with all required roles", key: "valid", required: []string{"read", "admin"}},
				{name: "valid without required roles", key: "valid"},
				{name: "valid with future expiration", key: "valid", expires: time.Now().Add(time.Hour)},
				{name: "valid with duplicate requirements", key: "valid", required: []string{"admin", "admin"}},
				{name: "empty key", wantErr: ErrInvalidAPIKey},
				{name: "mismatched hash", key: "wrong", wantErr: ErrInvalidAPIKey},
				{name: "unknown key", key: "valid", storeErr: ErrInvalidAPIKey, wantErr: ErrInvalidAPIKey},
				{name: "revoked", key: "valid", revoked: true, wantErr: ErrInvalidAPIKey},
				{name: "expired", key: "valid", expires: time.Now().Add(-time.Hour), wantErr: ErrInvalidAPIKey},
				{name: "missing role", key: "valid", required: []string{"write"}, wantErr: ErrAPIKeyForbidden},
				{name: "missing second role", key: "valid", required: []string{"read", "write"}, wantErr: ErrAPIKeyForbidden},
				{name: "backend error", key: "valid", storeErr: backendError, wantErr: backendError},
				{name: "missing store", key: "valid", nilStore: true, wantErr: ErrAPIKeyStoreNotConfigured},
				{name: "canceled", key: "valid", cancel: true, wantErr: context.Canceled},
			} {
				t.Run(tc.name, func(t *testing.T) {
					type marker struct{}
					ctx := context.WithValue(context.Background(), marker{}, "preserved")
					if tc.cancel {
						canceled, cancel := context.WithCancel(ctx)
						cancel()
						ctx = canceled
					}
					record := APIKeyRecord{
						Hash: sha256.Sum256([]byte("valid")), Subject: "user-42", Roles: []string{"read", "admin"},
						ExpiresAt: tc.expires, Revoked: tc.revoked,
					}
					calls := 0
					var store APIKeyStore = storeFunc(func(gotCtx context.Context, scheme string, hash [sha256.Size]byte) (APIKeyRecord, error) {
						calls++
						if gotCtx != ctx || scheme != method.scheme || hash != sha256.Sum256([]byte(tc.key)) {
							t.Fatal("store received incorrect context, scheme, or key digest")
						}
						return record, tc.storeErr
					})
					if tc.nilStore {
						store = nil
					}
					required := slices.Clone(tc.required)
					result, err := method.call(NewHandler(store), ctx, tc.key, tc.required)
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("error = %v, want %v", err, tc.wantErr)
					}
					wantCalls := 1
					if tc.cancel || tc.nilStore || tc.key == "" {
						wantCalls = 0
					}
					if calls != wantCalls {
						t.Fatalf("store calls = %d, want %d", calls, wantCalls)
					}
					if !slices.Equal(tc.required, required) || !slices.Equal(record.Roles, []string{"read", "admin"}) {
						t.Fatal("authorization mutated role slices")
					}
					if result == nil || result.Value(marker{}) != "preserved" {
						t.Fatal("original context values were lost")
					}
					identity, ok := APIKeyIdentityFromContext(result, method.scheme)
					if tc.wantErr != nil {
						if ok || result != ctx {
							t.Fatal("failed authorization changed the context")
						}
						return
					}
					if !ok || identity.Subject != record.Subject || !slices.Equal(identity.Roles, record.Roles) {
						t.Fatalf("unexpected identity: %+v, found %v", identity, ok)
					}
					// Neither the store nor consumers can mutate the context's roles.
					record.Roles[0] = "modified by store"
					identity.Roles[1] = "modified by caller"
					again, _ := APIKeyIdentityFromContext(result, method.scheme)
					if !slices.Equal(again.Roles, []string{"read", "admin"}) {
						t.Fatal("context identity shares mutable roles")
					}
				})
			}
		})
	}
}

func TestIndependentSchemeIdentities(t *testing.T) {
	store := storeFunc(func(_ context.Context, scheme string, hash [sha256.Size]byte) (APIKeyRecord, error) {
		return APIKeyRecord{Hash: hash, Subject: scheme}, nil
	})
	handler := NewHandler(store)
	ctx, err := handler.HandleCookie(context.Background(), "operation", api.CookieCredential{APIKey: "cookie-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = handler.HandleHeader(ctx, "operation", api.HeaderCredential{APIKey: "header-key"})
	if err != nil {
		t.Fatal(err)
	}
	for _, scheme := range []string{"CookieCredential", "HeaderCredential"} {
		identity, ok := APIKeyIdentityFromContext(ctx, scheme)
		if !ok || identity.Subject != scheme {
			t.Fatalf("identity for %s was lost", scheme)
		}
	}
	if _, ok := APIKeyIdentityFromContext(ctx, "QueryCredential"); ok {
		t.Fatal("identity exists for a scheme that was not authenticated")
	}
}

func TestAdditionalCredentialShapes(t *testing.T) {
	var schemes []string
	store := storeFunc(func(_ context.Context, scheme string, hash [sha256.Size]byte) (APIKeyRecord, error) {
		schemes = append(schemes, scheme)
		return APIKeyRecord{Hash: hash}, nil
	})
	h := NewHandler(store)
	ctx := context.Background()
	if _, err := h.HandleLegacy(ctx, "operation", api.LegacyCredential{APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandleAlias(ctx, "operation", api.AliasCredential{APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation", &api.PointerCredential{APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandlePointer(ctx, "operation", nil); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("nil credential: %v", err)
	}
	if !slices.Equal(schemes, []string{"LegacyCredential", "AliasCredential", "PointerCredential"}) {
		t.Fatalf("wrong scheme namespaces: %v", schemes)
	}
}

func TestOtherSchemesRemainStubs(t *testing.T) {
	defer func() {
		if got := recover(); got != "HandleUnsupported: not implemented" {
			t.Fatalf("panic = %v", got)
		}
	}()
	_, _ = NewHandler(nil).HandleUnsupported(context.Background(), "operation", api.CustomCredential{})
}
