package securitygen

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateOAuth2Detection(t *testing.T) {
	for _, tc := range []struct {
		name, declaration, method, wantError string
		otherKind                            string
	}{
		{
			name: "arbitrary names", declaration: "type CredentialXYZ struct { Token string; Scopes []string }",
			method: "AuthenticateXYZ(c ctxt.Context, operation string, key CredentialXYZ) (ctxt.Context, error)",
		},
		{
			name: "unnamed parameters", declaration: "type CredentialXYZ struct { Token string; Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)",
		},
		{
			name: "pointer and named results", declaration: "type CredentialXYZ struct { Token string; Scopes []string }",
			method: "Handle(s ctxt.Context, context string, h *CredentialXYZ) (next ctxt.Context, err error)",
		},
		{
			name: "alias", declaration: "type Original struct { Token string; Scopes []string }; type CredentialXYZ = Original",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)",
		},
		{
			name: "Bearer with misleading method name", declaration: "type CredentialXYZ struct { Token string; Roles []string }",
			method: "HandleOAuth2(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", otherKind: "bearer",
		},
		{
			name: "Token alone is Bearer", declaration: "type CredentialXYZ struct { Token string }",
			method: "HandleOAuth2(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", otherKind: "bearer",
		},
		{
			name: "unused OAuth2 type", declaration: "type Unused struct { Token string; Scopes []string }; type CredentialXYZ struct {}",
			method: "HandleOAuth2(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", otherKind: "stub",
		},
		{
			name: "missing token", declaration: "type CredentialXYZ struct { Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "OAuth2 credential CredentialXYZ must have a Token string field",
		},
		{
			name: "invalid token", declaration: "type CredentialXYZ struct { Token []byte; Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "Token string field",
		},
		{
			name: "invalid scopes", declaration: "type CredentialXYZ struct { Token string; Scopes string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "Scopes of type []string",
		},
		{
			name: "array is not scopes slice", declaration: "type CredentialXYZ struct { Token string; Scopes [2]string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "Scopes of type []string",
		},
		{
			name: "invalid result", declaration: "type CredentialXYZ struct { Token string; Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) error", wantError: "return (context.Context, error)",
		},
		{
			name: "invalid context", declaration: "type CredentialXYZ struct { Token string; Scopes []string }",
			method: "Handle(string, string, CredentialXYZ) (ctxt.Context, error)", wantError: "accept context.Context",
		},
		{
			name: "mixed roles and scopes", declaration: "type CredentialXYZ struct { Token string; Roles, Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "mixes Roles and Scopes",
		},
		{
			name: "scopes mixed with Basic", declaration: "type CredentialXYZ struct { Username, Password string; Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "mixes Scopes and other authentication fields",
		},
		{
			name: "scopes mixed with API key", declaration: "type CredentialXYZ struct { APIKey string; Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "mixes Scopes and other authentication fields",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := "package api\nimport ctxt \"context\"\ntype SecurityHandler interface { " + tc.method + " }\n"
			models := "package api\n" + tc.declaration + "\n"
			cfg := config{
				source: filepath.Join(dir, "security.go"), output: filepath.Join(dir, "out", "security.go"),
				apiImport: "example.test/api", packageName: "security", typeName: "Handler", constructor: "NewHandler",
			}
			writeTestFile(t, cfg.source, []byte(source))
			writeTestFile(t, filepath.Join(dir, "models.go"), []byte(models))
			code, err := generate(cfg)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertImplementationCompiles(t, cfg, code, source, models)
			if tc.otherKind != "" {
				if bytes.Contains(code, []byte("OAuth2TokenVerifier")) {
					t.Fatal("unrelated/unused scheme added OAuth2 support")
				}
				want := "func NewHandler()"
				if tc.otherKind == "bearer" {
					want = "func NewHandler(bearerTokens BearerTokenVerifier)"
				}
				if !bytes.Contains(code, []byte(want)) {
					t.Fatalf("missing %q", want)
				}
			} else {
				for _, want := range []string{
					"type OAuth2TokenVerifier interface", "func NewHandler(oauth2Tokens OAuth2TokenVerifier)",
					`s.authorizeOAuth2(ctx, "CredentialXYZ", credentials.Token, credentials.Scopes)`,
				} {
					if !bytes.Contains(code, []byte(want)) {
						t.Errorf("missing %q", want)
					}
				}
				if bytes.Contains(code, []byte("BearerTokenVerifier")) || bytes.Contains(code, []byte(": not implemented")) {
					t.Fatal("OAuth2 was confused with Bearer or left unimplemented")
				}
			}
			if bytes.Contains(code, []byte("APIKeyStore")) || bytes.Contains(code, []byte("BasicAuthStore")) {
				t.Fatal("OAuth2 alone generated unrelated dependencies")
			}
			again, err := generate(cfg)
			if err != nil || !bytes.Equal(code, again) {
				t.Fatalf("generation is not deterministic: %v", err)
			}
		})
	}
}

func TestOAuth2ConstructorDependencies(t *testing.T) {
	// Cover all combinations of the three other supported authentication kinds.
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("other_schemes_%03b", mask), func(t *testing.T) {
			methods := "HandleOAuth(context.Context, string, OAuth) (context.Context, error); HandleOther(context.Context, string, OtherOAuth) (context.Context, error);"
			var args []string
			if mask&1 != 0 {
				methods += "HandleKey(context.Context, string, Key) (context.Context, error);"
				args = append(args, "apiKeys APIKeyStore")
			}
			if mask&2 != 0 {
				methods += "HandleLogin(context.Context, string, Login) (context.Context, error);"
				args = append(args, "basicAuth BasicAuthStore", "passwords PasswordVerifier")
			}
			if mask&4 != 0 {
				methods += "HandleBearer(context.Context, string, Token) (context.Context, error);"
				args = append(args, "bearerTokens BearerTokenVerifier")
			}
			// OAuth2 parameters follow the other schemes even when its methods come first.
			args = append(args, "oauth2Tokens OAuth2TokenVerifier")
			source := `package api
import "context"
type Key struct { APIKey string }
type Login struct { Username, Password string }
type Token struct { Token string; Roles []string }
type OAuth struct { Token string; Scopes []string }
type OtherOAuth = OAuth
type SecurityHandler interface { ` + methods + " }\n"
			cfg := config{source: filepath.Join(t.TempDir(), "source.go"), apiImport: "example.test/api", packageName: "security", typeName: "Handler", constructor: "NewHandler"}
			writeTestFile(t, cfg.source, []byte(source))
			code, err := generate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertImplementationCompiles(t, cfg, code, source)
			if !bytes.Contains(code, []byte("func NewHandler("+strings.Join(args, ", ")+")")) {
				t.Fatalf("missing constructor arguments %v", args)
			}
			for name, want := range map[string]bool{"APIKeyStore": mask&1 != 0, "BasicAuthStore": mask&2 != 0, "PasswordVerifier": mask&2 != 0, "BearerTokenVerifier": mask&4 != 0, "OAuth2TokenVerifier": true} {
				if count := bytes.Count(code, []byte("type "+name+" interface")); (count == 1) != want || count > 1 {
					t.Errorf("interface %s count = %d, want presence %v", name, count, want)
				}
			}
			if bytes.Contains(code, []byte("panic(")) {
				t.Fatal("a supported scheme remains a stub")
			}
		})
	}
}

func TestGeneratedOAuth2Handlers(t *testing.T) {
	runGeneratedFixture(t, "oauth2")
}
