package securitygen

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateBearerAuthDetection(t *testing.T) {
	for _, tc := range []struct {
		name, declaration, method, wantError string
		stub, oauth                          bool
	}{
		{
			name: "arbitrary names", declaration: "type CredentialXYZ struct { Token string; Roles []string }",
			method: "AuthenticateXYZ(c ctxt.Context, operation string, key CredentialXYZ) (ctxt.Context, error)",
		},
		{
			name: "no roles", declaration: "type CredentialXYZ struct { Token string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)",
		},
		{
			name: "pointer and named results", declaration: "type CredentialXYZ struct { Token string; Roles []string }",
			method: "Handle(s ctxt.Context, context string, h *CredentialXYZ) (next ctxt.Context, err error)",
		},
		{
			name: "alias", declaration: "type Original struct { Token string; Roles []string }; type CredentialXYZ = Original",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)",
		},
		{
			name: "OAuth2 is not HTTP Bearer", declaration: "type CredentialXYZ struct { Token string; Scopes []string }",
			method: "HandleBearerAuth(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", oauth: true,
		},
		{
			name: "unused bearer type", declaration: "type Unused struct { Token string; Roles []string }; type CredentialXYZ struct {}",
			method: "HandleBearerAuth(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", stub: true,
		},
		{
			name: "invalid token", declaration: "type CredentialXYZ struct { Token []byte }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "Token string field",
		},
		{
			name: "invalid roles", declaration: "type CredentialXYZ struct { Token string; Roles string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "Roles of type []string",
		},
		{
			name: "invalid result", declaration: "type CredentialXYZ struct { Token string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) error", wantError: "return (context.Context, error)",
		},
		{
			name: "invalid context", declaration: "type CredentialXYZ struct { Token string }",
			method: "Handle(string, string, CredentialXYZ) (ctxt.Context, error)", wantError: "accept context.Context",
		},
		{
			name: "mixed roles and scopes", declaration: "type CredentialXYZ struct { Token string; Roles, Scopes []string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "mixes Roles and Scopes",
		},
		{
			name: "mixed API key and token", declaration: "type CredentialXYZ struct { Token, APIKey string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "mixes token and other authentication fields",
		},
		{
			name: "mixed Basic and token", declaration: "type CredentialXYZ struct { Token, Username, Password string }",
			method: "Handle(ctxt.Context, string, CredentialXYZ) (ctxt.Context, error)", wantError: "mixes token and other authentication fields",
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
			if tc.stub {
				if bytes.Contains(code, []byte("BearerTokenVerifier")) || !bytes.Contains(code, []byte("func NewHandler()")) || !bytes.Contains(code, []byte(": not implemented")) {
					t.Fatal("unsupported/unused scheme added Bearer support")
				}
			} else if tc.oauth {
				if bytes.Contains(code, []byte("BearerTokenVerifier")) || !bytes.Contains(code, []byte("func NewHandler(oauth2Tokens OAuth2TokenVerifier)")) {
					t.Fatal("OAuth2 must use its own verifier, not Bearer support")
				}
			} else {
				for _, want := range []string{
					"type BearerTokenVerifier interface", "func NewHandler(bearerTokens BearerTokenVerifier)",
					`s.authorizeBearerAuth(ctx, "CredentialXYZ", credentials.Token,`,
				} {
					if !bytes.Contains(code, []byte(want)) {
						t.Errorf("missing %q", want)
					}
				}
			}
			if bytes.Contains(code, []byte("APIKeyStore")) || bytes.Contains(code, []byte("BasicAuthStore")) {
				t.Fatal("Bearer auth alone generated unrelated dependencies")
			}
			again, err := generate(cfg)
			if err != nil || !bytes.Equal(code, again) {
				t.Fatalf("generation is not deterministic: %v", err)
			}
		})
	}
}

func TestBearerConstructorDependencies(t *testing.T) {
	const bearer = "HandleBearer(context.Context, string, Token) (context.Context, error);"
	const other = "HandleOther(context.Context, string, OtherToken) (context.Context, error);"
	const key = "HandleKey(context.Context, string, Key) (context.Context, error);"
	const basic = "HandleLogin(context.Context, string, Login) (context.Context, error);"
	const oauth = "HandleOAuth(context.Context, string, OAuth) (context.Context, error);"
	for _, tc := range []struct {
		name, methods, args string
		key, basic, oauth2  bool
	}{
		{name: "Bearer only", methods: bearer, args: "bearerTokens BearerTokenVerifier"},
		{name: "multiple schemes", methods: bearer + other, args: "bearerTokens BearerTokenVerifier"},
		{name: "Bearer and OAuth2", methods: bearer + oauth, args: "bearerTokens BearerTokenVerifier, oauth2Tokens OAuth2TokenVerifier", oauth2: true},
		{name: "with API key", methods: bearer + key, args: "apiKeys APIKeyStore, bearerTokens BearerTokenVerifier", key: true},
		{name: "with Basic", methods: bearer + basic, args: "basicAuth BasicAuthStore, passwords PasswordVerifier, bearerTokens BearerTokenVerifier", basic: true},
		{name: "all schemes", methods: key + basic + bearer + other + oauth, args: "apiKeys APIKeyStore, basicAuth BasicAuthStore, passwords PasswordVerifier, bearerTokens BearerTokenVerifier, oauth2Tokens OAuth2TokenVerifier", key: true, basic: true, oauth2: true},
		{name: "reversed order", methods: oauth + other + bearer + basic + key, args: "apiKeys APIKeyStore, basicAuth BasicAuthStore, passwords PasswordVerifier, bearerTokens BearerTokenVerifier, oauth2Tokens OAuth2TokenVerifier", key: true, basic: true, oauth2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := `package api
import "context"
type Key struct { APIKey string }
type Login struct { Username, Password string }
type Token struct { Token string; Roles []string }
type OtherToken = Token
type OAuth struct { Token string; Scopes []string }
type SecurityHandler interface { ` + tc.methods + " }\n"
			cfg := config{source: filepath.Join(t.TempDir(), "source.go"), apiImport: "example.test/api", packageName: "security", typeName: "Handler", constructor: "NewHandler"}
			writeTestFile(t, cfg.source, []byte(source))
			code, err := generate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertImplementationCompiles(t, cfg, code, source)
			if !bytes.Contains(code, []byte("func NewHandler("+tc.args+")")) {
				t.Fatalf("missing constructor arguments %s", tc.args)
			}
			for name, want := range map[string]bool{"APIKeyStore": tc.key, "BasicAuthStore": tc.basic, "PasswordVerifier": tc.basic, "BearerTokenVerifier": true, "OAuth2TokenVerifier": tc.oauth2} {
				if count := bytes.Count(code, []byte("type "+name+" interface")); (count == 1) != want || count > 1 {
					t.Errorf("interface %s count = %d, want presence %v", name, count, want)
				}
			}
		})
	}
}

func TestGeneratedBearerAuthHandlers(t *testing.T) {
	runGeneratedFixture(t, "bearerauth")
}
