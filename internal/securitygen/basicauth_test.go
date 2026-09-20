package securitygen

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateBasicAuthDetection(t *testing.T) {
	for _, tc := range []struct {
		name, declaration, method, wantError string
	}{
		{
			name:        "arbitrary names and grouped credential fields",
			declaration: "type LoginXYZ struct { Username, Password string; Roles []string }",
			method:      "AuthenticateXYZ(c ctxt.Context, operation string, key LoginXYZ) (ctxt.Context, error)",
		},
		{
			name:        "no roles and unnamed parameters",
			declaration: "type LoginXYZ struct { Username, Password string }",
			method:      "Handle(ctxt.Context, string, LoginXYZ) (ctxt.Context, error)",
		},
		{
			name:        "pointer and named results",
			declaration: "type LoginXYZ struct { Username, Password string; Roles []string }",
			method:      "Handle(s ctxt.Context, context string, h *LoginXYZ) (next ctxt.Context, err error)",
		},
		{
			name:        "alias",
			declaration: "type Original struct { Username, Password string }; type LoginXYZ = Original",
			method:      "Handle(ctxt.Context, string, LoginXYZ) (ctxt.Context, error)",
		},
		{
			name:        "missing password",
			declaration: "type LoginXYZ struct { Username string }",
			method:      "Handle(ctxt.Context, string, LoginXYZ) (ctxt.Context, error)",
			wantError:   "Username and Password string fields",
		},
		{
			name:        "wrong username type",
			declaration: "type LoginXYZ struct { Username int; Password string }",
			method:      "Handle(ctxt.Context, string, LoginXYZ) (ctxt.Context, error)",
			wantError:   "Username and Password string fields",
		},
		{
			name:        "wrong roles type",
			declaration: "type LoginXYZ struct { Username, Password string; Roles string }",
			method:      "Handle(ctxt.Context, string, LoginXYZ) (ctxt.Context, error)",
			wantError:   "Roles of type []string",
		},
		{
			name:        "wrong result type",
			declaration: "type LoginXYZ struct { Username, Password string }",
			method:      "Handle(ctxt.Context, string, LoginXYZ) error",
			wantError:   "return (context.Context, error)",
		},
		{
			name:        "ambiguous credential shape",
			declaration: "type LoginXYZ struct { Username, Password, APIKey string }",
			method:      "Handle(ctxt.Context, string, LoginXYZ) (ctxt.Context, error)",
			wantError:   "mixes API key and Basic auth fields",
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
			for _, want := range []string{
				"type BasicAuthStore interface", "type PasswordVerifier interface",
				"func NewHandler(basicAuth BasicAuthStore, passwords PasswordVerifier)",
				`s.authorizeBasicAuth(ctx, "LoginXYZ", credentials.Username, credentials.Password,`,
			} {
				if !bytes.Contains(code, []byte(want)) {
					t.Errorf("missing %q", want)
				}
			}
			if bytes.Contains(code, []byte("APIKeyStore")) {
				t.Fatal("Basic auth alone must not generate an API key dependency")
			}
			again, err := generate(cfg)
			if err != nil || !bytes.Equal(code, again) {
				t.Fatalf("generation is not deterministic: %v", err)
			}
		})
	}
}

func TestConstructorDependencies(t *testing.T) {
	const keyMethod = "HandleKey(context.Context, string, Key) (context.Context, error);"
	const loginMethod = "HandleLogin(context.Context, string, Login) (context.Context, error);"
	const secondLogin = "HandleSecond(context.Context, string, OtherLogin) (context.Context, error);"
	for _, tc := range []struct {
		name, methods, constructor string
		key, basic                 bool
	}{
		{name: "none", constructor: "func NewHandler()"},
		{name: "API key", methods: keyMethod, constructor: "func NewHandler(apiKeys APIKeyStore)", key: true},
		{name: "Basic auth", methods: loginMethod, constructor: "func NewHandler(basicAuth BasicAuthStore, passwords PasswordVerifier)", basic: true},
		{name: "both kinds", methods: keyMethod + loginMethod, constructor: "func NewHandler(apiKeys APIKeyStore, basicAuth BasicAuthStore, passwords PasswordVerifier)", key: true, basic: true},
		{name: "reversed method order", methods: loginMethod + keyMethod, constructor: "func NewHandler(apiKeys APIKeyStore, basicAuth BasicAuthStore, passwords PasswordVerifier)", key: true, basic: true},
		{name: "multiple Basic schemes", methods: loginMethod + secondLogin, constructor: "func NewHandler(basicAuth BasicAuthStore, passwords PasswordVerifier)", basic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "package api\n"
			if tc.methods != "" {
				source += "import \"context\"\n"
			}
			source += "type Key struct { APIKey string }; type Login struct { Username, Password string }; type OtherLogin = Login\n"
			source += "type SecurityHandler interface { " + tc.methods + " }\n"
			cfg := config{source: filepath.Join(t.TempDir(), "source.go"), apiImport: "example.test/api", packageName: "security", typeName: "Handler", constructor: "NewHandler"}
			writeTestFile(t, cfg.source, []byte(source))
			code, err := generate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertImplementationCompiles(t, cfg, code, source)
			if !bytes.Contains(code, []byte(tc.constructor)) {
				t.Fatalf("missing constructor %s", tc.constructor)
			}
			for name, want := range map[string]bool{"APIKeyStore": tc.key, "BasicAuthStore": tc.basic, "PasswordVerifier": tc.basic} {
				if count := bytes.Count(code, []byte("type "+name+" interface")); (count == 1) != want || count > 1 {
					t.Errorf("interface %s count = %d, want presence %v", name, count, want)
				}
			}
		})
	}
}

func TestGeneratedBasicAuthHandlers(t *testing.T) {
	runGeneratedFixture(t, "basicauth")
}
