package securitygen

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAPIKeyDetection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		declaration string
		method      string
		wantAPIKey  bool
		wantError   string
	}{
		{
			name:        "arbitrary scheme and method names",
			declaration: "type CustomSecret struct { APIKey string; Roles []string }",
			method:      "AuthenticateXYZ(c ctxt.Context, operation string, key CustomSecret) (ctxt.Context, error)",
			wantAPIKey:  true,
		},
		{
			name:        "legacy credential without roles",
			declaration: "type CustomSecret struct { APIKey string }",
			method:      "Handle(ctxt.Context, string, CustomSecret) (ctxt.Context, error)",
			wantAPIKey:  true,
		},
		{
			name:        "pointer credential and named results",
			declaration: "type CustomSecret struct { APIKey string; Roles []string }",
			method:      "Handle(c ctxt.Context, s string, h *CustomSecret) (next ctxt.Context, err error)",
			wantAPIKey:  true,
		},
		{
			name:        "credential alias",
			declaration: "type Original struct { APIKey string; Roles []string }; type CustomSecret = Original",
			method:      "Handle(ctxt.Context, string, CustomSecret) (ctxt.Context, error)",
			wantAPIKey:  true,
		},
		{
			name:        "misleading method name is not an API key",
			declaration: "type CustomSecret struct { Token string; Roles []string }",
			method:      "HandleApiKeyHeader(ctxt.Context, string, CustomSecret) (ctxt.Context, error)",
		},
		{
			name:        "unused API key type adds no dependency",
			declaration: "type Unused struct { APIKey string }; type CustomSecret struct { Token string }",
			method:      "Handle(ctxt.Context, string, CustomSecret) (ctxt.Context, error)",
		},
		{
			name:        "invalid API key field",
			declaration: "type CustomSecret struct { APIKey int }",
			method:      "Handle(ctxt.Context, string, CustomSecret) (ctxt.Context, error)",
			wantError:   "APIKey string",
		},
		{
			name:        "invalid roles field",
			declaration: "type CustomSecret struct { APIKey string; Roles string }",
			method:      "Handle(ctxt.Context, string, CustomSecret) (ctxt.Context, error)",
			wantError:   "Roles of type []string",
		},
		{
			name:        "unexpected API key result",
			declaration: "type CustomSecret struct { APIKey string }",
			method:      "Handle(ctxt.Context, string, CustomSecret) error",
			wantError:   "return (context.Context, error)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := "package api\nimport ctxt \"context\"\ntype SecurityHandler interface { " + tc.method + " }\n"
			typesSource := "package api\n" + tc.declaration + "\n"
			cfg := config{
				source: filepath.Join(dir, "security.go"), output: filepath.Join(dir, "out", "security.go"),
				apiImport: "example.test/api", packageName: "security", typeName: "Handler", constructor: "NewHandler",
			}
			writeTestFile(t, cfg.source, []byte(source))
			writeTestFile(t, filepath.Join(dir, "models.go"), []byte(typesSource))
			// Test files and inactive platform files must not affect detection.
			writeTestFile(t, filepath.Join(dir, "broken_test.go"), []byte("not Go code"))
			writeTestFile(t, filepath.Join(dir, "inactive.go"), []byte("//go:build ignore\n\nnot Go code"))
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
			assertImplementationCompiles(t, cfg, code, source, typesSource)
			if got := bytes.Contains(code, []byte("type APIKeyStore interface")); got != tc.wantAPIKey {
				t.Fatalf("APIKeyStore present = %v, want %v", got, tc.wantAPIKey)
			}
			if tc.wantAPIKey {
				if !bytes.Contains(code, []byte("func NewHandler(apiKeys APIKeyStore)")) {
					t.Fatal("constructor is missing the API key dependency")
				}
				if !bytes.Contains(code, []byte(`s.authorizeAPIKey(ctx, "CustomSecret", credentials.APIKey,`)) {
					t.Fatal("API key method does not delegate to the shared implementation")
				}
			} else if bytes.Contains(code, []byte("apiKeys APIKeyStore")) {
				t.Fatal("constructor without API keys must not require an API key dependency")
			}
			again, err := generate(cfg)
			if err != nil || !bytes.Equal(code, again) {
				t.Fatalf("generation is not deterministic: %v", err)
			}
		})
	}
}

func TestGeneratedAPIKeyHandlers(t *testing.T) {
	runGeneratedFixture(t, "apikey")
}

func runGeneratedFixture(t *testing.T, fixtureName string) {
	t.Helper()
	dir := t.TempDir()
	apiDir := filepath.Join(dir, "api")
	if err := os.Mkdir(apiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "go.mod"), []byte("module example.test/generated\n\ngo "+testModuleGoVersion+"\n"))
	for fixture, target := range map[string]string{
		"interface.go":    filepath.Join(apiDir, "oas_security_gen.go"),
		"models.go":       filepath.Join(apiDir, "oas_schemas_gen.go"),
		"runtime_test.go": filepath.Join(dir, "security_test.go"),
	} {
		data, err := os.ReadFile(filepath.Join("testdata", fixtureName, fixture))
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, target, data)
	}
	if err := Run([]string{
		"-source", filepath.Join(apiDir, "oas_security_gen.go"), "-output", filepath.Join(dir, "security.go"),
		"-api-import", "example.test/generated/api", "-type", "Handler", "-constructor", "NewHandler",
	}); err != nil {
		t.Fatal(err)
	}
	// Execute tests against freshly generated code, not a hand-maintained copy.
	cmd := exec.Command("go", "test", "-count=1", "-cover", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated handler tests failed: %v\n%s", err, output)
	}
	t.Logf("generated handler tests:\n%s", output)
}
